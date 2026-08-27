/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Web handlers for HTTP API endpoints

// authMiddleware validates API key for sensitive endpoints.
// The API key is read from the NL6_API_KEY environment variable.
// If the environment variable is not set, authentication is disabled
// (backward compatibility for local development).
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := os.Getenv("NL6_API_KEY")
		
		// If no API key is configured, allow the request (backward compatibility)
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}
		
		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendErrorResponse(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}
		
		// Support both "Bearer <token>" and plain token formats
		token := authHeader
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		
		if token != apiKey {
			sendErrorResponse(w, "Invalid API key", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// validateIPRange checks if the requested IP range is within allowed simulator ranges.
// This prevents attackers from configuring arbitrary network ranges that could
// affect host networking or reserved address spaces.
func validateIPRange(startIP string, netmask string) error {
	ip := net.ParseIP(startIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", startIP)
	}
	
	// Ensure it's IPv4
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 addresses are supported")
	}
	
	// Define allowed private ranges for simulator use
	// RFC 1918 private address spaces
	allowedRanges := []string{
		"10.0.0.0/8",      // Class A private
		"172.16.0.0/12",   // Class B private
		"192.168.0.0/16",  // Class C private
	}
	
	// Check if the IP falls within any allowed range
	inAllowedRange := false
	for _, cidr := range allowedRanges {
		_, allowedNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if allowedNet.Contains(ip4) {
			inAllowedRange = true
			break
		}
	}
	
	if !inAllowedRange {
		return fmt.Errorf("IP address %s is outside allowed simulator ranges (RFC 1918 private addresses: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)", startIP)
	}
	
	// Additional validation: reject reserved/special-use addresses within private ranges
	// Reject network addresses (x.x.x.0) and broadcast addresses (x.x.x.255)
	// for /24 networks to prevent common misconfigurations
	if netmask == "24" {
		lastOctet := ip4[3]
		if lastOctet == 0 {
			return fmt.Errorf("IP address %s appears to be a network address (ends in .0); use a host address instead", startIP)
		}
		if lastOctet == 255 {
			return fmt.Errorf("IP address %s appears to be a broadcast address (ends in .255); use a host address instead", startIP)
		}
	}
	
	// Reject localhost range (127.0.0.0/8)
	if ip4[0] == 127 {
		return fmt.Errorf("IP address %s is in the localhost range (127.0.0.0/8) and cannot be used for device simulation", startIP)
	}
	
	// Reject link-local range (169.254.0.0/16)
	if ip4[0] == 169 && ip4[1] == 254 {
		return fmt.Errorf("IP address %s is in the link-local range (169.254.0.0/16) and cannot be used for device simulation", startIP)
	}
	
	// Reject multicast range (224.0.0.0/4)
	if ip4[0] >= 224 && ip4[0] <= 239 {
		return fmt.Errorf("IP address %s is in the multicast range (224.0.0.0/4) and cannot be used for device simulation", startIP)
	}
	
	return nil
}

func createDevicesHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateDevicesRequest
	// 64 KiB cap is generous for the create-devices schema (most
	// requests are well under 1 KiB). DisallowUnknownFields surfaces
	// typo'd JSON keys (e.g. `if_flap_secnario`) as 400 rather than
	// silently dropping them — matches the trap/syslog/interface-state
	// POST conventions.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.DeviceCount <= 0 {
		sendErrorResponse(w, "Device count must be greater than 0", http.StatusBadRequest)
		return
	}
	// Upper bound: per-count allocations (device IP slices, worker pools)
	// scale with this request-controlled value, so cap it at the simulator's
	// design ceiling instead of letting a single request drive an OOM
	// (CodeQL go/uncontrolled-allocation-size). 100k comfortably covers the
	// 30k+ target fleet and a flat /16 management plane.
	if req.DeviceCount > 100000 {
		sendErrorResponse(w, "Device count must be at most 100000", http.StatusBadRequest)
		return
	}
	// MaxWorkers sizes worker-pool channels: 0 selects the adaptive default;
	// negative would panic make(chan, n) and huge values defeat the pool.
	if req.MaxWorkers < 0 || req.MaxWorkers > 1000 {
		sendErrorResponse(w, "max_workers must be between 0 (auto) and 1000", http.StatusBadRequest)
		return
	}

	// The fleet defaults to a flat /16 management plane: an omitted netmask
	// opts into it. Explicit "24" / "8" are still honored by the shared
	// allocation rule (see ipalloc.go nextHost / parsePrefix). Reject any other
	// value rather than silently coercing it — the netmask is passed verbatim to
	// `ip addr add` for the TUN, so an unsupported prefix would otherwise leave
	// the device's on-link mask disagreeing with the allocation/route prefix.
	if req.Netmask == "" {
		req.Netmask = "16"
	}
	switch req.Netmask {
	case "8", "16", "24":
	default:
		sendErrorResponse(w, "netmask must be 8, 16, or 24", http.StatusBadRequest)
		return
	}

	// Validate that the requested IP range is within allowed simulator ranges.
	// This prevents unauthorized control of host networking via arbitrary address
	// ranges that could affect routing tables or reserved address spaces.
	if err := validateIPRange(req.StartIP, req.Netmask); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	snmpPort := req.SNMPPort
	if snmpPort == 0 {
		snmpPort = DEFAULT_SNMP_PORT
	}
	if snmpPort < 1 || snmpPort > 65535 {
		sendErrorResponse(w, "snmp_port must be between 1 and 65535", http.StatusBadRequest)
		return
	}

	// Parse and validate per-device export blocks. Each block is
	// optional; missing or nil → export disabled for batch. Validation
	// failures return 400 with the underlying error so the operator
	// can see what went wrong. After phases 4 and 5 each block now
	// drives a real per-device exporter via the always-on subsystem.
	// Validate optional if_error_scenario before constructing the seed
	// so we reject unknown values atomically and don't partially mutate
	// manager state.
	ifErrScenario, err := ParseIfErrorScenario(req.IfErrorScenario)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	ifFlapScenario, err := ParseIfFlapScenario(req.IfFlapScenario)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	opticalScenario, err := ParseOpticalScenario(req.OpticalScenario)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// A non-clean optical band on a request whose every device type carries
	// no OCH inventory is the same stated contradiction as an explicit flow
	// block on a layer-1 platform, so it gets the same 400 rather than a 201
	// that echoes a band back for a device where it does nothing.
	if rf, ok := opticalIncapableRequest(req, opticalScenario); ok {
		sendErrorResponse(w, fmt.Sprintf(
			"device type %q has no optical channels: optical_scenario applies only to coherent optical transport types; remove the \"optical_scenario\" field",
			rf), http.StatusBadRequest)
		return
	}

	seed := &ExportSeed{
		Flow:            req.Flow,
		Traps:           req.Traps,
		Syslog:          req.Syslog,
		GnmiDialout:     req.GnmiDialout,
		IfErrorScenario: ifErrScenario,
		IfFlapScenario:  ifFlapScenario,
		OpticalScenario: opticalScenario,
	}
	// Record whether each interval was EXPLICITLY supplied, from the RAW
	// request — ApplyDefaults below stamps the package default over an omitted
	// zero and destroys the distinction permanently. Every downstream surface
	// (the attach logs, the read-back, a re-POST of an exported inventory)
	// depends on this marker to tell "the operator asked for 10s" from "the
	// operator asked for nothing".
	seed.Syslog.markIntervalProvenance()
	seed.Traps.markIntervalProvenance()
	seed.Flow.markIntervalProvenance()

	// Disclose interval settings the engine will not honor, to the caller who
	// set them. The detection already existed in all three managers but was
	// routed to a log, warn-once-per-subsystem-lifecycle, which never reaches
	// an operator driving the simulator over HTTP.
	//
	// The `warnings` channel is retained deliberately even though nothing
	// populates it today: it is the general "your request was accepted, but
	// here is something you should know" surface, and re-adding it later is
	// more churn than leaving it. The interval disclosures that used to fill it
	// became a 400 in nl6#445 — a field the engine cannot honour is refused at
	// the door rather than stored, echoed and ignored.
	//
	// The nil check on `manager` exists for handler-level tests, which
	// deliberately construct none (see web_create_devices_scenario_test.go).
	var exportWarnings []exportWarning
	_ = manager

	// rejectWith fails the request while still handing back any disclosures.
	rejectWith := func(msg string, code int) {
		if len(exportWarnings) == 0 {
			sendErrorResponse(w, msg, code)
			return
		}
		sendErrorResponseWithData(w, msg, code, RejectedRequestData{Warnings: exportWarnings})
	}

	if seed.Flow != nil {
		seed.Flow.ApplyDefaults()
		if err := seed.Flow.Validate(); err != nil {
			rejectWith(err.Error(), http.StatusBadRequest)
			return
		}
		// An explicit flow block on a request whose every device is a type
		// that natively exports no flow records is a contradiction the
		// caller stated on purpose, so reject it rather than silently
		// dropping the config.
		//
		// This has to consider the resolved type set, not just
		// req.ResourceFile: a category-filtered round-robin batch
		// (`{"round_robin":true,"category":"Optical Transport"}`) names no
		// resource file yet resolves to flow-incapable types only, and
		// would otherwise return 201 while every device silently lost its
		// flow config.
		//
		// A *mixed* round-robin batch is deliberately still accepted — the
		// flow-capable devices export and the incapable ones are skipped
		// with a log line, because failing the batch would make a
		// batch-wide flow seed unusable with -round-robin.
		if rf, ok := flowIncapableRequest(req); ok {
			rejectWith(fmt.Sprintf(
				"device type %q does not support flow export: it is a layer-1 transport platform and performs no layer-3/4 inspection; remove the \"flow\" block",
				rf), http.StatusBadRequest)
			return
		}
	}
	if seed.Traps != nil {
		seed.Traps.ApplyDefaults()
		if err := seed.Traps.Validate(); err != nil {
			rejectWith(err.Error(), http.StatusBadRequest)
			return
		}
		// INFORM mode requires per-device UDP source binding so the
		// exporter can demux acks without a global request-id table.
		// Reject the whole batch with 400 here rather than letting
		// each device fail the attach individually (phase 4.6) — atomic
		// batch failure matches the contract for every other validation
		// rule on this endpoint.
		if strings.EqualFold(seed.Traps.Mode, "inform") && !manager.TrapSourcePerDevice() {
			rejectWith("traps: mode=inform requires the simulator-wide -trap-source-per-device flag (default true) to be enabled", http.StatusBadRequest)
			return
		}
	}
	if seed.Syslog != nil {
		seed.Syslog.ApplyDefaults()
		if err := seed.Syslog.Validate(); err != nil {
			rejectWith(err.Error(), http.StatusBadRequest)
			return
		}
	}
	if seed.GnmiDialout != nil {
		seed.GnmiDialout.ApplyDefaults()
		if err := seed.GnmiDialout.Validate(); err != nil {
			rejectWith(err.Error(), http.StatusBadRequest)
			return
		}
	}
	// Collapse the seed to nil when no block was supplied so CreateDevices
	// receives the exact "no export" signal rather than an empty shell.
	// Scenario fields set to anything other than their clean defaults are
	// also signals to keep the seed — they need to reach applyExportSeed
	// for the per-device cycler and flap scheduler to pick them up.
	if seed.Flow == nil && seed.Traps == nil && seed.Syslog == nil && seed.GnmiDialout == nil &&
		seed.IfErrorScenario == IfErrorClean && seed.IfFlapScenario == IfFlapClean &&
		seed.OpticalScenario == OpticalClean {
		seed = nil
	}

	// Always route through CreateDevicesWithOptions with pre-allocation on:
	// the former CreateDevices fallback was exactly CreateDevicesWithOptions
	// with preAllocate=true, maxWorkers=0, so this preserves behaviour while
	// giving us the actual created count (req.MaxWorkers is 0 when unset).
	created, err := manager.CreateDevicesWithOptions(req.StartIP, req.DeviceCount, req.Netmask, req.ResourceFile, req.SNMPv3, true, req.MaxWorkers, req.RoundRobin, req.Category, snmpPort, seed)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Report the ACTUAL created count, not the requested count — some devices
	// can fail to start under resource pressure at scale, and silently echoing
	// the request made partial failures invisible (a Clos fabric would then
	// reference never-created devices as "unresolved" topology links).
	failed := req.DeviceCount - created
	msg := fmt.Sprintf("Created %d devices starting from %s", created, req.StartIP)
	if failed > 0 {
		msg = fmt.Sprintf("Created %d of %d devices (%d failed to start) starting from %s", created, req.DeviceCount, failed, req.StartIP)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: msg,
		Data:    CreateDevicesResult{Created: created, Requested: req.DeviceCount, Failed: failed, Warnings: exportWarnings},
	})
}

func listDevicesHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()
	sendDataResponse(w, devices)
}

func listResourcesHandler(w http.ResponseWriter, r *http.Request) {
	resources := manager.ListAvailableResources()
	sendDataResponse(w, resources)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	status := manager.GetStatus()
	sendDataResponse(w, status)
}

func systemStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := GetSystemStats()
	sendDataResponse(w, stats)
}

// versionHandler implements GET /api/v1/version. The version is immutable
// per process, so the response is marked cacheable (private, max-age=3600)
// to cut chatter on page reloads. `private` keeps shared proxies from
// caching one simulator's version across other operators or across a
// binary swap-and-restart inside the TTL. Shape:
//
//	{"version": "v0.5.0"}
func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	_ = json.NewEncoder(w).Encode(map[string]string{"version": Version})
}

func flowStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := manager.GetFlowStatus()
	sendDataResponse(w, status)
}

// trapStatusHandler implements GET /api/v1/traps/status. Returns a
// TrapStatus JSON body (shape documented in trap_manager.go).
func trapStatusHandler(w http.ResponseWriter, r *http.Request) {
	manager.WriteTrapStatusJSON(w)
}

// syslogStatusHandler implements GET /api/v1/syslog/status. Returns a
// SyslogStatus JSON body (shape documented in syslog_manager.go).
func syslogStatusHandler(w http.ResponseWriter, r *http.Request) {
	manager.WriteSyslogStatusJSON(w)
}

// fireSyslogHandler implements POST /api/v1/devices/{ip}/syslog. Body:
//
//	{ "name": "interface-down", "templateOverrides": {"IfIndex": "3"} }
//
// Returns 202 Accepted with {} on success. Bypasses the global rate
// limiter (pre-flight 1.4): on-demand fires are for test-harness use and
// should not compete with scheduled traffic for tokens.
// Status code mapping:
//   - 503 when syslog export is not enabled
//   - 404 when the device IP is unknown
//   - 400 when the catalog entry name is unknown or JSON is malformed
func fireSyslogHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]

	var req struct {
		Name              string            `json:"name"`
		TemplateOverrides map[string]string `json:"templateOverrides"`
	}
	// Bound the request body so a malicious or misconfigured client can't
	// force an unbounded allocation on the admin-plane HTTP surface.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	// Reject unknown field names so typo'd override keys (e.g.
	// `tempalteOverrides`) surface as a 400 instead of being silently
	// dropped and producing confusing "overrides didn't apply" debugging.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		sendErrorResponse(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := manager.FireSyslogOnDevice(ip, req.Name, req.TemplateOverrides); err != nil {
		var entryErr *SyslogEntryNotFoundError
		switch {
		case errors.Is(err, ErrSyslogExportDisabled):
			sendErrorResponse(w, err.Error(), http.StatusServiceUnavailable)
		case errors.Is(err, ErrSyslogCatalogUnavailable):
			// Pathological manager state — see trap handler for rationale.
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		case errors.Is(err, ErrSyslogDeviceNotFound):
			sendErrorResponse(w, err.Error(), http.StatusNotFound)
		case errors.As(err, &entryErr):
			// Enriched 400: the device's resolved catalog and its
			// entries list so operators can self-service.
			// FireSyslogOnDevice always wraps unknown-entry failures
			// in *SyslogEntryNotFoundError, so this arm handles every
			// ErrSyslogEntryNotFound case.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":            entryErr.Error(),
				"catalog":          entryErr.Catalog,
				"availableEntries": entryErr.Entries,
			})
		default:
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("{}"))
}

// fireTrapHandler implements POST /api/v1/devices/{ip}/trap. Body:
//
//	{ "name": "linkDown", "varbindOverrides": {"IfIndex": "3"} }
//
// Returns 202 Accepted with {"requestId": N} on success.
// Status code mapping:
//   - 503 when trap export is not enabled
//   - 404 when the device IP is unknown
//   - 400 when the catalog entry name is unknown
func fireTrapHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]

	var req struct {
		Name             string            `json:"name"`
		VarbindOverrides map[string]string `json:"varbindOverrides"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		sendErrorResponse(w, "name is required", http.StatusBadRequest)
		return
	}

	reqID, err := manager.FireTrapOnDevice(ip, req.Name, req.VarbindOverrides)
	if err != nil {
		var entryErr *TrapEntryNotFoundError
		switch {
		case errors.Is(err, ErrTrapExportDisabled):
			sendErrorResponse(w, err.Error(), http.StatusServiceUnavailable)
		case errors.Is(err, ErrTrapCatalogUnavailable):
			// Pathological manager state — client retrying later
			// won't help. Map to 500 rather than 503.
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		case errors.Is(err, ErrTrapDeviceNotFound):
			sendErrorResponse(w, err.Error(), http.StatusNotFound)
		case errors.As(err, &entryErr):
			// 400 with available entries so operators can self-service
			// when they target the wrong catalog (e.g., Cisco entry
			// name on a Juniper device). FireTrapOnDevice always wraps
			// ErrTrapEntryNotFound in *TrapEntryNotFoundError, so this
			// arm handles every unknown-entry case.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":            entryErr.Error(),
				"catalog":          entryErr.Catalog,
				"availableEntries": entryErr.Entries,
			})
		default:
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]uint32{"requestId": reqID})
}

func deleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["id"]

	err := manager.DeleteDevice(deviceID)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	sendSuccessResponse(w, fmt.Sprintf("Device %s deleted", deviceID))
}

func deleteAllDevicesHandler(w http.ResponseWriter, r *http.Request) {
	err := manager.DeleteAllDevices()
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendSuccessResponse(w, "All devices deleted")
}

func exportDevicesCSVHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()

	// Set headers for CSV download
	filename := fmt.Sprintf("devices_%s.csv", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	// Create CSV writer
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write CSV headers. "Resource File" is appended at the end so any
	// downstream consumer that indexes columns positionally
	// (`awk -F,`, spreadsheet macros) keeps working — inserting mid-row
	// would silently shift every column to its right.
	headers := []string{"Device ID", "IP Address", "Interface", "SNMP Port", "SSH Port", "Status", "Resource File"}
	if err := writer.Write(headers); err != nil {
		http.Error(w, "Failed to write CSV headers", http.StatusInternalServerError)
		return
	}

	// Write device data
	for _, device := range devices {
		status := "Stopped"
		if device.Running {
			status = "Running"
		}

		interfaceName := device.Interface
		if interfaceName == "" {
			interfaceName = "N/A"
		}

		// Auto-start devices (CLI -auto-start-ip path) carry an empty
		// resource_file — substitute N/A to match the Interface
		// column's convention and avoid an indistinguishable-from-error
		// empty cell mid-row.
		resourceFile := device.ResourceFile
		if resourceFile == "" {
			resourceFile = "N/A"
		}

		record := []string{
			device.ID,
			device.IP,
			interfaceName,
			fmt.Sprintf("%d", device.SNMPPort),
			fmt.Sprintf("%d", device.SSHPort),
			status,
			resourceFile,
		}

		if err := writer.Write(record); err != nil {
			http.Error(w, "Failed to write CSV record", http.StatusInternalServerError)
			return
		}
	}
}

func generateRouteScriptHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()

	// Set headers for script download
	filename := fmt.Sprintf("add_simulator_routes_%s.sh", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	// Generate bash script content
	script := generateRouteScript(devices)
	w.Write([]byte(script))
}

func pprofMemoryHandler(w http.ResponseWriter, r *http.Request) {
	filename := fmt.Sprintf("nl6_heap_%s.pprof", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	if err := pprof.WriteHeapProfile(w); err != nil {
		http.Error(w, "Failed to write heap profile", http.StatusInternalServerError)
	}
}

func cpuProfileHandler(w http.ResponseWriter, r *http.Request) {
	filename := fmt.Sprintf("nl6_cpu_%s.pprof", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	if err := pprof.StartCPUProfile(w); err != nil {
		http.Error(w, "Failed to start CPU profile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	time.Sleep(5 * time.Second)
	pprof.StopCPUProfile()
}

// Helper functions for API responses
func sendSuccessResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: message,
	})
}

func sendDataResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "Success",
		Data:    data,
	})
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	sendErrorResponseWithData(w, message, statusCode, nil)
}

// sendErrorResponseWithData is sendErrorResponse plus a payload, for the case
// where a rejected request still carries information the caller needs.
//
// APIResponse already had a Data field; error responses simply never set it, so
// this changes no envelope shape and existing error bodies stay byte-identical
// (a nil Data is dropped by omitempty). Its one use today is attaching interval
// disclosures to a 400, so a caller learns in ONE round trip both that their
// request was invalid and that one of their fields would have been inert
// anyway.
func sendErrorResponseWithData(w http.ResponseWriter, message string, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Message: message,
		Data:    data,
	})
}

// Web UI handler - serves the index.html from web directory
func webUIHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/index.html")
}

// Setup REST API routes
func setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Web UI
	router.HandleFunc("/", webUIHandler).Methods("GET")
	router.HandleFunc("/ui", webUIHandler).Methods("GET")

	// Static web assets (CSS, JS)
	router.PathPrefix("/web/").Handler(http.StripPrefix("/web/", http.FileServer(http.Dir("web"))))

	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	
	// Read-only endpoints (no authentication required for backward compatibility)
	api.HandleFunc("/status", statusHandler).Methods("GET")
	api.HandleFunc("/version", versionHandler).Methods("GET")
	api.HandleFunc("/devices", listDevicesHandler).Methods("GET")
	api.HandleFunc("/devices/export", exportDevicesCSVHandler).Methods("GET")
	api.HandleFunc("/devices/routes", generateRouteScriptHandler).Methods("GET")
	api.HandleFunc("/resources", listResourcesHandler).Methods("GET")
	api.HandleFunc("/system-stats", systemStatsHandler).Methods("GET")
	api.HandleFunc("/flows/status", flowStatusHandler).Methods("GET")
	api.HandleFunc("/traps/status", trapStatusHandler).Methods("GET")
	api.HandleFunc("/syslog/status", syslogStatusHandler).Methods("GET")
	api.HandleFunc("/gnmi/status", gnmiStatusHandler).Methods("GET")
	api.HandleFunc("/gnmi/dialout/status", gnmiDialoutStatusHandler).Methods("GET")
	api.HandleFunc("/dns/status", dnsStatusHandler).Methods("GET")
	api.HandleFunc("/fidelity", fidelityStatusHandler).Methods("GET")
	api.HandleFunc("/topology", listTopologyHandler).Methods("GET")
	api.HandleFunc("/topology/status", topologyStatusHandler).Methods("GET")
	api.HandleFunc("/topology/graph", topologyGraphHandler).Methods("GET")
	api.HandleFunc("/scenarios", listScenariosHandler).Methods("GET")
	api.HandleFunc("/scenarios/{id}/report", scenarioReportHandler).Methods("GET")
	api.HandleFunc("/scenarios/{id}/metrics", scenarioMetricsHandler).Methods("GET")
	api.HandleFunc("/scenarios/{id}", scenarioStatusHandler).Methods("GET")
	api.HandleFunc("/devices/{ip}/optical", opticalStatusHandler).Methods("GET")
	
	// Mutating endpoints (require authentication when NL6_API_KEY is set)
	// These endpoints can modify simulator state, create/delete devices,
	// or trigger privileged network operations
	authenticated := api.PathPrefix("").Subrouter()
	authenticated.Use(authMiddleware)
	
	authenticated.HandleFunc("/fidelity", fidelityToggleHandler).Methods("POST")
	authenticated.HandleFunc("/devices", createDevicesHandler).Methods("POST")
	authenticated.HandleFunc("/devices/{id}", deleteDeviceHandler).Methods("DELETE")
	authenticated.HandleFunc("/devices", deleteAllDevicesHandler).Methods("DELETE")
	authenticated.HandleFunc("/devices/{ip}/trap", fireTrapHandler).Methods("POST")
	authenticated.HandleFunc("/devices/{ip}/syslog", fireSyslogHandler).Methods("POST")
	authenticated.HandleFunc("/devices/{ip}/interfaces/{ifIndex}/oper-status", setOperStatusHandler).Methods("POST")
	authenticated.HandleFunc("/devices/{ip}/optical/{component}/degrade", degradeOpticalHandler).Methods("POST")
	authenticated.HandleFunc("/devices/{ip}/interfaces/{ifIndex}/admin-status", setAdminStatusHandler).Methods("POST")
	authenticated.HandleFunc("/topology", createTopologyHandler).Methods("POST")
	authenticated.HandleFunc("/topology", deleteTopologyHandler).Methods("DELETE")
	authenticated.HandleFunc("/scenarios", createScenarioHandler).Methods("POST")
	authenticated.HandleFunc("/scenarios/{id}/arm", armScenarioHandler).Methods("POST")
	authenticated.HandleFunc("/scenarios/{id}/start", startScenarioHandler).Methods("POST")
	authenticated.HandleFunc("/scenarios/{id}/stop", stopScenarioHandler).Methods("POST")
	authenticated.HandleFunc("/scenarios/{id}", deleteScenarioHandler).Methods("DELETE")
	authenticated.HandleFunc("/debug/pprof-memory", pprofMemoryHandler).Methods("GET")
	authenticated.HandleFunc("/debug/cpu-profile", cpuProfileHandler).Methods("GET")

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	return router
}
