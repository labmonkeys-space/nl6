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
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// parseAuthProtocol converts string to authentication protocol constant
func parseAuthProtocol(proto string) int {
	switch strings.ToLower(proto) {
	case "md5":
		return SNMPV3_AUTH_MD5
	case "sha1", "sha":
		return SNMPV3_AUTH_SHA1
	case "none", "":
		return SNMPV3_AUTH_NONE
	default:
		log.Printf("Unknown auth protocol '%s', using MD5", proto)
		return SNMPV3_AUTH_MD5
	}
}

// parsePrivProtocol converts string to privacy protocol constant
func parsePrivProtocol(proto string) int {
	switch strings.ToLower(proto) {
	case "des":
		return SNMPV3_PRIV_DES
	case "aes128", "aes":
		return SNMPV3_PRIV_AES128
	case "none", "":
		return SNMPV3_PRIV_NONE
	default:
		log.Printf("Unknown privacy protocol '%s', using none", proto)
		return SNMPV3_PRIV_NONE
	}
}

// setupSignalHandler sets up graceful shutdown on SIGINT/SIGTERM
func setupSignalHandler() {
	// Survive a dropped controlling terminal. A long device-creation run
	// (e.g. a k=32 Clos build) saturates the host enough that an interactive
	// SSH session can drop; the resulting SIGHUP would otherwise terminate a
	// foreground `make run`, killing the simulator mid-build and freezing the
	// wizard. Ignoring SIGHUP keeps it running (reparented to init) so creation
	// completes and the fleet is intact on reconnect. SIGPIPE is ignored too so
	// log writes to the now-closed terminal's stdout/stderr (fd 1/2) don't kill
	// it either — Go already ignores SIGPIPE for network fds, this extends that
	// to the terminal. Ctrl-C (SIGINT) and SIGTERM still shut down gracefully.
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("\nReceived signal %v, shutting down gracefully...", sig)

		// Cleanup manager (deletes devices, cleans up namespace)
		if manager != nil {
			if err := manager.Shutdown(); err != nil {
				log.Printf("Error during shutdown: %v", err)
			}
		}

		log.Println("Shutdown complete")
		os.Exit(0)
	}()
}

func main() {
	// Define command-line flags
	var (
		autoStartIP     = flag.String("auto-start-ip", "", "Auto-create devices starting from this IP address (e.g., 192.168.100.1)")
		autoCount       = flag.Int("auto-count", 0, "Number of devices to auto-create (requires -auto-start-ip)")
		autoNetmask     = flag.String("auto-netmask", "16", "Netmask for auto-created devices: the fleet is a flat /16 management plane (default: 16)")
		snmpv3EngineID  = flag.String("snmpv3-engine-id", "", "Enable SNMPv3 with specified engine ID (e.g., 800000090300AABBCCDD)")
		snmpv3AuthProto = flag.String("snmpv3-auth", "md5", "SNMPv3 authentication protocol: none, md5, sha1 (default: md5)")
		snmpv3PrivProto = flag.String("snmpv3-priv", "none", "SNMPv3 privacy protocol: none, des, aes128 (default: none)")
		port            = flag.String("port", "8080", "Server port (default: 8080)")
		snmpPort        = flag.Int("snmp-port", DEFAULT_SNMP_PORT, "UDP port for SNMP listener on each device (default: 161)")
		noNamespace     = flag.Bool("no-namespace", false, "Disable network namespace isolation (use root namespace)")
		showHelp        = flag.Bool("help", false, "Show this help message")
		showVersion     = flag.Bool("version", false, "Print the simulator version string and exit")
		ifScenario      = flag.Int("if-scenario", 2, "Interface state scenario: 1=all-shutdown, 2=all-normal (default), 3=all-failure, 4=pct-failure")
		ifFailurePct    = flag.Int("if-failure-pct", 10, "Percentage of interfaces with oper-down (used with -if-scenario 4, 0–100)")
		ifErrorScenario = flag.String("if-error-scenario", "clean", "Per-device IF-MIB error/discard counter scenario for the auto-start batch: clean | typical | degraded | failing. REST-created devices default to clean regardless; they opt in via if_error_scenario in the POST body.")
		ifFlapScenario  = flag.String("if-flap-scenario", "clean", "Per-device link-flap scenario for the auto-start batch: clean (default, no flaps) | rare (~6h mean) | typical (~15min) | aggressive (~1min). REST-created devices default to clean; opt in via if_flap_scenario in the POST body.")
		ifFlapGlobalCap = flag.Int("if-flap-global-cap", 0, "Simulator-wide tps ceiling for flap events (0 = unlimited)")

		// Flow export flags
		flowCollector            = flag.String("flow-collector", "", "NetFlow/IPFIX collector address (host:port, e.g. 192.168.1.100:2055); disables flow export when empty")
		flowProtocol             = flag.String("flow-protocol", "netflow9", "Flow export protocol: netflow9 (default), ipfix, netflow5, sflow (alias sflow5). Under netflow5, -flow-template-interval is accepted but has no effect (v5 has no template mechanism). Under sflow, -flow-template-interval is accepted but has no effect (sFlow records are self-describing); flow-samples carry a synthetic sampling_rate of 10 × FlowProfile.ConcurrentFlows — see CLAUDE.md and README.md for caveats")
		flowActiveSecs           = flag.Int("flow-active-timeout", 30, "Active flow timeout in seconds (default: 30)")
		flowInactiveSecs         = flag.Int("flow-inactive-timeout", 15, "Inactive flow timeout in seconds (default: 15)")
		flowTemplateIntervalSecs = flag.Int("flow-template-interval", 60, "Template retransmission interval in seconds (default: 60)")
		flowTickSecs             = flag.Int("flow-tick-interval", 5, "Flow ticker interval in seconds (default: 5)")
		flowSourcePerDevice      = flag.Bool("flow-source-per-device", true, "Bind a per-device UDP socket inside the opensim namespace so flow packets use the device's IP as the source address (default: true). Requires the opensim ns to have a route to the collector; set to false to use a single shared socket from the host namespace")

		// SNMP trap / INFORM export flags. See CLAUDE.md "SNMP Trap export" for detail.
		trapCollector       = flag.String("trap-collector", "", "SNMP trap collector address (host:port, e.g. 10.0.0.50:162); enables trap export when non-empty")
		trapMode            = flag.String("trap-mode", "trap", "SNMP notification mode: trap (default, fire-and-forget) or inform (acknowledged)")
		trapInterval        = flag.Duration("trap-interval", 30*time.Second, "Per-device mean firing interval (Poisson-distributed); default 30s")
		trapGlobalCap       = flag.Int("trap-global-cap", 0, "Simulator-wide tps ceiling for trap fires + retries (0 = unlimited)")
		trapCatalog         = flag.String("trap-catalog", "", "Path to a JSON trap catalog; overrides the embedded universal 5-trap catalog when set")
		trapCommunity       = flag.String("trap-community", "public", "SNMPv2c community string for trap/INFORM PDUs")
		trapSourcePerDevice = flag.Bool("trap-source-per-device", true, "Bind a per-device UDP socket in the opensim ns so trap packets use the device IP as source (required in -trap-mode inform)")
		trapInformTimeout   = flag.Duration("trap-inform-timeout", 5*time.Second, "Per-retry timeout in INFORM mode (default 5s)")
		trapInformRetries   = flag.Int("trap-inform-retries", 2, "Maximum retransmissions per INFORM before declaring it failed (default 2)")

		// UDP syslog export flags. See CLAUDE.md "Syslog export" for detail.
		syslogCollector       = flag.String("syslog-collector", "", "UDP syslog collector address (host:port, e.g. 10.0.0.50:514); enables syslog export when non-empty")
		syslogFormat          = flag.String("syslog-format", "5424", "Syslog wire format: 5424 (default, structured RFC 5424) or 3164 (BSD RFC 3164)")
		syslogInterval        = flag.Duration("syslog-interval", 10*time.Second, "Per-device mean firing interval (Poisson-distributed); default 10s")
		syslogGlobalCap       = flag.Int("syslog-global-cap", 0, "Simulator-wide rate ceiling for syslog fires (0 = unlimited)")
		syslogCatalog         = flag.String("syslog-catalog", "", "Path to a JSON syslog catalog; overrides the embedded universal 6-entry catalog when set")
		syslogSourcePerDevice = flag.Bool("syslog-source-per-device", true, "Bind a per-device UDP socket in the opensim ns so syslog packets use the device IP as source (default true). Bind failures fall back to shared socket with a warning (never fatal for syslog)")

		// gNMI flags. See CLAUDE.md "gNMI target" for detail.
		gnmiPort    = flag.Int("gnmi-port", gnmiDefaultPort, "TCP port for gNMI listener on each device (default: 9339)")
		gnmiDisable = flag.Bool("gnmi-disable", false, "Disable the gNMI subsystem; no device listens on the gNMI port. Default: false (subsystem on)")

		// Topology flag. Loads an inter-device LLDP link graph at startup.
		// Validation is syntactic only; device existence / ifIndex
		// ownership resolve lazily at SNMP-serve time, so the file may
		// reference auto-start devices not yet created. See CLAUDE.md
		// "LLDP topology".
		topologyConfig = flag.String("topology-config", "", "Path to a JSON inter-device link graph ({\"links\":[{\"a\":{\"ip\",\"ifindex\"},\"b\":{\"ip\",\"ifindex\"}}]}); enables LLDP topology when set")
	)

	flag.Parse()

	// `-version` prints the baked-in Version and exits before any
	// simulator setup runs (no flag dependencies, no TUN, no netns, no
	// port binds). Lets `./nl6 -version` work without root and
	// without touching system state.
	if *showVersion {
		fmt.Println(Version)
		return
	}

	// Apply interface state scenario
	ifStateConfig = &IfStateConfig{
		Scenario:   *ifScenario,
		FailurePct: *ifFailurePct,
	}

	// Show help if requested
	if *showHelp {
		fmt.Println("nl6 — network device simulator with TUN/TAP support")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Printf("  %s [options]\n", os.Args[0])
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Network Namespace Isolation:")
		fmt.Println("  By default, devices are created in a dedicated network namespace ('opensim')")
		fmt.Println("  to prevent systemd-networkd from consuming excessive CPU/memory with many devices.")
		fmt.Println("  External machines can still access devices via static routes to this host.")
		fmt.Println("  Use -no-namespace to disable this (not recommended for 1000+ devices).")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Printf("  %s                                                    # Start server only\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 5       # Auto-create 5 devices\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 10.10.10.1 -auto-count 3 -port 9090  # Custom API port\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 10.10.10.1 -auto-count 3 -snmp-port 1161  # Non-privileged SNMP port\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 30000      # 30K devices (uses namespace)\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 100 -no-namespace  # Disable namespace\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 2 \\      # SNMPv3 with MD5 auth\n", os.Args[0])
		fmt.Printf("    -snmpv3-engine-id 800000090300AABBCCDD -snmpv3-auth md5\n")
		fmt.Println()
		return
	}

	log.Printf("simulator %s starting (pid=%d)", Version, os.Getpid())

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Println("WARNING: Not running as root. TUN/TAP interface creation will fail.")
		log.Println("Please run with: sudo ./nl6")
	}

	// Initialize manager with namespace support (unless disabled)
	useNamespace := !*noNamespace
	manager = NewSimulatorManagerWithOptions(useNamespace)

	// Load the inter-device LLDP topology graph if configured. Syntactic
	// validation failures are fatal; missing devices are NOT (lazy
	// resolution at serve time covers the auto-start goroutine race).
	if *topologyConfig != "" {
		if err := manager.topology.LoadFromFile(*topologyConfig); err != nil {
			log.Fatalf("topology: %v", err)
		}
		log.Printf("topology: loaded %d link(s) from %s", manager.topology.Count(), *topologyConfig)
	}

	// Setup signal handler for graceful shutdown
	setupSignalHandler()

	// Load world cities from CSV file
	if err := loadWorldCities(); err != nil {
		log.Printf("Warning: failed to load world cities: %v", err)
	}

	// Load default resources - look for asr9k first, then fallback to cisco_ios
	err := manager.LoadResources("resources/asr9k.json")
	if err != nil {
		log.Printf("Failed to load ASR9K resources: %v", err)
		log.Println("Trying to load default Cisco IOS resources...")
		err = manager.LoadResources("resources/cisco_ios.json")
		if err != nil {
			log.Fatalf("Failed to load any resources: %v", err)
		}
	}

	// Configure simulator-wide flow parameters. Per-device fields (collector,
	// protocol, timeouts) live on DeviceFlowConfig; `tick_interval`,
	// `template_interval`, and `source_per_device` remain global per
	// design §D5. Always applied so operators can tune the ticker cadence
	// even when no CLI-seed flow export is configured.
	manager.SetFlowSourcePerDevice(*flowSourcePerDevice)
	manager.SetFlowTickInterval(time.Duration(*flowTickSecs) * time.Second)
	manager.SetFlowTemplateInterval(time.Duration(*flowTemplateIntervalSecs) * time.Second)

	// Build the CLI-seed flow config for the auto-start batch. Phase 3 of
	// per-device-export-config: flags seed auto-start devices only;
	// REST-created devices must opt in via POST /api/v1/devices.
	var flowSeed *DeviceFlowConfig
	if *flowCollector != "" {
		flowSeed = &DeviceFlowConfig{
			Collector:       *flowCollector,
			Protocol:        *flowProtocol,
			TickInterval:    jsonDuration(time.Duration(*flowTickSecs) * time.Second),
			ActiveTimeout:   jsonDuration(time.Duration(*flowActiveSecs) * time.Second),
			InactiveTimeout: jsonDuration(time.Duration(*flowInactiveSecs) * time.Second),
		}
		flowSeed.ApplyDefaults()
		if err := flowSeed.Validate(); err != nil {
			log.Fatalf("flow export: invalid -flow-* CLI seed: %v", err)
		}
	}

	// Start the SNMP trap subsystem unconditionally so REST-created
	// devices can opt in to traps even when no CLI seed is provided.
	// Phase 4 of per-device-export-config: simulator-wide knobs
	// (catalog, global cap, per-device-source, scheduler mean interval)
	// live on the manager; per-device knobs (collector, mode, community,
	// interval, inform-*) live on each DeviceTrapConfig.
	if err := manager.StartTrapSubsystem(TrapSubsystemConfig{
		CatalogPath:           *trapCatalog,
		GlobalCap:             *trapGlobalCap,
		SourcePerDevice:       *trapSourcePerDevice,
		MeanSchedulerInterval: *trapInterval,
	}); err != nil {
		log.Fatalf("Failed to initialize trap subsystem: %v", err)
	}

	// Start the flap subsystem unconditionally so REST-created devices
	// can opt in to flap scenarios even when no CLI seed is provided.
	// The CLI flag -if-flap-scenario seeds only the auto-start batch;
	// REST devices default to clean and must opt in via if_flap_scenario.
	// Use ParseIfFlapScenario (case-insensitive + trim) so operators can
	// pass e.g. "Aggressive" without a fatal exit; canonicalises to
	// lowercase before reaching StartFlapSubsystem.
	flapScenarioCanon, err := ParseIfFlapScenario(*ifFlapScenario)
	if err != nil {
		log.Fatalf("flap subsystem: %v", err)
	}
	if *ifFlapGlobalCap < 0 {
		log.Fatalf("flap subsystem: -if-flap-global-cap must be non-negative, got %d", *ifFlapGlobalCap)
	}
	if err := manager.StartFlapSubsystem(FlapSubsystemConfig{
		GlobalCap:       *ifFlapGlobalCap,
		DefaultScenario: flapScenarioCanon,
	}); err != nil {
		log.Fatalf("Failed to initialize flap subsystem: %v", err)
	}

	// Build the CLI-seed trap config for the auto-start batch. Mirrors
	// the flow-seed pattern: flags seed auto-start devices only;
	// REST-created devices must opt in via POST /api/v1/devices.
	var trapSeed *DeviceTrapConfig
	if *trapCollector != "" {
		// Validate trap mode up front so a bad -trap-mode fails startup.
		if _, err := ParseTrapMode(*trapMode); err != nil {
			log.Fatalf("trap export: invalid -trap-mode: %v", err)
		}
		trapSeed = &DeviceTrapConfig{
			Collector:     *trapCollector,
			Mode:          *trapMode,
			Community:     *trapCommunity,
			Interval:      jsonDuration(*trapInterval),
			InformTimeout: jsonDuration(*trapInformTimeout),
			InformRetries: *trapInformRetries,
		}
		trapSeed.ApplyDefaults()
		if err := trapSeed.Validate(); err != nil {
			log.Fatalf("trap export: invalid -trap-* CLI seed: %v", err)
		}
	}

	// Start the UDP syslog subsystem unconditionally so REST-created
	// devices can opt in to syslog even when no CLI seed is provided.
	// Phase 5 of per-device-export-config: simulator-wide knobs
	// (catalog, global cap, per-device-source, scheduler mean interval)
	// live on the manager; per-device knobs (collector, format,
	// interval) live on each DeviceSyslogConfig.
	if err := manager.StartSyslogSubsystem(SyslogSubsystemConfig{
		CatalogPath:           *syslogCatalog,
		GlobalCap:             *syslogGlobalCap,
		SourcePerDevice:       *syslogSourcePerDevice,
		MeanSchedulerInterval: *syslogInterval,
	}); err != nil {
		log.Fatalf("Failed to initialize syslog subsystem: %v", err)
	}

	// Start the gNMI subsystem. Always-on per-device when not disabled
	// (design.md §D2): every device created from this point onward
	// binds a TLS-wrapped gRPC listener on -gnmi-port. The opt-out
	// is the subsystem-wide -gnmi-disable flag.
	if err := manager.StartGnmiSubsystem(GnmiSubsystemConfig{
		Port:     *gnmiPort,
		Disabled: *gnmiDisable,
	}); err != nil {
		log.Fatalf("Failed to initialize gNMI subsystem: %v", err)
	}

	// Build the CLI-seed syslog config for the auto-start batch. Mirrors
	// the flow-seed and trap-seed patterns. `DeviceSyslogConfig.Validate`
	// canonicalises Format via ParseSyslogFormat, so a malformed
	// -syslog-format surfaces here.
	var syslogSeed *DeviceSyslogConfig
	if *syslogCollector != "" {
		syslogSeed = &DeviceSyslogConfig{
			Collector: *syslogCollector,
			Format:    *syslogFormat,
			Interval:  jsonDuration(*syslogInterval),
		}
		syslogSeed.ApplyDefaults()
		if err := syslogSeed.Validate(); err != nil {
			log.Fatalf("syslog export: invalid -syslog-* CLI seed: %v", err)
		}
	}

	// Validate -if-error-scenario for the auto-start batch. Invalid
	// scenarios fail fast so operators don't accidentally run with an
	// unintended default.
	autoStartScenario, err := ParseIfErrorScenario(*ifErrorScenario)
	if err != nil {
		log.Fatalf("if_error_scenario: %v", err)
	}

	// Reuse the already-canonicalised flap scenario from StartFlapSubsystem
	// above so we don't double-validate / disagree across two call sites.
	autoStartFlapScenario := flapScenarioCanon

	// Validate auto-creation parameters
	if *autoStartIP != "" && *autoCount <= 0 {
		log.Println("WARNING: -auto-start-ip provided but -auto-count is 0 or negative. No devices will be auto-created.")
	} else if *autoStartIP == "" && *autoCount > 0 {
		log.Println("WARNING: -auto-count provided but -auto-start-ip is empty. No devices will be auto-created.")
	}

	// Setup REST API first
	router := setupRoutes()

	// Start API server in background
	apiPort := ":" + *port
	log.Printf("nl6 — network device simulator starting on port %s", apiPort)
	log.Println()
	log.Println("Web UI:")
	log.Printf("  http://localhost%s/", apiPort)
	log.Printf("  http://localhost%s/ui", apiPort)
	log.Println()

	// Start web server in background. Use http.Server with explicit
	// timeouts (gosec G114) rather than the bare ListenAndServe.
	// 30s covers the slowest local handler today (device-create
	// preallocation); operators driving heavier writes can tune this.
	go func() {
		srv := &http.Server{
			Addr:              apiPort,
			Handler:           router,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Fatal(srv.ListenAndServe())
	}()

	// Give web server a moment to start
	time.Sleep(100 * time.Millisecond)
	log.Printf("Web UI is now available at http://localhost%s/ui", apiPort)
	log.Println()

	// Auto-create devices in background if requested
	if *autoStartIP != "" && *autoCount > 0 {
		go func() {
			log.Printf("Starting background device creation: %d devices from %s/%s", *autoCount, *autoStartIP, *autoNetmask)

			// Create SNMPv3 configuration if engine ID is provided
			var v3Config *SNMPv3Config
			if *snmpv3EngineID != "" {
				authProto := parseAuthProtocol(*snmpv3AuthProto)
				privProto := parsePrivProtocol(*snmpv3PrivProto)

				v3Config = &SNMPv3Config{
					Enabled:      true,
					EngineID:     *snmpv3EngineID,
					Username:     USERNAME, // Use same as SSH
					Password:     PASSWORD, // Use same as SSH
					AuthProtocol: authProto,
					PrivProtocol: privProto,
					PrivPassword: PASSWORD, // Use same password for privacy
				}
				log.Printf("SNMPv3 enabled with engine ID: %s, auth: %s, priv: %s",
					*snmpv3EngineID, *snmpv3AuthProto, *snmpv3PrivProto)
			}

			err := manager.CreateDevices(*autoStartIP, *autoCount, *autoNetmask, "", v3Config, false, "", *snmpPort, &ExportSeed{Flow: flowSeed, Traps: trapSeed, Syslog: syslogSeed, IfErrorScenario: autoStartScenario, IfFlapScenario: autoStartFlapScenario})
			if err != nil {
				log.Printf("Failed to auto-create devices: %v", err)
			} else {
				log.Printf("Successfully auto-created %d devices", *autoCount)
			}
		}()
	}

	// Print API documentation
	log.Println("API Endpoints:")
	log.Println("  POST   /api/v1/devices           - Create devices")
	log.Println("  GET    /api/v1/devices           - List devices")
	log.Println("  GET    /api/v1/devices/export    - Export devices to CSV")
	log.Println("  GET    /api/v1/devices/routes    - Download route configuration script")
	log.Println("  DELETE /api/v1/devices/{id}      - Delete device")
	log.Println("  DELETE /api/v1/devices           - Delete all devices")
	log.Println("  GET    /health                   - Health check")
	log.Println()
	log.Println("Example curl commands:")
	log.Printf(`  curl -X POST http://localhost%s/api/v1/devices -H "Content-Type: application/json" -d '{"start_ip":"192.168.100.1","device_count":3,"netmask":"16"}'`, apiPort)
	log.Println()
	log.Printf(`  curl http://localhost%s/api/v1/devices`, apiPort)
	log.Println()
	log.Printf(`  curl http://localhost%s/api/v1/devices/export -o devices.csv`, apiPort)
	log.Println()
	log.Printf(`  curl http://localhost%s/api/v1/devices/routes -o add_routes.sh`, apiPort)
	log.Println()
	log.Println()
	log.Println("SNMPv3 + SSH Examples:")
	log.Println("  Create devices with SNMPv3 support:")
	log.Printf("    sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 2 \\")
	log.Println()
	log.Printf("      -snmpv3-engine-id 800000090300AABBCCDD -snmpv3-auth md5")
	log.Println()
	log.Println()
	log.Printf("  Or via REST API with SNMPv3:")
	log.Printf(`    curl -X POST http://localhost%s/api/v1/devices \`, apiPort)
	log.Println()
	log.Printf(`      -H "Content-Type: application/json" \`)
	log.Println()
	log.Printf(`      -d '{"start_ip":"192.168.100.1","device_count":1,"netmask":"16",`)
	log.Println()
	log.Printf(`           "snmpv3":{"enabled":true,"engine_id":"800000090300AABBCCDD",`)
	log.Println()
	log.Printf(`           "username":"simadmin","password":"simadmin","auth_protocol":1,"priv_protocol":0}}'`)
	log.Println()
	log.Println()
	log.Println("Connection Examples:")
	log.Println("  SSH (same credentials for all devices):")
	log.Println("    ssh simadmin@<device-ip>")
	log.Println("    Password: simadmin")
	log.Println()
	log.Println("  SNMP v2c (traditional):")
	log.Println("    snmpwalk -v2c -c public <device-ip> 1.3.6.1.2.1.1.1.0")
	log.Println()
	log.Println("  SNMPv3 (when enabled):")
	log.Println("    # MD5 auth, no privacy:")
	log.Println("    snmpwalk -v3 -u simadmin -A simadmin -a MD5 -l authNoPriv <device-ip> 1.3.6.1.2.1.1.1.0")
	log.Println()
	log.Println("    # MD5 auth + DES privacy:")
	log.Println("    snmpwalk -v3 -u simadmin -A simadmin -X simadmin -a MD5 -x DES -l authPriv <device-ip> 1.3.6.1.2.1.1.1.0")
	log.Println()
	log.Println("Additional Tips:")
	log.Println("  - Open the Web UI in your browser for easy management")
	log.Println("  - All devices use same credentials: simadmin/simadmin")
	log.Println("  - SNMPv2c community: public")
	log.Println("  - Check TUN interfaces: ip addr show | grep sim")
	log.Println("  - Test script available: ./test_snmpv3.sh")

	// Keep the main thread alive
	select {}
}
