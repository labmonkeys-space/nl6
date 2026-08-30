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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Resource-load faults come in exactly two kinds, and callers must be able to
// tell them apart (nl6#538).
//
//   - errResourceInvalid — the file exists and its CONTENT is wrong: JSON that
//     does not parse, a document that decodes to null, an empty device-type
//     directory, a value the SNMP guard rejects, an optical inventory that
//     disagrees with its profile, a resource file NAME that is not a device
//     type slug. This is caller data that is wrong, so it is FATAL at startup
//     and 400 at REST. It is never downgraded to a log line and never
//     substituted for another device type: serving a silently substituted
//     profile is a wrong answer that no collector can detect.
//   - errResourceNotFound — the file or directory is simply absent. This is
//     the ordinary case on a tree that ships only some device types, so a
//     caller may still carry on (the round-robin skip).
//
// Classifying a JSON parse failure as INVALID rather than as a third kind is
// deliberate: it is the same "the operator wrote a bad file" fault as a
// sentinel value.
//
// The two sentinels are NOT redundant even though the REST boundary answers
// both 400 (an unknown device type is an unsatisfiable request, not server
// state): they have a second consumer each, and those disagree. Round-robin
// device creation SKIPS a not-found type and FAILS on an invalid one. Collapse
// the sentinels and that distinction goes with them.
//
// Every error a caller must classify travels with %w. A bare %v at any link
// flattens the chain and makes errors.Is at the handler silently return false.
var (
	errResourceInvalid  = errors.New("invalid resource content")
	errResourceNotFound = errors.New("resource not found")
)

// resourceFileError is a classified fault about one resource file or
// directory. Both kinds use it, distinguished by kind, so the REST boundary
// needs one errors.As to reach the safe rendering of either.
//
// Two renderings are needed and neither can be derived from the other by
// string surgery, because the file name sits mid-sentence: Error() names the
// path as the loader resolved it (that is what belongs in a log), while
// PublicMessage names only the base name (that is what belongs in an HTTP 400
// body, which must not disclose a server-side directory layout).
//
// The fields are File, Msg, kind and cause and NOTHING ELSE. An earlier cut
// carried OID and Value too; nothing read them, because a per-entry fault
// interpolates both into Msg anyway, and a field no rendering reads is a field
// that silently goes stale.
type resourceFileError struct {
	File  string // path as resolved by the loader
	Msg   string // the explanation, with no file prefix of its own
	kind  error  // errResourceInvalid or errResourceNotFound
	cause error  // the underlying error, when there is one; may be nil
}

// Error names the path as the loader resolved it, which is what a log line
// needs. It sanitises both halves: this string reaches log.Printf, and BOTH
// the file name (a REST field) and the message (which quotes file CONTENT) are
// attacker-influenced, so an embedded newline would forge a log line. It is
// deliberately NOT length-capped — a log may carry the whole diagnosis.
func (e *resourceFileError) Error() string {
	return "resource " + sanitiseResourceName(e.File) + ": " + sanitiseForMessage(e.Msg)
}

// PublicMessage renders the same fault for an HTTP body: the file's base name
// only, control characters stripped, and the whole thing length-capped.
//
// Both defences matter because File comes from a REST field and Msg quotes
// file CONTENT. Without them a device_type of "a\nFATAL: everything is fine"
// forges log lines, and a multi-megabyte value in a resource file becomes a
// multi-megabyte error body.
func (e *resourceFileError) PublicMessage() string {
	return truncateForMessage("resource "+sanitiseResourceName(filepath.Base(e.File))+": "+sanitiseForMessage(e.Msg),
		maxResourceMessageBytes)
}

// Unwrap returns BOTH the classification sentinel and the underlying cause, so
// errors.Is(err, errResourceInvalid) and errors.As(err, &jsonSyntaxErr) each
// work. Returning only the sentinel made the cause unrecoverable.
func (e *resourceFileError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}

// maxResourceMessageBytes caps a message rendered into an HTTP body.
const maxResourceMessageBytes = 512

// sanitiseResourceName makes a file name safe to put in a log line or an HTTP
// body: control characters (newlines above all) become "_", and an empty name
// gets a placeholder rather than filepath.Base's bare ".".
func sanitiseResourceName(name string) string {
	if name == "" {
		return "<unnamed>"
	}
	clean := sanitiseForMessage(name)
	if clean == "." || clean == "" {
		return "<unnamed>"
	}
	return clean
}

// sanitiseForMessage replaces every ASCII control character and DEL with "_".
func sanitiseForMessage(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// truncateForMessage caps a rendered message, marking that it was cut.
func truncateForMessage(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "… (truncated)"
}

// invalidResource builds an invalid-CONTENT fault.
func invalidResource(file, format string, args ...interface{}) error {
	return &resourceFileError{File: file, Msg: fmt.Sprintf(format, args...), kind: errResourceInvalid}
}

// invalidResourceCause is invalidResource for a fault with an underlying error
// worth keeping reachable (a *json.SyntaxError, an *os.PathError). The cause is
// NOT printed by Error(); the caller still formats whatever it wants into the
// message. It exists so errors.As can reach it.
func invalidResourceCause(file string, cause error, format string, args ...interface{}) error {
	return &resourceFileError{File: file, Msg: fmt.Sprintf(format, args...), kind: errResourceInvalid, cause: cause}
}

// notFoundResource builds an ABSENT-file fault. The round-robin loader carries
// on past one; the REST boundary answers it 400, because the caller named a
// device type that does not exist.
func notFoundResource(file, format string, args ...interface{}) error {
	return &resourceFileError{File: file, Msg: fmt.Sprintf(format, args...), kind: errResourceNotFound}
}

func (sm *SimulatorManager) LoadResources(filename string) error {
	// Extract directory name from filename (e.g., "resources/asr9k.json" -> "resources/asr9k")
	dirPath := strings.TrimSuffix(filename, ".json")

	// Check if directory exists (new structure)
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		return sm.loadResourcesFromDir(dirPath)
	}

	// Fallback to old single-file format for backwards compatibility
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("Resources file %s not found, creating default resources...", filename)
		if err := sm.createDefaultResources(filename); err != nil {
			// Absent, and the synthesised default could not be written
			// either. Still an ABSENT-file fault, not a content one, so a
			// caller may fall back. The cause stays reachable via errors.As.
			return &resourceFileError{
				File:  filename,
				Msg:   fmt.Sprintf("not found, and default resources could not be created: %v", err),
				kind:  errResourceNotFound,
				cause: err,
			}
		}
		return nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Decoded into a LOCAL, published to sm.deviceResources only once it has
	// validated: a failed load must leave the previous set in place rather
	// than a partial or unindexed one.
	//
	// The local is a *DeviceResources rather than a value because this is the
	// one decode in the package that targets a pointer, and a file containing
	// the literal `null` therefore leaves it nil. validateSNMPResourceValues
	// returns nil for nil input, so before this check buildResourceIndexes
	// dereferenced it and PANICKED.
	var resources *DeviceResources
	if err := json.NewDecoder(file).Decode(&resources); err != nil {
		return invalidResourceCause(filename, err, "failed to parse: %v", err)
	}
	if resources == nil {
		return invalidResource(filename, "decoded to JSON null; expected an object with "+
			"\"snmp\", \"ssh\", \"api\" and/or \"optical\" arrays")
	}

	if err := validateSNMPResourceValues(filename, resources); err != nil {
		return err
	}

	// Build indexes for loaded default resources
	sm.buildResourceIndexes(resources)

	sm.deviceResources = resources

	log.Printf("Loaded %d SNMP and %d SSH resources with indexes", len(resources.SNMP), len(resources.SSH))
	return nil
}

// loadResourcesFromDir loads and merges all JSON files from a directory
func (sm *SimulatorManager) loadResourcesFromDir(dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %v", dirPath, err)
	}

	// Merged into a LOCAL. Assigning sm.deviceResources up front and returning
	// mid-loop on a bad part published a partial, unindexed set onto the
	// manager and destroyed the previously loaded one.
	resources := &DeviceResources{
		SNMP:    make([]SNMPResource, 0),
		SSH:     make([]SSHResource, 0),
		API:     make([]APIResource, 0),
		Optical: make([]OpticalChannel, 0),
	}

	parts := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", dirPath, entry.Name())
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open %s: %v", filePath, err)
		}

		// A value, not a pointer, so a part containing `null` decodes to an
		// empty part rather than to nil. Only LoadResources' single-file
		// decode targets a pointer.
		var partResources DeviceResources
		if err := json.NewDecoder(file).Decode(&partResources); err != nil {
			file.Close()
			return invalidResourceCause(filePath, err, "failed to parse: %v", err)
		}
		file.Close()

		// Validated per part: a resource directory holds ~15 split files, and
		// validating once after the merge would name only the directory.
		if err := validateSNMPResourceValues(filePath, &partResources); err != nil {
			return err
		}

		resources.SNMP = append(resources.SNMP, partResources.SNMP...)
		resources.SSH = append(resources.SSH, partResources.SSH...)
		resources.API = append(resources.API, partResources.API...)
		resources.Optical = append(resources.Optical, partResources.Optical...)
		parts++
	}

	// An existing directory holding no .json part at all is invalid CONTENT,
	// not an absent device type: it was the one surviving route by which a
	// good in-memory set was replaced with nothing, silently and with a
	// success return.
	if parts == 0 {
		return invalidResource(dirPath, "device-type directory contains no .json resource part")
	}

	if err := validateOpticalInventory(resourceFileForDir(dirPath), resources); err != nil {
		return err
	}

	// Build indexes for loaded default resources
	sm.buildResourceIndexes(resources)

	sm.deviceResources = resources

	log.Printf("Loaded %d SNMP and %d SSH resources from directory %s",
		len(resources.SNMP), len(resources.SSH), dirPath)
	return nil
}

// resourceFileForDir maps a resource directory to its canonical resource
// file name (".../resources/ciena_waveserver5" -> "ciena_waveserver5.json").
func resourceFileForDir(dirPath string) string {
	slug := strings.TrimSuffix(dirPath, "/")
	if i := strings.LastIndex(slug, "/"); i >= 0 {
		slug = slug[i+1:]
	}
	return slug + ".json"
}

// validateOpticalInventory fails loudly when an optical device type
// loaded no usable OCH inventory.
//
// This guard exists because the resource decoder is NOT strict: a JSON
// part whose shape the loader does not recognise decodes into a
// zero-valued DeviceResources and is discarded without any error. So a
// typo'd key or a wrong structure in the optical part would otherwise
// yield a silently channel-less optical device, and the failure would
// only surface much later as empty telemetry.
//
// No-op for every non-optical device type.
func validateOpticalInventory(resourceFile string, resources *DeviceResources) error {
	prof := OpticalProfileFor(resourceFile)
	if prof == nil {
		return nil
	}
	if resources == nil || len(resources.Optical) == 0 {
		return invalidResource(resourceFile, "optical device type loaded no optical channels: expected an inventory part "+
			"with an %q array of %d channel(s); note the resource decoder is not strict, so a part whose "+
			"key or shape is wrong is discarded silently — check the JSON structure",
			"optical", prof.ChannelCount)
	}
	seen := make(map[string]struct{}, len(resources.Optical))
	for i, ch := range resources.Optical {
		if ch.Name == "" {
			return invalidResource(resourceFile, "optical device type: channel at index %d has an empty name; "+
				"the OCH component name is the per-channel discovery key and is required", i)
		}
		if _, dup := seen[ch.Name]; dup {
			return invalidResource(resourceFile, "optical device type: duplicate optical channel name %q; "+
				"component names must be unique", ch.Name)
		}
		seen[ch.Name] = struct{}{}
	}
	// Checked last: a malformed channel is a more precise diagnosis than a
	// count mismatch, and both would otherwise be true at once.
	if prof.ChannelCount > 0 && len(resources.Optical) != prof.ChannelCount {
		return invalidResource(resourceFile, "optical device type declares %d optical channel(s) in its device profile "+
			"but its inventory loaded %d; profile and inventory must agree, or one of them is stale",
			prof.ChannelCount, len(resources.Optical))
	}
	return nil
}

// normaliseResourceOID gives a resource-file OID key the leading dot that
// oidTypeTable, oidIndex and every lookup expect. Resource files may spell a
// key either way; this is the single place that reconciles them.
func normaliseResourceOID(oid string) string {
	if len(oid) > 0 && oid[0] != '.' {
		return "." + oid
	}
	return oid
}

// validateSNMPResourceValues rejects a resource response that collides with an
// RFC 3416 exception sentinel (nl6#523). Same loud-fail shape as
// validateOpticalInventory: the error names the file, the OID and the value,
// because fixing it means editing one line of one file.
//
// The exceptions travel from lookup to encoder as strings in the VALUE space
// (valueNoSuchObject, valueEndOfMibView), so a file whose response is literally
// one of them is encoded as the exception tag instead of the OCTET STRING it
// asked for, and a v1 manager gets error-status noSuchName. Removing the
// hazard at the root means a typed value rather than a string, which is the
// larger fix #523 defers. This closes the RESOURCE-FILE route to it; sysName
// and sysLocation are served outside the resource map (sysLocation comes from
// the operator-supplied worldcities CSV) and are NOT covered.
//
// The test is isSNMPExceptionValue, which is EXACT: "noSuchObject seen",
// "NoSuchObject" and " noSuchObject" are ordinary data and load.
//
// Rejecting rather than warning (unlike the trap-catalog size check, which
// disables oversized entries) is defensible because this rule depends on no
// operator-settable knob: the whole shipped set passes, so a refusal can only
// come from a file the operator wrote and can fix.
//
// Scope is the SNMP `snmp` array only. SSH, API and Optical entries never reach
// encodeTypedValue, and the trap/syslog catalogs use a different encoder. It is
// wired at the four loaders a resource file can reach. createDefaultResources
// writes compiled-in constants and is deliberately not guarded: no input can
// make that check fire.
//
// Two rules. The sentinel rule above (nl6#523), checked FIRST because
// encodeTypedValue tests the sentinel before the type tag, so it is the
// diagnosis that matches what the wire would do. Then the OID-typed value rule
// (nl6#529): a value on a leaf whose snmpTypeTag is ASN1_OBJECT_ID must be one
// encodeOID can represent, decided by asking the encoder (encodableAsOID).
// Before nl6#529 such a value was encoded anyway, as a different and
// valid-looking OID; since the encoder fix it becomes the degenerate 06 00.
// Coverage is bounded by oidTypeTable, which today carries one OBJECT
// IDENTIFIER row (sysObjectID).
func validateSNMPResourceValues(resourceFile string, resources *DeviceResources) error {
	if resources == nil {
		return nil
	}
	for _, r := range resources.SNMP {
		if isSNMPExceptionValue(r.Response) {
			return invalidResource(resourceFile,
				"OID %s has value %q, which collides with an SNMP exception "+
					"sentinel and would be encoded as an RFC 3416 exception instead of a string. "+
					"There is no escaping form: change the value. To make the OID answer "+
					"noSuchObject on purpose, omit the entry entirely, since an absent OID "+
					"already answers with the exception",
				r.OID, r.Response)
		}

		if snmpTypeTag(normaliseResourceOID(r.OID)) == ASN1_OBJECT_ID && !encodableAsOID(r.Response) {
			return invalidResource(resourceFile,
				"OID %s is OID-typed (OBJECT IDENTIFIER) but its value %q "+
					"is not an OID this encoder can represent. It needs at least two dot-separated "+
					"numbers, a first arc of 0, 1 or 2, a second arc no greater than 39 when the first "+
					"is 0 or 1, every arc within 4294967295, and an encoded body under 65536 bytes. "+
					"Correct the value; served as-is it would go out as the degenerate encoding 06 00",
				r.OID, r.Response)
		}
	}
	return nil
}

func (sm *SimulatorManager) createDefaultResources(filename string) error {
	defaultResources := &DeviceResources{
		SNMP: []SNMPResource{
			{OID: "1.3.6.1.2.1.1.1.0", Response: "Cisco IOS Software, Router Version 15.1"},
			{OID: "1.3.6.1.2.1.1.2.0", Response: "1.3.6.1.4.1.9.1.1"},
			{OID: "1.3.6.1.2.1.1.3.0", Response: "123456789"},
			{OID: "1.3.6.1.2.1.1.4.0", Response: "Network Administrator"},
			{OID: "1.3.6.1.2.1.1.5.0", Response: "Router-Simulator"},
			{OID: "1.3.6.1.2.1.1.6.0", Response: "Simulation Lab"},
			{OID: "1.3.6.1.2.1.2.1.0", Response: "4"},
			{OID: "1.3.6.1.2.1.2.2.1.1.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.2.1", Response: "FastEthernet0/0"},
			{OID: "1.3.6.1.2.1.2.2.1.3.1", Response: "6"},
			{OID: "1.3.6.1.2.1.2.2.1.5.1", Response: "1000000000"},
			{OID: "1.3.6.1.2.1.2.2.1.7.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.8.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.10.1", Response: "1000000"},
			{OID: "1.3.6.1.2.1.2.2.1.16.1", Response: "500000"},
			{OID: "1.3.6.1.2.1.4.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.4.2.0", Response: "64"},
			{OID: "1.3.6.1.2.1.4.3.0", Response: "100"},
			{OID: "1.3.6.1.2.1.4.4.0", Response: "0"},
			{OID: "1.3.6.1.2.1.4.5.0", Response: "10"},
			{OID: "1.3.6.1.2.1.6.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.6.2.0", Response: "60"},
			{OID: "1.3.6.1.2.1.6.4.0", Response: "2"},
			{OID: "1.3.6.1.2.1.6.5.0", Response: "1000"},
			{OID: "1.3.6.1.2.1.6.6.0", Response: "500"},
			{OID: "1.3.6.1.2.1.6.8.0", Response: "200"},
			{OID: "1.3.6.1.2.1.6.9.0", Response: "100"},
			{OID: "1.3.6.1.2.1.7.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.7.2.0", Response: "1000"},
			{OID: "1.3.6.1.2.1.7.3.0", Response: "500"},
		},
		SSH: []SSHResource{
			{Command: "show version", Response: "Cisco IOS Software, Router Version 15.1\nDevice Simulator v1.0\nUptime: 1 day, 2 hours, 30 minutes"},
			{Command: "show interfaces", Response: "FastEthernet0/0 is up, line protocol is up\n  Hardware is FastEthernet, address is 0011.2233.4455\n  Internet address is 192.168.1.1/24\n  MTU 1500 bytes, BW 100000 Kbit/sec"},
			{Command: "show ip route", Response: "Codes: L - local, C - connected, S - static\nGateway of last resort is 192.168.1.254 to network 0.0.0.0\nC    192.168.1.0/24 is directly connected, FastEthernet0/0"},
			{Command: "show running-config", Response: "version 15.1\nhostname Router-Simulator\ninterface FastEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"},
			{Command: "show processes cpu", Response: "CPU utilization for five seconds: 2%/0%; one minute: 3%; five minutes: 4%\nPID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process\n  1        1000       10000        100  0.5%   0.6%   0.7%   0 Init"},
			{Command: "show memory", Response: "Head    Total(b)     Used(b)     Free(b)   Lowest(b)  Largest(b)\nProcessor  67108864    33554432    33554432   30000000   30000000\n I/O     16777216     8388608     8388608    8000000    8000000"},
			{Command: "ping 8.8.8.8", Response: "Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:\n!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms"},
			{Command: "traceroute 8.8.8.8", Response: "Type escape sequence to abort.\nTracing the route to 8.8.8.8\n  1 192.168.1.254 4 msec 2 msec 4 msec\n  2 * * *\n  3 8.8.8.8 20 msec 18 msec 20 msec"},
		},
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(defaultResources); err != nil {
		return err
	}

	// Build indexes for default resources too
	sm.buildResourceIndexes(defaultResources)

	sm.deviceResources = defaultResources
	log.Printf("Created default resources file %s with %d SNMP and %d SSH resources",
		filename, len(defaultResources.SNMP), len(defaultResources.SSH))

	return nil
}

// resourceFilenameRe is the allowlist for resource file names reaching the
// filesystem: a device-type slug plus the ".json" suffix. The name flows in
// from the REST device_type field, so this is the path-injection choke point
// — anything with separators, dots, or other metacharacters is rejected
// before any os.Stat/Open/ReadDir sees it (CodeQL go/path-injection).
var resourceFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.json$`)

// LoadSpecificResources loads resources from a directory in the resources folder
func (sm *SimulatorManager) LoadSpecificResources(filename string) (*DeviceResources, error) {
	if !resourceFilenameRe.MatchString(filename) {
		// Caller data that is wrong, so it is classified with the content
		// faults and takes the same 400 at REST. filepath.Base keeps a name
		// with separators in it out of the response body.
		return nil, invalidResource(filename, "invalid resource file name (expected <device-type>.json, "+
			"a slug of letters, digits, underscores and hyphens)")
	}

	// Check cache first
	if cached, exists := sm.resourcesCache[filename]; exists {
		return cached, nil
	}

	// Extract directory name (e.g., "cisco_catalyst_9500.json" -> "cisco_catalyst_9500")
	dirName := strings.TrimSuffix(filename, ".json")
	dirPath := fmt.Sprintf("resources/%s", dirName)

	// Check if directory exists (new structure)
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		return sm.loadSpecificResourcesFromDir(dirPath, filename)
	}

	// Fallback to old single-file format for backwards compatibility
	resourcePath := fmt.Sprintf("resources/%s", filename)
	if _, err := os.Stat(resourcePath); os.IsNotExist(err) {
		return nil, notFoundResource(filename, "no such device type: neither the directory resources/%s nor the file resources/%s exists",
			strings.TrimSuffix(filename, ".json"), filename)
	}

	file, err := os.Open(resourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open resource file %s: %v", resourcePath, err)
	}
	defer file.Close()

	// Decoded into a POINTER so a document that is literally `null` is
	// DISTINGUISHABLE from an empty object (nl6#538). Into a value it decoded
	// to a zero DeviceResources, passed the guard, was cached, and produced
	// devices that answer no OID at all — no error and no warning. A
	// single-file resource that says nothing is invalid content on every
	// loader, not just the startup one.
	//
	// Directory PARTS keep decoding into a value: a part legitimately carries
	// only some sections, so an empty one is ordinary there.
	var resources *DeviceResources
	if err := json.NewDecoder(file).Decode(&resources); err != nil {
		return nil, invalidResourceCause(resourcePath, err, "failed to parse: %v", err)
	}
	if resources == nil {
		return nil, invalidResource(resourcePath, "decoded to JSON null; expected an object with "+
			"\"snmp\", \"ssh\", \"api\" and/or \"optical\" arrays")
	}

	if err := validateSNMPResourceValues(resourcePath, resources); err != nil {
		return nil, err
	}

	// Build performance indexes for fast lookups (also sorts by OID after normalizing)
	sm.buildResourceIndexes(resources)

	// Cache the loaded resources with indexes
	sm.resourcesCache[filename] = resources

	return resources, nil
}

// loadSpecificResourcesFromDir loads and merges all JSON files from a resource directory
func (sm *SimulatorManager) loadSpecificResourcesFromDir(dirPath string, cacheKey string) (*DeviceResources, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %v", dirPath, err)
	}

	resources := &DeviceResources{
		SNMP:    make([]SNMPResource, 0),
		SSH:     make([]SSHResource, 0),
		API:     make([]APIResource, 0),
		Optical: make([]OpticalChannel, 0),
	}

	parts := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", dirPath, entry.Name())
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", filePath, err)
		}

		var partResources DeviceResources
		if err := json.NewDecoder(file).Decode(&partResources); err != nil {
			file.Close()
			return nil, invalidResourceCause(filePath, err, "failed to parse: %v", err)
		}
		file.Close()

		// Validated per part, for the same reason as loadResourcesFromDir.
		if err := validateSNMPResourceValues(filePath, &partResources); err != nil {
			return nil, err
		}

		resources.SNMP = append(resources.SNMP, partResources.SNMP...)
		resources.SSH = append(resources.SSH, partResources.SSH...)
		resources.API = append(resources.API, partResources.API...)
		resources.Optical = append(resources.Optical, partResources.Optical...)
		parts++
	}

	// Same rule as loadResourcesFromDir: an empty directory is invalid
	// content, and here it would otherwise be CACHED as an empty device type.
	if parts == 0 {
		return nil, invalidResource(dirPath, "device-type directory contains no .json resource part")
	}

	if err := validateOpticalInventory(resourceFileForDir(dirPath), resources); err != nil {
		return nil, err
	}

	// Build performance indexes for fast lookups (also sorts by OID after normalizing)
	sm.buildResourceIndexes(resources)

	// Cache the loaded resources with indexes
	sm.resourcesCache[cacheKey] = resources

	return resources, nil
}

// buildResourceIndexes builds performance optimization indexes for fast OID lookups
func (sm *SimulatorManager) buildResourceIndexes(resources *DeviceResources) {
	// Sort SNMP resources by OID numerically so that SNMP walks return OIDs in
	// strictly increasing order (column-major table ordering). JSON files store
	// OIDs in row-major order, so without this sort the oidNextMap produces an
	// "OID not increasing" error when snmpwalk crosses row boundaries.
	sort.Slice(resources.SNMP, func(i, j int) bool {
		return compareOIDsLexicographically(resources.SNMP[i].OID, resources.SNMP[j].OID) < 0
	})

	// Initialize lock-free sync.Map for O(1) OID lookups
	resources.oidIndex = &sync.Map{}

	// Initialize sorted OID slice for binary search in GetNext operations
	resources.sortedOIDs = make([]string, 0, len(resources.SNMP))

	// Initialize next OID map for pre-computed walk paths
	resources.oidNextMap = &sync.Map{}

	// Build oidIndex and sortedOIDs, skipping dynamic OIDs handled elsewhere.
	// Normalize OIDs from JSON to always use a leading dot.
	for _, resource := range resources.SNMP {
		oid := normaliseResourceOID(resource.OID)
		if oid == ".1.3.6.1.2.1.1.5.0" || oid == ".1.3.6.1.2.1.1.6.0" {
			continue
		}
		resources.oidIndex.Store(oid, resource.Response)
		resources.sortedOIDs = append(resources.sortedOIDs, oid)
	}

	// Sort OIDs into lexicographic order. Resource JSON files group OIDs by
	// interface (all columns for interface 1, then interface 2, etc.), not by
	// column, so the raw order is not lexicographic. Binary search in
	// findNextOID and the oidNextMap both require lexicographic ordering.
	sort.Slice(resources.sortedOIDs, func(i, j int) bool {
		return compareOIDsLexicographically(resources.sortedOIDs[i], resources.sortedOIDs[j]) < 0
	})

	// Build oidNextMap from sortedOIDs rather than from the raw SNMP slice.
	// The old loop used SNMP[i+1] which could land on a skipped special OID
	// (sysName/sysLocation). Those OIDs are absent from oidIndex, so the fast
	// path in findNextOID silently fell back to binary search for every OID
	// immediately preceding a special OID.
	for i := 0; i < len(resources.sortedOIDs)-1; i++ {
		resources.oidNextMap.Store(resources.sortedOIDs[i], resources.sortedOIDs[i+1])
	}
}

// ListAvailableResources lists all available resource directories in the resources directory
func (sm *SimulatorManager) ListAvailableResources() []ResourceInfo {
	var resources []ResourceInfo

	resourceDir := "resources"
	entries, err := os.ReadDir(resourceDir)
	if err != nil {
		log.Printf("Failed to read resources directory: %v", err)
		return resources
	}

	for _, entry := range entries {
		// Look for directories (new structure) containing JSON files
		if entry.IsDir() {
			name := entry.Name()
			deviceType := getDeviceTypeFromName(name)

			// Verify directory contains at least one JSON file
			dirPath := fmt.Sprintf("%s/%s", resourceDir, name)
			subEntries, err := os.ReadDir(dirPath)
			if err != nil {
				continue
			}

			hasJSON := false
			for _, subEntry := range subEntries {
				if !subEntry.IsDir() && strings.HasSuffix(subEntry.Name(), ".json") {
					hasJSON = true
					break
				}
			}

			if hasJSON {
				resources = append(resources, ResourceInfo{
					Filename: name + ".json", // Keep .json suffix for API compatibility
					Name:     name,
					Type:     deviceType,
					Category: getDeviceCategoryFromName(name),
				})
			}
		}
	}

	return resources
}

// getDeviceTypeFromName determines the device type from a resource name
func getDeviceTypeFromName(name string) string {
	nameLower := strings.ToLower(name)

	if strings.Contains(nameLower, "asr9k") {
		return "Cisco ASR9K"
	} else if strings.Contains(nameLower, "cisco") && strings.Contains(nameLower, "ios") {
		return "Cisco IOS"
	} else if strings.Contains(nameLower, "cisco") {
		return "Cisco Router/Switch"
	} else if strings.Contains(nameLower, "juniper") {
		return "Juniper"
	} else if strings.Contains(nameLower, "nexus") {
		return "Cisco Nexus"
	} else if strings.Contains(nameLower, "arista") {
		return "Arista"
	} else if strings.Contains(nameLower, "fortinet") {
		return "Fortinet"
	} else if strings.Contains(nameLower, "palo") {
		return "Palo Alto"
	} else if strings.Contains(nameLower, "check_point") {
		return "Check Point"
	} else if strings.Contains(nameLower, "dell") {
		return "Dell"
	} else if strings.Contains(nameLower, "hpe") || strings.Contains(nameLower, "hp") {
		return "HPE"
	} else if strings.Contains(nameLower, "huawei") {
		return "Huawei"
	} else if strings.Contains(nameLower, "nokia") {
		return "Nokia"
	} else if strings.Contains(nameLower, "extreme") {
		return "Extreme Networks"
	} else if strings.Contains(nameLower, "dlink") || strings.Contains(nameLower, "d-link") {
		return "D-Link"
	} else if strings.Contains(nameLower, "sonicwall") {
		return "SonicWall"
	} else if strings.Contains(nameLower, "nec") {
		return "NEC"
	} else if strings.Contains(nameLower, "ibm") {
		return "IBM"
	} else if strings.Contains(nameLower, "netapp") {
		return "NetApp"
	} else if strings.Contains(nameLower, "pure") {
		return "Pure Storage"
	} else if strings.Contains(nameLower, "aws") {
		return "AWS"
	} else if strings.Contains(nameLower, "linux") {
		return "Linux Server"
	} else if strings.Contains(nameLower, "nvidia") || strings.Contains(nameLower, "dgx") || strings.Contains(nameLower, "hgx") {
		return "NVIDIA GPU Server"
	} else if strings.Contains(nameLower, "ciena") || strings.Contains(nameLower, "waveserver") {
		return "Ciena Waveserver 5"
	}

	// Capitalize first letter of name as fallback
	if len(name) > 0 {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return "Unknown"
}

// getDeviceCategoryFromName determines the device category from a resource name.
func getDeviceCategoryFromName(name string) string {
	nameLower := strings.ToLower(name)

	// Optical Transport (coherent DWDM transponders / muxponders).
	// Checked before Network Devices: an optical transport platform is not
	// a router or switch, and its telemetry model is entirely different.
	if strings.Contains(nameLower, "ciena") || strings.Contains(nameLower, "waveserver") {
		return "Optical Transport"
	}

	// Network Devices (routers, switches, firewalls)
	if strings.Contains(nameLower, "asr9k") || strings.Contains(nameLower, "crs") ||
		strings.Contains(nameLower, "mx240") || strings.Contains(nameLower, "mx960") ||
		strings.Contains(nameLower, "ne8000") || strings.Contains(nameLower, "7750") ||
		strings.Contains(nameLower, "nec") || (strings.Contains(nameLower, "cisco") && strings.Contains(nameLower, "ios")) ||
		strings.Contains(nameLower, "catalyst") || strings.Contains(nameLower, "nexus") ||
		strings.Contains(nameLower, "arista") || strings.Contains(nameLower, "extreme") ||
		strings.Contains(nameLower, "dlink") || strings.Contains(nameLower, "d-link") ||
		strings.Contains(nameLower, "palo") || strings.Contains(nameLower, "fortinet") ||
		strings.Contains(nameLower, "fortigate") || strings.Contains(nameLower, "check_point") ||
		strings.Contains(nameLower, "sonicwall") || strings.Contains(nameLower, "nokia") ||
		strings.Contains(nameLower, "huawei") || strings.Contains(nameLower, "juniper") {
		return "Network Devices"
	}

	// GPU Servers
	if strings.Contains(nameLower, "nvidia") || strings.Contains(nameLower, "dgx") ||
		strings.Contains(nameLower, "hgx") {
		return "GPU Servers"
	}

	// Storage
	if strings.Contains(nameLower, "netapp") || strings.Contains(nameLower, "pure") ||
		strings.Contains(nameLower, "dell_emc") || strings.Contains(nameLower, "aws") {
		return "Storage"
	}

	// Servers
	if strings.Contains(nameLower, "dell") || strings.Contains(nameLower, "hpe") ||
		strings.Contains(nameLower, "hp") || strings.Contains(nameLower, "ibm") ||
		strings.Contains(nameLower, "linux") || strings.Contains(nameLower, "poweredge") ||
		strings.Contains(nameLower, "proliant") || strings.Contains(nameLower, "power_s") {
		return "Servers"
	}

	return "Other"
}

// getDeviceTypeFromResourceFile determines the device type from a resource filename
func getDeviceTypeFromResourceFile(filename string) string {
	if filename == "" {
		return "Default"
	}

	name := strings.TrimSuffix(filename, ".json")
	return getDeviceTypeFromName(name)
}
