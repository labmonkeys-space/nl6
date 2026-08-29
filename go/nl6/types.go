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
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

// TUN interface management structures
type TunInterface struct {
	Name         string
	IP           net.IP
	fd           int
	PreAllocated bool // Track if this interface was pre-allocated
	InNamespace  bool // Track if this interface is in a network namespace
}

type SNMPResource struct {
	OID      string `json:"oid"`
	Response string `json:"response"`
}

type SSHResource struct {
	Command  string `json:"command"`
	Response string `json:"response"`
}

type APIResource struct {
	Method   string      `json:"method"`            // HTTP method: GET, POST, PUT, DELETE, PATCH
	Path     string      `json:"path"`              // API endpoint path
	Request  interface{} `json:"request,omitempty"` // Optional request body for POST/PUT
	Response interface{} `json:"response"`          // Response body
}

// OpticalChannel describes one coherent optical channel (OCH) from a
// device's optical inventory, loaded from the `optical` part of an
// optical device type's resource directory.
//
// The channel is keyed by Name — its OpenConfig component name, e.g.
// "OCH-1-1" — and deliberately NOT by ifIndex. An optical channel is not
// an interface: overloading ifIndex would collide with IF-MIB, trip the
// if_counters.go maxResourceIfIndex guards, and misrepresent the model,
// where optical-channel hangs off /components/component rather than
// /interfaces/interface.
type OpticalChannel struct {
	// Name is the OpenConfig component name and the discovery key.
	Name string `json:"name"`
	// LinePort is the chassis line port the channel terminates on,
	// in Ciena's <slot>-<port> form.
	LinePort string `json:"line_port"`
	// FrequencyMHz is the carrier frequency (openconfig frequency is
	// uint64 MHz).
	FrequencyMHz uint64 `json:"frequency_mhz"`
	// OperationalMode is the vendor-defined mode index selecting
	// modulation, baud rate and FEC.
	OperationalMode uint16 `json:"operational_mode"`
	// TargetOutputPowerDBm is the configured launch power.
	TargetOutputPowerDBm float64 `json:"target_output_power_dbm"`
}

type DeviceResources struct {
	SNMP []SNMPResource `json:"snmp"`
	SSH  []SSHResource  `json:"ssh"`
	API  []APIResource  `json:"api,omitempty"` // Optional API endpoints for storage devices
	// Optical is the OCH inventory for optical transport device types.
	// Empty for every packet device type.
	Optical []OpticalChannel `json:"optical,omitempty"`

	// Performance optimization indexes (not serialized)
	oidIndex   *sync.Map `json:"-"` // Lock-free OID -> Response mapping for O(1) lookups
	sortedOIDs []string  `json:"-"` // Pre-sorted OID list for GetNext operations
	oidNextMap *sync.Map `json:"-"` // Pre-computed next OID mapping for walks
}

// Device simulator represents a single simulated device
type DeviceSimulator struct {
	ID           string
	IP           net.IP
	SNMPPort     int
	SSHPort      int
	APIPort      int // HTTP API port for storage devices
	tunIface     *TunInterface
	snmpServer   *SNMPServer
	sshServer    *SSHServer
	apiServer    *APIServer // HTTP API server for storage devices
	resources    *DeviceResources
	resourceFile string // Track which resource file was used
	sysLocation  string // Dynamic sysLocation for this device
	sysName      string // Dynamic sysName for this device
	// Cached frequently accessed values (lock-free)
	cachedSysName     atomic.Value    // Stores string
	cachedSysLocation atomic.Value    // Stores string
	cachedLocation    atomic.Value    // Stores WorldCity (name + coordinates)
	metricsCycler     *MetricsCycler  // Per-device cycling CPU/memory metrics
	flowExporter      *FlowExporter   // NetFlow/IPFIX exporter (nil if flow export disabled)
	trapExporter      *TrapExporter   // SNMP trap/inform exporter (nil if trap export disabled)
	syslogExporter    *SyslogExporter // UDP syslog exporter (nil if syslog export disabled)
	// Per-device export configuration (nil = disabled for this device).
	// Set at device creation from either the CLI seed (auto-start path) or
	// the `flow`/`traps`/`syslog` blocks in POST /api/v1/devices. Wiring
	// lands in phases 3–5 of `per-device-export-config`.
	flowConfig   *DeviceFlowConfig
	trapConfig   *DeviceTrapConfig
	syslogConfig *DeviceSyslogConfig
	// gnmiDialoutConfig is the per-device gNMI dial-out (telemetry push)
	// configuration (nil = dial-out disabled; the device serves dial-in
	// only). Set at device creation from the CLI seed (auto-start batch)
	// or the `gnmi_dialout` block in POST /api/v1/devices. Independent of
	// the dial-in gNMI listener, so the fleet can run mixed.
	gnmiDialoutConfig   *DeviceGnmiDialoutConfig
	gnmiDialoutExporter *GnmiDialoutExporter // nil if dial-out disabled
	// IfErrorScenario controls the ppm bands the per-device counter
	// cycler draws errors and discards from. One of "clean" | "typical"
	// | "degraded" | "failing"; empty defaults to "clean". Set at device
	// creation from either the auto-start ExportSeed or the
	// `if_error_scenario` field in POST /api/v1/devices, and frozen for
	// the lifetime of the device (matches the immutability of other
	// per-device cycler state).
	IfErrorScenario string
	// IfFlapScenario is the per-device link-flap scenario: "clean"
	// (default; no flaps) | "rare" | "typical" | "aggressive". Set at
	// device creation from either the auto-start ExportSeed or the
	// `if_flap_scenario` field in POST /api/v1/devices, and frozen for
	// the lifetime of the device. When non-clean the flap scheduler
	// registers the device's ifIndexes at the end of CreateDevicesWithOptions.
	IfFlapScenario string
	// OpticalScenario controls the steady-state optical health band the
	// per-device optical value engine draws its dial means from:
	// "clean" | "typical" | "degraded" | "failing". Empty is treated as
	// clean. Only meaningful for optical transport device types.
	OpticalScenario string
	netNamespace    *NetNamespace // Network namespace (nil if using root namespace)
	// gNMI per-device gRPC server. Created in startGnmiServer when the
	// gNMI subsystem is enabled (the default). nil means "no listener
	// for this device" — either because the subsystem was disabled at
	// startup or because the device hasn't completed startGnmiServer.
	gnmiServer   *grpc.Server
	gnmiListener net.Listener
	running      bool
	mu           sync.RWMutex
}

// SNMPv3 USM (User-based Security Model) configuration
type SNMPv3Config struct {
	Enabled      bool   `json:"enabled"`
	EngineID     string `json:"engine_id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	AuthProtocol int    `json:"auth_protocol"` // 0=none, 1=MD5, 2=SHA1
	PrivProtocol int    `json:"priv_protocol"` // 0=none, 1=DES, 2=AES128
	PrivPassword string `json:"priv_password"` // Can be same as auth password
}

// SNMPv3 message structures
type SNMPv3Message struct {
	Version        int
	GlobalData     SNMPv3GlobalData
	SecurityParams SNMPv3SecurityParams
	ScopedPDU      []byte // Can be encrypted
}

type SNMPv3GlobalData struct {
	MsgID            int
	MsgMaxSize       int
	MsgFlags         byte
	MsgSecurityModel int
}

type SNMPv3SecurityParams struct {
	AuthoritativeEngineID    string
	AuthoritativeEngineBoots int
	AuthoritativeEngineTime  int
	UserName                 string
	AuthParams               []byte
	PrivParams               []byte
}

type SNMPServer struct {
	device       *DeviceSimulator
	listener     *net.UDPConn
	running      bool
	v3Config     *SNMPv3Config
	cachedDESKey []byte // cached result of generateDESKey()
	cachedAESKey []byte // cached result of generateAESKey()

	// lldpServedCache memoises this device's sorted LLDP served-OID set
	// (see lldpServedOIDs). The set is rebuilt only when the topology
	// generation changes — i.e. on a topology mutation, an oper-status
	// transition, or device creation — so the steady-state GETBULK walk hot
	// path skips the per-request build + sort entirely.
	lldpServedCache atomic.Pointer[lldpServedSnapshot]

	// firstSkipAbort gates the log line for a v1 Counter64 skip loop that
	// ended on a safety bound (see logFirstSkipAbort).
	firstSkipAbort sync.Once

	// firstMalformedList gates the log line for a discarded datagram whose
	// varbind list is not a valid ASN.1 encoding (see logFirstMalformedList).
	firstMalformedList sync.Once

	// firstBulkAbort gates the log line for a v3 GETBULK collection loop that
	// ended on a non-advancing successor (see logFirstBulkAbort).
	firstBulkAbort sync.Once
}

// lldpServedSnapshot is an immutable (gen, served) pair stored under
// SNMPServer.lldpServedCache. served is sorted ascending by compareOIDs and
// must never be mutated after store — it is shared across SNMP goroutines.
type lldpServedSnapshot struct {
	gen    uint64
	served []kvOID
}

type SSHServer struct {
	device   *DeviceSimulator
	listener net.Listener
	config   *ssh.ServerConfig
	running  bool
	signer   ssh.Signer // SSH host key signer
}

type APIServer struct {
	device        *DeviceSimulator
	listener      net.Listener
	server        apiHTTPServer
	running       bool
	sharedTLSCert *tls.Certificate // Shared TLS cert from SimulatorManager
}

// Manager for all simulated devices
type SimulatorManager struct {
	devices map[string]*DeviceSimulator
	// deviceIPs tracks IPs currently bound to a device so that duplicate
	// detection stays robust against changes to the device-ID format. Without
	// it, two concurrent calls that target the same IP with different
	// resource files would both pass the `sm.devices[deviceID]` lookup (the
	// IDs differ by slug) and race to bind the same TUN and SNMP/SSH ports.
	deviceIPs map[string]struct{}
	// deviceTypesByIP maps device IP → type slug. Populated in AddDevice /
	// per-device construction paths so the trap and syslog `CatalogFor(ip)`
	// hot paths can resolve device type in O(1). Kept in sync with `devices`
	// and `deviceIPs`; entries are removed on device deletion.
	deviceTypesByIP map[string]string
	// devicesByIP maps device IP → *DeviceSimulator so FindDeviceByIP is an
	// O(1) map read instead of an O(N) linear scan over `devices`. The LLDP
	// walk hot path resolves a peer device per link per walk step, so the
	// linear scan turned a single GETBULK walk into O(steps × N) work. Kept
	// in sync with `devices` / `deviceIPs` / `deviceTypesByIP`: written when a
	// device is added to `devices`, removed on deletion. Guarded by sm.mu.
	devicesByIP map[string]*DeviceSimulator
	// topology is the simulator-wide inter-device link graph (LLDP
	// topology). Owns its own mutex; safe to call under or outside sm.mu.
	// Populated from -topology-config at startup and the
	// POST/DELETE /api/v1/topology endpoints at runtime; pruned on
	// DeleteDevice. nil only in tests that construct the manager directly.
	topology        *Topology
	currentIP       net.IP
	nextTunIndex    int
	deviceResources *DeviceResources
	resourcesCache  map[string]*DeviceResources // Cache for loaded resource files
	sharedSSHSigner ssh.Signer                  // Shared SSH host key for all devices
	sharedTLSCert   *tls.Certificate            // Shared TLS certificate for all API servers

	// Network namespace for device isolation (prevents systemd-networkd overhead)
	netNamespace *NetNamespace // Network namespace for all simulated devices
	useNamespace bool          // Whether to use network namespace isolation

	// TUN interface pre-allocation settings
	tunPoolSize      int                      // Size of the pre-allocated pool (0 = no pre-allocation)
	maxWorkers       int                      // Maximum parallel workers for interface creation
	tunInterfacePool map[string]*TunInterface // Pool of pre-allocated interfaces indexed by IP
	tunPoolMutex     sync.RWMutex             // Mutex for interface pool access

	// Status tracking for pre-allocation and device creation
	isPreAllocating      atomic.Value // bool - true when pre-allocation is in progress
	preAllocProgress     atomic.Value // int - number of interfaces pre-allocated so far
	isCreatingDevices    atomic.Value // bool - true when device creation is in progress
	deviceCreateProgress atomic.Value // int - number of devices created so far
	deviceCreateTotal    atomic.Value // int - total number of devices to create

	// Flow export state. Per the per-device-export-config refactor, each
	// device owns its collector/protocol/timeouts on its `flowConfig`
	// field. The manager retains:
	//   - a pool of shared UDP sockets keyed by (collector, protocol) for
	//     the fallback path when `flowSourcePerDevice=false`;
	//   - simulator-wide concerns: buf pool, ticker goroutine, global tick
	//     interval, global template interval (design §D5), and stat
	//     counters aggregated across all devices.
	flowConns sync.Map // key: flowConnKey, value: *net.UDPConn (shared-socket fallback pool)
	// flowAggregates holds monotonic per-(collector,protocol) counters
	// that survive device deletion (review decision D1.b). Per-exporter
	// counters are added here on device Stop; GetFlowStatus merges these
	// with live-exporter counters to emit cumulative totals.
	flowAggregates   sync.Map // key: flowConnKey, value: *flowCollectorAggregate
	flowBufPool      sync.Pool
	flowTickInterval time.Duration
	// flowTickerPeriod is the cadence the running ticker actually LATCHED,
	// which is not always flowTickInterval. startFlowTicker runs from the
	// constructor, so the latched value is what runs; reporting the
	// flag-parsing path and only mutates the field — the ticker is never
	// restarted. Reporting flowTickInterval as "effective" would therefore
	// state a cadence nothing runs at. Written once, before the ticker
	// goroutine starts; read concurrently by the device read-back.
	flowTickerPeriod     atomic.Int64
	flowTemplateInterval time.Duration
	flowSourcePerDevice  bool // bind per-device UDP socket in nl6sim ns so src IP = device IP

	// fleetFrozenBy is the SET of load-test scenarios currently freezing fleet
	// membership (empty = not frozen). While non-empty, device create/delete is
	// rejected so a scenario's T0→T1 counter deltas can never be corrupted by
	// mid-window membership changes (FR35/FR38, scenario PR0).
	//
	// A set, not one ID: per-device overlap (#392) lets several scenarios run
	// at once, and a single slot meant the first to finish unfroze the fleet
	// for all of them — silently re-opening the very TOCTOU the freeze closes.
	// The freeze lifts when the LAST holder releases.
	//
	// Guarded by sm.mu; mutated only via freezeFleet/unfreezeFleet. freezeFleet
	// refuses while isCreatingDevices is set, and creation batches publish
	// isCreatingDevices BEFORE their freeze check, so a batch and a freeze can
	// never both proceed (review interlock).
	fleetFrozenBy map[string]struct{}

	// scenarios registers every load-test scenario by ID, keyed s-%06d.
	// Guarded by scenarioMu; scenarioSeq is the monotonic source of that ID
	// (D2/D5).
	//
	// The registry holds many, but the ADMISSION POLICY is what decides how
	// many may be live: today submitScenario still refuses while any scenario
	// is non-terminal, so behaviour is unchanged from the single-slot version
	// this replaced. Per-device overlap (#392) changes that policy without
	// touching this structure — the split is deliberate, so a policy change
	// and a structural change never land in the same diff.
	scenarioMu  sync.Mutex
	scenarios   map[string]*ScenarioController
	scenarioSeq uint64
	// scenarioSnap mirrors the registry for LOCK-FREE iteration, republished
	// under scenarioMu whenever the registry changes. It exists so a running
	// scenario can look up its concurrent peers while holding its own c.mu:
	// taking scenarioMu there would invert the scenarioMu → c.mu order that
	// submitScenario and deleteScenario establish.
	scenarioSnap atomic.Pointer[[]*ScenarioController]
	// scenarioPEN is the IANA Private Enterprise Number used to form
	// PEN-dependent run tags (syslog SD-PARAM `nl6@<PEN>`, SNMP enterprise
	// varbind). 0 = unset → those levers degrade to window + source-IP
	// isolation (FR37). Set once at startup via -scenario-pen; read-only after.
	scenarioPEN uint32

	flowStopCh         chan struct{}  // closed by Shutdown to stop the ticker goroutine
	flowStopOnce       sync.Once      // ensures flowStopCh is closed exactly once
	flowWg             sync.WaitGroup // tracks the ticker goroutine; Wait before tearing down pool
	flowFirstAttachLog sync.Once      // emits a single "flow export active" line on first per-device attach (review fix P4)

	// Simulator-wide "last template send" stamp — aggregated from
	// per-exporter ticks and surfaced via GetFlowStatus.
	// Per-exporter packet/byte/record counters live on the FlowExporter
	// itself and are aggregated at GetFlowStatus read time.
	flowStatLastTmpl atomic.Int64 // unix milliseconds of the most recent template transmission

	// SNMP trap export state. Per the per-device-export-config refactor,
	// each device owns its own collector/mode/community/interval/inform-*
	// settings on `trapConfig`. The manager retains the subsystem-level
	// concerns: catalog, scheduler, shared limiter, and shared-socket
	// pool for the per-device-binding fallback path.
	//
	// trapCatalogsByType is the per-device-type overlay map populated at
	// startup. Key `_universal` holds the universal catalog; other keys
	// are device-type slugs (e.g., "cisco_ios"). `trapCatalog` remains
	// as a legacy alias for the fallback.
	trapCatalog         *Catalog
	trapCatalogsByType  map[string]*Catalog
	trapScheduler       atomic.Pointer[TrapScheduler] // lock-free read so device.Stop can deregister without taking sm.mu
	trapEncoder         TrapEncoder
	trapLimiter         *rate.Limiter // shared global cap (nil = unlimited)
	trapConns           sync.Map      // key: string collector, value: *net.UDPConn (shared-socket fallback pool, TRAP mode only)
	trapAggregates      sync.Map      // key: trapAggKey, value: *trapCollectorAggregate — monotonic counters surviving device delete
	trapFirstAttachLog  atomic.Bool   // CAS-gated so the "trap export active" line fires once per lifecycle; race-free reset on Stop
	trapGlobalCap       int
	trapSourcePerDevice bool
	trapCatalogPath     string // "" when using embedded catalog

	// UDP syslog export state. Per the per-device-export-config refactor,
	// each device owns its own collector/format/interval on `syslogConfig`.
	// The manager retains subsystem-level concerns: catalog, scheduler,
	// shared limiter, and shared-socket pool for the fallback path.
	//
	// syslogCatalogsByType mirrors trapCatalogsByType for the syslog side.
	syslogCatalog         *SyslogCatalog
	syslogCatalogsByType  map[string]*SyslogCatalog
	syslogScheduler       atomic.Pointer[SyslogScheduler] // lock-free read so device.Stop can deregister without taking sm.mu
	syslogEncodersByFmt   map[SyslogFormat]SyslogEncoder  // one encoder per format; lazily populated
	syslogLimiter         *rate.Limiter                   // independent of trap's limiter (design.md §D9)
	syslogConns           sync.Map                        // key: syslogConnKey, value: *net.UDPConn (shared-socket fallback pool)
	syslogAggregates      sync.Map                        // key: syslogConnKey, value: *syslogCollectorAggregate — monotonic counters surviving device delete
	syslogFirstAttachLog  atomic.Bool                     // CAS-gated so the "syslog export active" line fires once per lifecycle; race-free reset on Stop
	syslogGlobalCap       int
	syslogSourcePerDevice bool
	syslogCatalogPath     string // "" when using embedded catalog

	// gNMI subsystem state. Per design.md, the per-device gRPC servers
	// own their own listeners; the manager retains only the
	// subsystem-wide knobs (port, disabled flag) plus the aggregate
	// counters surfaced by GET /api/v1/gnmi/status. All counters are
	// accessed via sync/atomic.
	gnmiPort                 int
	gnmiSubsystemDisabled    atomic.Bool // -gnmi-disable; lock-free read on every device start (P6)
	gnmiSubsystemActive      atomic.Bool
	gnmiActiveSubscriptions  int64  // atomic; live ONCE + STREAM streams (P16)
	gnmiUpdatesSent          uint64 // atomic; cumulative SubscribeResponse.update entries
	gnmiUpdatesDropped       uint64 // atomic; oldest-drop overflow events (§D8)
	gnmiTLSHandshakeFailures uint64 // atomic; per-device listener Accept errors (P17)
	gnmiStateEventsEmitted   uint64 // atomic; cumulative state-change events fanned out to ON_CHANGE subs
	gnmiStateEventsDropped   uint64 // atomic; per-channel oldest-drop overflow

	// gNMI dial-out subsystem state. Each dial-out device owns its own
	// grpc.ClientConn + Publish stream on its gnmiDialoutExporter (no
	// shared connection pool — a single ClientConn caps at ~100 concurrent
	// HTTP/2 streams). The manager retains only an active flag and the
	// per-(collector,flavor) monotonic aggregates that survive device
	// deletion, mirroring the flow/trap/syslog status pattern.
	gnmiDialoutSubsystemActive atomic.Bool
	gnmiDialoutAggregates      sync.Map // key: gnmiDialoutKey, value: *gnmiDialoutAggregate

	// DNS service-discovery subsystem. The server (dns_server.go) reads the
	// live device map through the manager's zoneDataProvider implementation, so
	// there is no per-device DNS state — only the shared SOA serial, a dirty
	// flag, and the debounce worker plumbing. Off by default; Stop is
	// shutdown-only, matching the trap/syslog/gNMI Stop semantics.
	dnsServer          *dnsServer
	dnsSubsystemActive atomic.Bool
	dnsDirty           atomic.Bool
	dnsWake            chan struct{} // buffered(1) debounce signal
	dnsStopCh          chan struct{}
	dnsWg              sync.WaitGroup
	dnsDebounce        time.Duration
	dnsCtx             context.Context // cancelled by Stop to abort in-flight NOTIFY
	dnsCancel          context.CancelFunc
	dnsSerial          atomic.Uint32 // shared SOA serial (all zones advance in lockstep)
	dnsSerialMu        sync.Mutex    // serialises the serial read-modify-write
	dnsZoneBumps       uint64        // atomic; serial-bump events (one per coalesced burst)
	dnsNotifiesSent    uint64        // atomic; NOTIFY messages sent (per zone × secondary)
	dnsNotifyErrors    uint64        // atomic; NOTIFY send failures

	// Flap subsystem state (interface state engine driver). Shared
	// scheduler, same lock-free atomic.Pointer pattern as trap/syslog
	// so the per-device DeleteDevice path can Deregister without
	// re-entering sm.mu. Scenario opt-in is per device (auto-start
	// batch via -if-flap-scenario; REST devices via if_flap_scenario
	// on the POST body).
	//
	// `flapRunCancel` is the cancel func paired with the context the
	// scheduler's Run goroutine receives. StopFlapSubsystem invokes it
	// so any blocking `rate.Limiter.Wait(ctx)` inside Run unblocks
	// immediately — without it, Stop's close-on-stopCh wouldn't reach
	// the goroutine until the next token grant. Lifetime is bound by
	// sm.mu: written under Lock in Start, cleared under Lock in Stop.
	flapScheduler  atomic.Pointer[FlapScheduler]
	flapGlobalCap  int
	flapDefaultIfs IfFlapScenario // auto-start seed only; REST devices default to clean
	flapRunCancel  context.CancelFunc

	// revertTimers tracks pending REST auto-revert goroutines (POST
	// .../oper-status with a `duration` field). Keyed by `revertKey{ip,
	// ifIndex, isOper}` so a second duration POST on the same leaf
	// cancels the first. `device.Stop()` cancels every entry for the
	// device IP; `manager.Shutdown()` cancels all. Bypasses the flap
	// scheduler's global cap (matches trap/syslog on-demand HTTP fire
	// convention — test-harness use case, no rate-limit competition).
	revertTimers sync.Map // revertKey → *revertTimer

	// opticalAlarms is the shared SD/SF threshold evaluator (#347), started
	// unconditionally at subsystem-start (nil only before that point and in
	// tests). Guarded by sm.mu: written once at start, read from
	// device-creation goroutines via RegisterOpticalDevice.
	opticalAlarms *OpticalAlarmEvaluator

	// revertTimerCounts is the per-device atomic counter of in-flight
	// auto-revert goroutines (string IP → *atomic.Int64). Schedule
	// rejects when the counter would exceed `maxRevertTimersPerDevice`;
	// the goroutine's defer decrements on exit. Live entries linger
	// across device delete because cleanup runs in the goroutine; this
	// is fine because they zero out and stop growing.
	revertTimerCounts sync.Map // string IP → *atomic.Int64

	mu sync.RWMutex
}

// Resource file info for API
type ResourceInfo struct {
	Filename string `json:"filename"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Category string `json:"category"`
}

// API request/response structures
type CreateDevicesRequest struct {
	StartIP      string        `json:"start_ip"`
	DeviceCount  int           `json:"device_count"`
	Netmask      string        `json:"netmask"`
	ResourceFile string        `json:"resource_file,omitempty"` // Optional resource file selection
	RoundRobin   bool          `json:"round_robin,omitempty"`   // Optional: cycle through device types
	Category     string        `json:"category,omitempty"`      // Optional: filter round robin to a category
	SNMPv3       *SNMPv3Config `json:"snmpv3,omitempty"`
	PreAllocate  bool          `json:"pre_allocate,omitempty"` // Optional: explicitly enable/disable pre-allocation
	MaxWorkers   int           `json:"max_workers,omitempty"`  // Optional: max workers for pre-allocation
	SNMPPort     int           `json:"snmp_port,omitempty"`    // Optional: UDP port for SNMP listener (default: 161)
	// Per-device export configuration. A nil block disables that export
	// type for the batch. Wiring lands in phases 3–5 of
	// `per-device-export-config`; phase 2 only parses and validates.
	Flow        *DeviceFlowConfig        `json:"flow,omitempty"`
	Traps       *DeviceTrapConfig        `json:"traps,omitempty"`
	Syslog      *DeviceSyslogConfig      `json:"syslog,omitempty"`
	GnmiDialout *DeviceGnmiDialoutConfig `json:"gnmi_dialout,omitempty"`

	// IfErrorScenario selects the per-device error / discard counter
	// scenario: "clean" | "typical" | "degraded" | "failing". Empty
	// defaults to "clean" (NOT to the simulator's CLI seed — REST
	// bodies opt in explicitly, mirroring the per-device-export-config
	// pattern). Validated at handler time; unknown values reject the
	// batch with 400.
	IfErrorScenario string `json:"if_error_scenario,omitempty"`

	// IfFlapScenario selects the per-device link-flap scenario:
	// "clean" (default; no flaps) | "rare" | "typical" | "aggressive".
	// Empty maps to "clean". Same opt-in-explicit semantics as
	// if_error_scenario: REST bodies do NOT inherit the CLI seed.
	IfFlapScenario string `json:"if_flap_scenario,omitempty"`
	// OpticalScenario selects the per-device optical health band for
	// optical transport device types: clean (default) | typical |
	// degraded | failing. Omitting the field yields clean even when the
	// auto-start seed flag says otherwise — the established REST opt-in
	// contract.
	OpticalScenario string `json:"optical_scenario,omitempty"`
}

// RoundRobinDeviceTypes defines all 29 device flavors for round robin creation.
//
// Assignment is `deviceIndex % len(list)` (see CreateDevicesWithOptions),
// so the list is ORDER- AND LENGTH-SENSITIVE. New entries are appended
// rather than inserted, which preserves the type of every device position
// below the old length — but be clear about the limit: growing the list
// necessarily changes the mapping for positions at or above the old
// length (with 28 entries device #29 drew index 0; with 29 it draws index
// 28). Re-provisioning a fleet captured before a type was added will not
// reproduce the same type per IP beyond that point.
var RoundRobinDeviceTypes = []string{
	// Network Devices
	"cisco_catalyst_9500.json",
	"juniper_mx240.json",
	"asr9k.json",
	"palo_alto_pa3220.json",
	"fortinet_fortigate_600e.json",
	"juniper_mx960.json",
	"cisco_nexus_9500.json",
	"huawei_ne8000.json",
	"nec_ix3315.json",
	"arista_7280r3.json",
	"check_point_15600.json",
	"cisco_crs_x.json",
	"cisco_ios.json",
	"extreme_vsp4450.json",
	"nokia_7750_sr12.json",
	"sonicwall_nsa6700.json",
	"dlink_dgs3630.json",
	// Servers
	"dell_poweredge_r750.json",
	"hpe_proliant_dl380.json",
	"ibm_power_s922.json",
	"linux_server.json",
	// GPU Servers
	"nvidia_dgx_a100.json",
	"nvidia_dgx_h100.json",
	"nvidia_hgx_h200.json",
	// Storage
	"netapp_ontap.json",
	"pure_storage_flasharray.json",
	"dell_emc_unity.json",
	"aws_s3_storage.json",
	// Optical Transport (appended — see the index note above)
	"ciena_waveserver5.json",
}

type DeviceInfo struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Interface string `json:"interface,omitempty"`
	SNMPPort  int    `json:"snmp_port"`
	SSHPort   int    `json:"ssh_port"`
	Running   bool   `json:"running"`
	// ResourceFile is the canonical device identifier (e.g.
	// "asr9k.json") accepted by POST /api/v1/devices. Emitted so GET
	// responses can be replayed against POST without the consumer
	// having to reverse-derive the filename from `device_type` (which
	// is a many-to-one display label).
	ResourceFile string `json:"resource_file,omitempty"`
	DeviceType   string `json:"device_type,omitempty"`
	// Per-device export configuration echoed for GET /api/v1/devices
	// consumers. Fields are omitted from JSON when nil. Populated from
	// the device's runtime state in phases 3–5.
	//
	// These are the stored config structs verbatim, so a GET block remains a
	// valid POST block and a read-modify-write client (including the repo's own
	// scripts/fleet.sh import) keeps working. The cadence actually in effect is
	// reported SEPARATELY in EffectiveIntervals — nesting it here made the
	// blocks un-POSTable under DisallowUnknownFields. See
	// export_interval_disclosure.go.
	Flow        *DeviceFlowConfig        `json:"flow,omitempty"`
	Traps       *DeviceTrapConfig        `json:"traps,omitempty"`
	Syslog      *DeviceSyslogConfig      `json:"syslog,omitempty"`
	GnmiDialout *DeviceGnmiDialoutConfig `json:"gnmi_dialout,omitempty"`
	// EffectiveIntervals reports the cadences the schedulers are configured
	// with, for the subsystems this device participates in. Present only when
	// the device has at least one export config. It exists because the
	// per-device interval fields above are accepted, stored, and NOT honored
	// (nl6#445): reporting only what was asked for would let the API confirm a
	// wrong belief.
	EffectiveIntervals *effectiveIntervals `json:"effective_intervals,omitempty"`
	// IfErrorScenario surfaces the per-device counter scenario set at
	// creation time. Omitted from JSON when "" so clean-default devices
	// don't clutter GET responses.
	IfErrorScenario string `json:"if_error_scenario,omitempty"`
	// IfFlapScenario surfaces the per-device link-flap scenario set at
	// creation time. Omitted when clean-default for the same reason.
	IfFlapScenario string `json:"if_flap_scenario,omitempty"`
	// OpticalScenario surfaces the per-device optical health band set at
	// creation time. Omitted when clean-default, matching the two
	// interface scenarios above.
	OpticalScenario string `json:"optical_scenario,omitempty"`
	// Location is the device's assigned world-city string (the same value
	// served as sysLocation.0), previously reachable only via SNMP. Omitted
	// when empty.
	Location string `json:"location,omitempty"`
	// Latitude / Longitude are the coordinates of the assigned location.
	// Pointers so an unresolved location omits them entirely rather than
	// reporting a misleading 0.0 (a legitimate point); always emitted as a
	// pair (both nil or both set).
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// CreateDevicesResult is the `data` payload of a successful POST /api/v1/devices.
// `Created` is the number of devices that actually started; `Requested` is the
// batch size; `Failed` = Requested - Created. Created can be less than Requested
// when devices fail to start under resource pressure at scale — clients should
// reconcile against Requested rather than assume the whole batch came up.
type CreateDevicesResult struct {
	Created   int `json:"created"`
	Requested int `json:"requested"`
	Failed    int `json:"failed"`
	// Warnings disclose settings that were accepted and stored but are not
	// honored by the engine — today the three interval knobs. Additive and
	// omitted when empty, so existing clients are unaffected; the point is
	// that the caller who set the value is the one who hears about it,
	// rather than a container log they will never read.
	Warnings []exportWarning `json:"warnings,omitempty"`
}

// RejectedRequestData is the payload on a 400 that still carries disclosures.
//
// Deliberately NOT CreateDevicesResult: that type's contract is created /
// requested / failed, and a rejection would report "N requested, 0 created,
// 0 failed" for a batch that was never attempted — a client computing
// failed = requested - created reads that as a silent total loss.
type RejectedRequestData struct {
	Warnings []exportWarning `json:"warnings,omitempty"`
}

type ManagerStatus struct {
	IsPreAllocating      bool `json:"is_pre_allocating"`
	PreAllocProgress     int  `json:"pre_alloc_progress"`
	PreAllocTotal        int  `json:"pre_alloc_total"`
	IsCreatingDevices    bool `json:"is_creating_devices"`
	DeviceCreateProgress int  `json:"device_create_progress"`
	DeviceCreateTotal    int  `json:"device_create_total"`
	TotalDevices         int  `json:"total_devices"`
	RunningDevices       int  `json:"running_devices"`
}

// FlowStatus is the JSON body returned by GET /api/v1/flows/status.
//
// BREAKING (per-device-export-config phase 3): the response shape is now
// an array-of-collectors aggregated across devices. The legacy scalar
// `enabled`/`protocol`/`collector`/`total_*` fields were removed — clients
// detect "feature off" via `len(collectors) == 0`.
type FlowStatus struct {
	Collectors       []FlowCollectorStatus `json:"collectors"`
	DevicesExporting int                   `json:"devices_exporting"`
	LastTemplateSend string                `json:"last_template_send,omitempty"`
}

// FlowCollectorStatus is one aggregate record in FlowStatus.Collectors.
// Devices with the same (collector, protocol) tuple collapse into one
// record; counters are cumulative since simulator start across every
// device that has ever exported under that tuple.
type FlowCollectorStatus struct {
	Collector   string `json:"collector"`
	Protocol    string `json:"protocol"`
	Devices     int    `json:"devices"`
	SentPackets uint64 `json:"sent_packets"`
	// SendFailures counts datagrams the kernel refused. sent_packets therefore
	// means "reached the kernel", matching syslog's status shape. Additive in
	// nl6#491; before it, failures were counted as sends and a down collector
	// was invisible here.
	SendFailures uint64 `json:"send_failures"`
	SentBytes    uint64 `json:"sent_bytes"`
	SentRecords  uint64 `json:"sent_records"`
}

// ExportSeed carries the optional per-device export configs handed to
// `CreateDevices` / `CreateDevicesWithOptions`. A non-nil field seeds
// every device in the batch with a copy of the referenced config.
// nil fields mean "no export of this type for this batch".
type ExportSeed struct {
	Flow        *DeviceFlowConfig
	Traps       *DeviceTrapConfig
	Syslog      *DeviceSyslogConfig
	GnmiDialout *DeviceGnmiDialoutConfig
	// IfErrorScenario is the per-device counter scenario for every
	// device created from this seed. Empty string = "clean" default.
	// Despite its home in ExportSeed, this is not an export concept —
	// the seed struct is the natural carrier for "per-device defaults
	// for this batch" and lives alongside the export blocks to keep
	// one plumbing channel instead of several parallel ones.
	IfErrorScenario IfErrorScenario
	// IfFlapScenario is the per-device link-flap scenario for every
	// device created from this seed. Same semantics as IfErrorScenario:
	// non-empty value seeds the device; empty = "clean" no-flap default.
	IfFlapScenario IfFlapScenario
	// OpticalScenario is the per-device optical health band for every
	// device created from this seed. Same semantics as IfErrorScenario:
	// it applies to the auto-start batch only, and a REST request that
	// omits the field gets clean.
	OpticalScenario OpticalScenario
}

// flowConnKey identifies a shared-socket pool entry. One pooled
// *net.UDPConn exists per unique (collector, protocol) tuple when
// `flowSourcePerDevice=false`.
type flowConnKey struct {
	collector string
	protocol  string
}
