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
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
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

type DeviceResources struct {
	SNMP []SNMPResource `json:"snmp"`
	SSH  []SSHResource  `json:"ssh"`
	API  []APIResource  `json:"api,omitempty"` // Optional API endpoints for storage devices

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
	// IfErrorScenario controls the ppm bands the per-device counter
	// cycler draws errors and discards from. One of "clean" | "typical"
	// | "degraded" | "failing"; empty defaults to "clean". Set at device
	// creation from either the auto-start ExportSeed or the
	// `if_error_scenario` field in POST /api/v1/devices, and frozen for
	// the lifetime of the device (matches the immutability of other
	// per-device cycler state).
	IfErrorScenario string
	netNamespace    *NetNamespace // Network namespace (nil if using root namespace)
	running         bool
	mu              sync.RWMutex
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
	flowAggregates       sync.Map // key: flowConnKey, value: *flowCollectorAggregate
	flowBufPool          sync.Pool
	flowTickInterval     time.Duration
	flowTemplateInterval time.Duration
	flowSourcePerDevice  bool           // bind per-device UDP socket in opensim ns so src IP = device IP
	flowStopCh           chan struct{}  // closed by Shutdown to stop the ticker goroutine
	flowStopOnce         sync.Once      // ensures flowStopCh is closed exactly once
	flowWg               sync.WaitGroup // tracks the ticker goroutine; Wait before tearing down pool
	flowFirstAttachLog   sync.Once      // emits a single "flow export active" line on first per-device attach (review fix P4)

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
	trapIntervalWarned  atomic.Bool   // CAS-gated divergence warning — one line per lifecycle, not per device (phase-5 review P13)
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
	syslogLimiter         *rate.Limiter                  // independent of trap's limiter (design.md §D9)
	syslogConns           sync.Map                       // key: syslogConnKey, value: *net.UDPConn (shared-socket fallback pool)
	syslogAggregates      sync.Map                       // key: syslogConnKey, value: *syslogCollectorAggregate — monotonic counters surviving device delete
	syslogFirstAttachLog  atomic.Bool                    // CAS-gated so the "syslog export active" line fires once per lifecycle; race-free reset on Stop
	syslogIntervalWarned  atomic.Bool                    // CAS-gated divergence warning — one line per lifecycle, not per device (phase-5 review P13)
	syslogGlobalCap       int
	syslogSourcePerDevice bool
	syslogCatalogPath     string // "" when using embedded catalog

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
	Flow   *DeviceFlowConfig   `json:"flow,omitempty"`
	Traps  *DeviceTrapConfig   `json:"traps,omitempty"`
	Syslog *DeviceSyslogConfig `json:"syslog,omitempty"`

	// IfErrorScenario selects the per-device error / discard counter
	// scenario: "clean" | "typical" | "degraded" | "failing". Empty
	// defaults to "clean" (NOT to the simulator's CLI seed — REST
	// bodies opt in explicitly, mirroring the per-device-export-config
	// pattern). Validated at handler time; unknown values reject the
	// batch with 400.
	IfErrorScenario string `json:"if_error_scenario,omitempty"`
}

// RoundRobinDeviceTypes defines all 28 device flavors for round robin creation
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
}

type DeviceInfo struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	Interface  string `json:"interface,omitempty"`
	SNMPPort   int    `json:"snmp_port"`
	SSHPort    int    `json:"ssh_port"`
	Running    bool   `json:"running"`
	DeviceType string `json:"device_type,omitempty"`
	// Per-device export configuration echoed for GET /api/v1/devices
	// consumers. Fields are omitted from JSON when nil. Populated from
	// the device's runtime state in phases 3–5.
	Flow   *DeviceFlowConfig   `json:"flow,omitempty"`
	Traps  *DeviceTrapConfig   `json:"traps,omitempty"`
	Syslog *DeviceSyslogConfig `json:"syslog,omitempty"`
	// IfErrorScenario surfaces the per-device counter scenario set at
	// creation time. Omitted from JSON when "" so clean-default devices
	// don't clutter GET responses.
	IfErrorScenario string `json:"if_error_scenario,omitempty"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
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
	SentBytes   uint64 `json:"sent_bytes"`
	SentRecords uint64 `json:"sent_records"`
}

// ExportSeed carries the optional per-device export configs handed to
// `CreateDevices` / `CreateDevicesWithOptions`. A non-nil field seeds
// every device in the batch with a copy of the referenced config.
// nil fields mean "no export of this type for this batch".
type ExportSeed struct {
	Flow   *DeviceFlowConfig
	Traps  *DeviceTrapConfig
	Syslog *DeviceSyslogConfig
	// IfErrorScenario is the per-device counter scenario for every
	// device created from this seed. Empty string = "clean" default.
	// Despite its home in ExportSeed, this is not an export concept —
	// the seed struct is the natural carrier for "per-device defaults
	// for this batch" and lives alongside the export blocks to keep
	// one plumbing channel instead of several parallel ones.
	IfErrorScenario IfErrorScenario
}

// flowConnKey identifies a shared-socket pool entry. One pooled
// *net.UDPConn exists per unique (collector, protocol) tuple when
// `flowSourcePerDevice=false`.
type flowConnKey struct {
	collector string
	protocol  string
}
