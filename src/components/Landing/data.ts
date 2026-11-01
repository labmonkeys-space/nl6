// Content tables for the nl6 landing page.
// Kept as a plain module so it's cheap to tweak without touching components.

export type Feature = { icon: string; title: string; body: string };
export type Category = { name: string; items: string[] };
export type DocGroup = { group: string; body: string; links: { t: string; h: string }[] };
export type StatusGroup = { k: string; items: string[] };
export type TerminalLine =
  | { k: 'cmd' | 'out' | 'ok'; text: string }
  | { k: 'bar'; text: string }
  | { k: 'blank' };

export const CATEGORIES: Category[] = [
  { name: 'Core Routers',    items: ['Cisco ASR9K · 48', 'Cisco ASR 9902 · 50', 'Cisco CRS-X · 144', 'Huawei NE8000 · 96', 'Nokia 7750 SR-12 · 72', 'Juniper MX960 · 80', 'Juniper MX10004 · 80'] },
  { name: 'Edge Routers',    items: ['Juniper MX240 · 24', 'NEC IX3315 · 48'] },
  { name: 'DC Switches',     items: ['Cisco Nexus 9500 · 64', 'Arista 7280R3 · 32'] },
  { name: 'Campus Switches', items: ['Cisco Catalyst 9500 · 48', 'Extreme VSP4450 · 48', 'D-Link DGS-3630 · 52', 'Cisco IOS · 4'] },
  { name: 'Firewalls',       items: ['Palo Alto PA-3220 · 16', 'Fortinet FortiGate-600E · 20', 'SonicWall NSa 6700 · 16', 'Check Point 15600 · 24'] },
  { name: 'Servers',         items: ['Dell PowerEdge R750', 'HPE ProLiant DL380', 'IBM Power S922', 'Linux Server · Ubuntu 24.04'] },
  { name: 'GPU Servers',     items: ['NVIDIA DGX-A100 · 8×80GB', 'NVIDIA DGX-H100 · 8×80GB', 'NVIDIA HGX-H200 · 8×141GB'] },
  { name: 'Storage',         items: ['AWS S3', 'Pure Storage FlashArray', 'NetApp ONTAP', 'Dell EMC Unity'] },
  { name: 'Optical',         items: ['Ciena Waveserver 5'] },
];

// Derived from CATEGORIES so the counts cannot drift from the list.
export const TYPE_COUNT = CATEGORIES.reduce((n, c) => n + c.items.length, 0);
export const CATEGORY_COUNT = CATEGORIES.length;

export const FEATURES: Feature[] = [
  { icon: 'scale', title: '30,000 devices', body: 'Tested scale on a single host. Parallel TUN pre-allocation, lock-free sync.Map for O(1) OID lookups, pre-computed next-OID mappings.' },
  { icon: 'proto', title: 'Protocols', body: 'SNMP v1/v2c/v3 (MD5/SHA1 · DES/AES128) with opt-in SET, SSH with VT100, HTTPS REST, gNMI (OpenConfig plus per-type catalogues), NETCONF on Catalyst 9500 and MX10004, LLDP topology. Push exporters: NetFlow v5 / v9 / IPFIX with NBAR2, sFlow v5 (experimental), SNMP traps/informs, syslog over UDP/TCP/TLS, gNMI dial-out.' },
  { icon: 'metric', title: 'Load-test fidelity', body: 'Arm → run a bounded push experiment over 7 protocols → get an exact sent-ledger. Diff it against your monitor to localize missed or duplicated telemetry. Fidelity mode, loss localization, run tagging, nl6-reconcile CLI, HTML report.' },
  { icon: 'devices', title: `${TYPE_COUNT} device types`, body: `Routers, switches, firewalls, servers, GPU servers (DGX/HGX), storage systems and optical transport, across ${CATEGORY_COUNT} categories.` },
  { icon: 'gpu', title: 'GPU simulation', body: 'NVIDIA DGX-A100 / H100 / HGX-H200 with per-GPU DCGM OIDs — utilization, VRAM, temp, power, fan, SM/memory clocks.' },
  { icon: 'isol', title: 'Namespace isolation', body: 'Each device runs in the dedicated nl6sim network namespace with its own TUN interface and IP.' },
  { icon: 'metric', title: 'Dynamic metrics', body: '100-point sine-wave cycling for CPU, memory, temperature; full IF-MIB counter set (octets, ucast / mcast / bcast packets, errors, discards) with per-device error scenarios; per-GPU DCGM OIDs.' },
];


// One entry per sidebar section: a few key pages plus the section's generated
// index page (sidebars.ts), so a new page is reachable without an edit here.
export const DOCS: DocGroup[] = [
  { group: 'Getting Started', body: 'Install from a package, Ansible or Docker, then start a fleet, resolve it with DNS and enable SNMP SET.', links: [
    { t: 'Quick start',      h: '/getting-started/quick-start' },
    { t: 'Install packages', h: '/getting-started/install-packages' },
    { t: 'Docker',           h: '/getting-started/docker' },
    { t: 'All Getting Started pages', h: '/getting-started' },
  ]},
  { group: 'Ops', body: 'Scale to 30k devices, tune the nl6sim namespace, troubleshoot, profile, and run exports and load tests.', links: [
    { t: 'Scaling',          h: '/ops/scaling' },
    { t: 'Troubleshooting',  h: '/ops/troubleshooting' },
    { t: 'Load-test scenarios', h: '/ops/loadtest-scenarios' },
    { t: 'All Ops pages',    h: '/ops' },
  ]},
  { group: 'Reference', body: 'CLI flags, REST API, device data, SNMP, gNMI, NETCONF, export wire formats, optical, discovery and GPU simulation.', links: [
    { t: 'CLI flags',        h: '/reference/cli-flags' },
    { t: 'Web API',          h: '/reference/web-api' },
    { t: 'Device types',     h: '/reference/device-types' },
    { t: 'GPU simulation',   h: '/reference/gpu' },
    { t: 'All Reference pages', h: '/reference' },
  ]},
  { group: 'Explanation', body: 'Why it is built this way: architecture, Kubernetes, SNMP data fidelity, collector ceilings.', links: [
    { t: 'Architecture',     h: '/explanation/architecture' },
    { t: 'All Explanation pages', h: '/explanation' },
  ]},
];

export const STATUS: StatusGroup[] = [
  { k: 'Stable',        items: ['SNMP v1/v2c/v3 + SET', 'SSH (VT100)', 'HTTPS REST (storage)', 'NetFlow v5/v9/IPFIX + NBAR2', 'gNMI (dial-in + dial-out)', 'NETCONF (Catalyst 9500, MX10004)', 'SNMP trap + syslog export', 'LLDP topology', 'DNS + Prometheus service discovery', 'Load-test scenarios', 'TUN + netns isolation', 'Web UI + REST API'] },
  { k: 'Experimental',  items: ['sFlow v5 (synthetic)'] },
  { k: 'Tested scale',  items: ['30,000 concurrent devices / host', '~50 MB base + ~1 KB / device', 'CPU: minimal in steady state'] },
];

export const TERMINAL_SCRIPT: TerminalLine[] = [
  { k: 'cmd', text: 'snmpwalk -v2c -c public 10.0.0.1 system' },
  { k: 'out', text: 'SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS XR Software, ASR9K Series, Version 7.5.2' },
  { k: 'out', text: 'SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.9.12.3.1.3.1736' },
  { k: 'out', text: 'DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (4567890123) 528 days, 16:55:01' },
  { k: 'out', text: 'SNMPv2-MIB::sysName.0 = STRING: ASR9K-Core-01' },
  { k: 'out', text: 'SNMPv2-MIB::sysLocation.0 = STRING: Stuttgart, Baden-Wuerttemberg, Europe' },
  { k: 'blank' },
  { k: 'cmd', text: 'snmpbulkwalk -v2c -c public 10.0.0.1 ifHCInOctets' },
  { k: 'out', text: 'IF-MIB::ifHCInOctets.1 = Counter64: 1012345678' },
  { k: 'out', text: 'IF-MIB::ifHCInOctets.2 = Counter64: 1024691356' },
  { k: 'out', text: 'IF-MIB::ifHCInOctets.3 = Counter64: 1037037034' },
  { k: 'blank' },
  { k: 'cmd', text: 'curl -s http://localhost:8080/api/v1/flows/status | jq -c \'.data | {devices_exporting, protocol: .collectors[0].protocol}\'' },
  { k: 'out', text: '{"devices_exporting":30000,"protocol":"ipfix"}' },
  { k: 'blank' },
  { k: 'ok',  text: '4 queries · <10ms latency each' },
];
