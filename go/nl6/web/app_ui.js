// nl6 Device Simulator - UI Functions

const elements = {
    createDevicesBtn: document.getElementById('createDevicesBtn'),
    createClosBtn: document.getElementById('createClosBtn'),
    deviceList: document.getElementById('deviceList'),
    alerts: document.getElementById('alerts'),
    exportBtn: document.getElementById('exportBtn'),
    routeScriptBtn: document.getElementById('routeScriptBtn'),
    refreshBtn: document.getElementById('refreshBtn'),
    pprofMemoryBtn: document.getElementById('pprofMemoryBtn'),
    cpuProfileBtn: document.getElementById('cpuProfileBtn'),
    deleteAllBtn: document.getElementById('deleteAllBtn'),
    totalDevices: document.getElementById('totalDevices'),
    runningDevices: document.getElementById('runningDevices'),
    stoppedDevices: document.getElementById('stoppedDevices'),
    tunInterfaces: document.getElementById('tunInterfaces'),
    paginationControls: document.getElementById('paginationControls'),
    pageInfo: document.getElementById('pageInfo'),
    prevPageBtn: document.getElementById('prevPageBtn'),
    nextPageBtn: document.getElementById('nextPageBtn'),
    filterControls: document.getElementById('filterControls'),
    deviceTable: document.getElementById('deviceTable'),
    filterDeviceId: document.getElementById('filterDeviceId'),
    filterIp: document.getElementById('filterIp'),
    filterInterface: document.getElementById('filterInterface'),
    filterDeviceType: document.getElementById('filterDeviceType'),
    filterPorts: document.getElementById('filterPorts'),
    filterStatus: document.getElementById('filterStatus'),
    filterExports: document.getElementById('filterExports'),
    clearFiltersBtn: document.getElementById('clearFiltersBtn'),
    // System stats elements
    simulatorMemory: document.getElementById('simulatorMemory'),
    systemMemory: document.getElementById('systemMemory'),
    memoryPercent: document.getElementById('memoryPercent'),
    cpuUsage: document.getElementById('cpuUsage'),
    cpuCores: document.getElementById('cpuCores'),
    loadAverage: document.getElementById('loadAverage')
};

function showAlert(message, type = 'success') {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-' + type;
    alertDiv.textContent = message;
    elements.alerts.appendChild(alertDiv);
    setTimeout(() => {
        if (alertDiv.parentNode) alertDiv.parentNode.removeChild(alertDiv);
    }, 5000);
}

function setLoading(elementId, loading) {
    const element = document.getElementById(elementId);
    if (element) element.style.display = loading ? 'inline-block' : 'none';
}

// Filter helper functions
// _filteredCache memoizes getFilteredDevices() so multiple callsites
// per render (renderDevices + getCurrentPageDevices + getTotalPages +
// updatePaginationControls) don't re-walk the array. Invalidated on
// any change to `devices` (reference identity) or any filter field.
// At 30k devices the filter loop is O(N) — running it 4× per render
// is the existing waste this layer removes.
let _filteredCacheDevices = null;
let _filteredCacheKey = '';
let _filteredCacheResult = null;

function getFilteredDevices() {
    const key = filters.id + '\x00' + filters.ip + '\x00' + filters.interface +
        '\x00' + filters.deviceType + '\x00' + filters.ports + '\x00' +
        filters.status + '\x00' + filters.exports;
    if (_filteredCacheDevices === devices && _filteredCacheKey === key) {
        return _filteredCacheResult;
    }
    const result = devices.filter(device => {
        const matchesId = !filters.id || device.id.toLowerCase().includes(filters.id.toLowerCase());
        const matchesIp = !filters.ip || device.ip.includes(filters.ip);
        const matchesInterface = !filters.interface || (device.interface && device.interface.toLowerCase().includes(filters.interface.toLowerCase()));
        const matchesDeviceType = !filters.deviceType || (device.device_type && device.device_type.toLowerCase().includes(filters.deviceType.toLowerCase()));
        const matchesPorts = !filters.ports ||
            (device.snmp_port.toString().includes(filters.ports) ||
             device.ssh_port.toString().includes(filters.ports));
        const matchesStatus = !filters.status ||
            (filters.status === 'running' && device.running) ||
            (filters.status === 'stopped' && !device.running);
        const hasAny = !!(device.flow || device.traps || device.syslog);
        const matchesExports = !filters.exports ||
            (filters.exports === 'any'    && hasAny) ||
            (filters.exports === 'none'   && !hasAny) ||
            (filters.exports === 'flow'   && !!device.flow) ||
            (filters.exports === 'trap'   && !!device.traps) ||
            (filters.exports === 'syslog' && !!device.syslog);

        return matchesId && matchesIp && matchesInterface && matchesDeviceType && matchesPorts && matchesStatus && matchesExports;
    });
    _filteredCacheDevices = devices;
    _filteredCacheKey = key;
    _filteredCacheResult = result;
    return result;
}

function updateFiltersFromInputs() {
    filters.id = elements.filterDeviceId.value;
    filters.ip = elements.filterIp.value;
    filters.interface = elements.filterInterface.value;
    filters.deviceType = elements.filterDeviceType.value;
    filters.ports = elements.filterPorts.value;
    filters.status = elements.filterStatus.value;
    filters.exports = elements.filterExports.value;
}

function clearAllFilters() {
    filters.id = '';
    filters.ip = '';
    filters.interface = '';
    filters.deviceType = '';
    filters.ports = '';
    filters.status = '';
    filters.exports = '';

    elements.filterDeviceId.value = '';
    elements.filterIp.value = '';
    elements.filterInterface.value = '';
    elements.filterDeviceType.value = '';
    elements.filterPorts.value = '';
    elements.filterStatus.value = '';
    elements.filterExports.value = '';

    currentPage = 1;
    renderDevices();
}

// statusOf returns the canonical status slug for a device: provisioning,
// deleting, running, or stopped (checked in that order). The transient
// flags `provisioning` and `deleting` are mirrored from the design's
// data shape but only `running` is currently set by the API — the slugs
// remain to keep the rendering uniform for when those flags land.
function statusOf(d) {
    if (d.provisioning) return 'provisioning';
    if (d.deleting) return 'deleting';
    return d.running ? 'running' : 'stopped';
}

function statusLabel(s) {
    return s === 'running' ? 'Running'
        : s === 'stopped' ? 'Stopped'
        : s === 'provisioning' ? 'Provisioning'
        : s === 'deleting' ? 'Deleting'
        : s;
}

function applyFilters() {
    updateFiltersFromInputs();
    currentPage = 1; // Reset to first page when filtering
    renderDevices();
}

// Pagination helper functions
function getTotalPages() {
    const filteredDevices = getFilteredDevices();
    return Math.ceil(filteredDevices.length / DEVICES_PER_PAGE);
}

function getCurrentPageDevices() {
    const filteredDevices = getFilteredDevices();
    const startIndex = (currentPage - 1) * DEVICES_PER_PAGE;
    const endIndex = startIndex + DEVICES_PER_PAGE;
    return filteredDevices.slice(startIndex, endIndex);
}

function updatePaginationControls() {
    const filteredDevices = getFilteredDevices();
    const totalPages = getTotalPages();
    const hasDevices = filteredDevices.length > 0;

    // Show/hide pagination controls
    elements.paginationControls.style.display = hasDevices ? 'flex' : 'none';

    if (hasDevices) {
        // Clamp currentPage when the set shrinks under us (deleteDevice,
        // deleteAllDevices, or any auto-refresh path that bypasses
        // applyFilters' reset-to-1). Without this clamp the operator
        // can land on "Page 5 of 2" with empty rows after a "Delete
        // all" issued from a deep page.
        if (currentPage > totalPages) {
            currentPage = totalPages;
        }

        // Update page info — new mono format: "Page N of M · X of Y devices [(filtered from Z)]"
        const showingCount = getCurrentPageDevices().length;
        const totalFiltered = filteredDevices.length;
        const totalDevices = devices.length;

        let pageInfoText = 'Page ' + currentPage + ' of ' + totalPages + ' · ' +
            showingCount + ' of ' + totalFiltered + ' devices';
        if (totalFiltered !== totalDevices) {
            pageInfoText += ' (filtered from ' + totalDevices + ')';
        }
        elements.pageInfo.textContent = pageInfoText;

        // Update button states
        elements.prevPageBtn.disabled = currentPage <= 1;
        elements.nextPageBtn.disabled = currentPage >= totalPages;
    }
}

function goToPage(page) {
    const totalPages = getTotalPages();
    if (page >= 1 && page <= totalPages) {
        currentPage = page;
        renderDevices();
        updatePaginationControls();
    }
}

function goToPreviousPage() {
    if (currentPage > 1) {
        goToPage(currentPage - 1);
    }
}

function goToNextPage() {
    const totalPages = getTotalPages();
    if (currentPage < totalPages) {
        goToPage(currentPage + 1);
    }
}

function renderDevices() {
    const filteredDevices = getFilteredDevices();
    const totalDevices = devices.length;

    // Empty-state — distinct copy when filters exclude everything vs. no devices at all.
    if (filteredDevices.length === 0) {
        const hasAnyDevices = totalDevices > 0;
        const title = hasAnyDevices ? 'No devices match' : 'No devices yet';
        const sub = hasAnyDevices
            ? 'Adjust or clear the filters above.'
            : 'Provision a device set to populate the simulator inventory.';
        const cta = hasAnyDevices
            ? ''
            : '<button class="btn btn-primary" data-action="open-provision" style="margin-top:10px">Create your first device set</button>';
        const icon = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>';
        elements.deviceTable.innerHTML =
            '<div class="empty-state">' +
                icon +
                '<div class="empty-title">' + title + '</div>' +
                '<div class="empty-sub">' + sub + '</div>' +
                cta +
            '</div>';
        // Click is handled by the delegated listener on
        // elements.deviceTable (see bottom of file).
        updatePaginationControls();
        return;
    }

    const rowsHTML = getCurrentPageDevices().map(device => {
        const status = statusOf(device);
        return '<tr class="frow' + (device.running ? '' : ' is-stopped') + '">' +
            '<td class="col-name mono"><span class="device-id">' + escapeHtml(device.id) + '</span></td>' +
            '<td class="col-ip mono">' + escapeHtml(device.ip) + '</td>' +
            '<td class="col-iface mono">' + escapeHtml(device.interface || 'N/A') + '</td>' +
            '<td class="col-type">' + escapeHtml(device.device_type || 'Unknown') + '</td>' +
            '<td class="col-ports">' +
                renderPortPill('SNMP', device.snmp_port, device.ip, device.running) +
                renderPortPill('SSH', device.ssh_port, device.ip, device.running) +
            '</td>' +
            '<td class="col-exports">' + renderExportBadges(device) + '</td>' +
            '<td class="col-status">' +
                '<span class="status-pill s-' + status + '">' + statusLabel(status) + '</span>' +
            '</td>' +
            '<td class="col-actions">' +
                '<div class="row-actions">' +
                    '<button class="row-action" data-action="test-ssh" data-ip="' + escapeHtml(device.ip) + '" data-port="' + device.ssh_port + '" title="SSH simadmin@' + escapeHtml(device.ip) + '">SSH</button>' +
                    '<button class="row-action" data-action="ping" data-ip="' + escapeHtml(device.ip) + '" title="Ping ' + escapeHtml(device.ip) + '">Ping</button>' +
                    '<button class="row-action row-action-danger" data-action="delete" data-device-id="' + escapeHtml(device.id) + '" title="Delete">Delete</button>' +
                '</div>' +
            '</td>' +
        '</tr>';
    }).join('');

    elements.deviceTable.innerHTML =
        '<table class="fleet-table">' +
            '<thead><tr>' +
                '<th>Device ID</th>' +
                '<th>IP address</th>' +
                '<th>Interface</th>' +
                '<th>Device type</th>' +
                '<th>Ports</th>' +
                '<th>Exports</th>' +
                '<th>Status</th>' +
                '<th></th>' +
            '</tr></thead>' +
            '<tbody>' + rowsHTML + '</tbody>' +
        '</table>';

    // Click is handled by the delegated listener on elements.deviceTable
    // (see bottom of file). Each render emits markup only.

    updatePaginationControls();
}

// renderPortPill returns an interactive button when the device is
// running (click copies ip:port to clipboard, brief .is-copied state)
// or an inert dim span when the device is stopped.
function renderPortPill(kind, port, ip, running) {
    const label = escapeHtml(kind + ' ' + port);
    if (!running) {
        const title = escapeHtml(kind + ' ' + port + ' — device is stopped');
        return '<span class="port-pill port-pill-off" aria-disabled="true" title="' + title + '">' + label + '</span>';
    }
    const title = escapeHtml('Copy ' + ip + ':' + port);
    return '<button type="button" class="port-pill port-pill-on" data-action="copy-port" data-ip="' + escapeHtml(ip) + '" data-port="' + port + '" title="' + title + '">' + label + '</button>';
}

// copyPortToClipboard writes `ip:port` to the system clipboard via the
// modern Clipboard API and flashes `.is-copied` on the pill for ~900ms
// — but ONLY on confirmed write success. On non-secure contexts (the
// dominant deployment target — plain HTTP on 10.x.x.x LAN) the API is
// undefined; in that case show a toast carrying the address so the
// operator can copy it manually. Without this guard the flash was
// firing regardless of write success and operators would paste stale
// clipboard content into terminals.
function copyPortToClipboard(btn, ip, port) {
    const addr = ip + ':' + port;
    const flash = () => {
        btn.classList.add('is-copied');
        setTimeout(() => btn.classList.remove('is-copied'), 900);
        // Screen readers get no signal from the colour-only `.is-copied`
        // flash — announce via the `#copyStatus` aria-live region. Setting
        // textContent twice (clear, then set) forces a re-announcement on
        // back-to-back copies of the same address.
        const status = document.getElementById('copyStatus');
        if (status) {
            status.textContent = '';
            setTimeout(() => { status.textContent = 'Copied ' + addr; }, 50);
        }
    };
    // Prefer the modern async Clipboard API when available (secure
    // context — HTTPS or localhost). Fall back to the deprecated
    // execCommand path on plain HTTP so copy still works on the
    // typical 10.42.0.0/16 LAN deployment.
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(addr).then(flash).catch(() => {
            if (!execCopyFallback(addr, flash)) {
                showAlert('Could not copy — address: ' + addr, 'warning');
            }
        });
        return;
    }
    if (!execCopyFallback(addr, flash)) {
        showAlert('Clipboard unavailable — address: ' + addr, 'warning');
    }
}

// execCopyFallback uses a hidden <textarea> + document.execCommand('copy')
// to put `text` on the system clipboard. Returns true on success, false
// otherwise. `onSuccess` is called when copy completes. The technique
// is deprecated but is the only path that works in non-secure contexts
// where navigator.clipboard is undefined.
function execCopyFallback(text, onSuccess) {
    const ta = document.createElement('textarea');
    ta.value = text;
    // Keep off-screen but selectable; readonly prevents the on-screen
    // keyboard on mobile.
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    document.body.appendChild(ta);
    const prevSelection = document.activeElement;
    ta.focus();
    ta.select();
    let ok = false;
    try {
        ok = document.execCommand('copy');
    } catch (_) {
        ok = false;
    }
    document.body.removeChild(ta);
    if (prevSelection && typeof prevSelection.focus === 'function') {
        prevSelection.focus();
    }
    if (ok) onSuccess();
    return ok;
}

// renderExportBadges returns three FLOW/TRAP/SYSLOG badges per row.
// A badge is `on` when the device's corresponding nested config block
// is non-null (data.go: DeviceInfo echoes them via omitempty), `off`
// otherwise. The `title` attribute carries the configured collector
// address for hover-detail when active, and "export disabled" when
// off (also exposed via aria-label for screen readers — color-only
// state communication fails WCAG 1.1.1 / 1.4.1).
function renderExportBadges(device) {
    return '<div class="export-badges" role="group" aria-label="Export configuration">' +
        renderExportBadge('FLOW', 'Flow', device.flow, b => (b.protocol || 'netflow9')) +
        renderExportBadge('TRAP', 'SNMP traps', device.traps, b => (b.mode || 'trap')) +
        renderExportBadge('SYSLOG', 'Syslog', device.syslog, b => (b.format || '5424')) +
        '</div>';
}

function renderExportBadge(label, kind, block, kindSuffix) {
    if (block && block.collector) {
        const desc = kind + ' export to ' + block.collector + ' (' + kindSuffix(block) + ')';
        return '<span class="export-badge on" role="img" aria-label="' + escapeHtml(desc) +
            '" title="' + escapeHtml(desc) + '">' + label + '</span>';
    }
    const desc = kind + ' export disabled';
    return '<span class="export-badge off" role="img" aria-label="' + escapeHtml(desc) +
        '" title="' + escapeHtml(desc) + '">' + label + '</span>';
}

function updateStats() {
    const total = devices.length;
    const running = devices.filter(d => d.running).length;
    const stopped = total - running;
    const interfaces = devices.filter(d => d.interface).length;
    elements.totalDevices.textContent = total;
    elements.runningDevices.textContent = running;
    elements.stoppedDevices.textContent = stopped;
    elements.tunInterfaces.textContent = interfaces;
}

function updateSystemStatsDisplay(stats) {
    // Simulator memory
    if (stats.simulator_memory_gb >= 1) {
        elements.simulatorMemory.textContent = stats.simulator_memory_gb.toFixed(2) + ' GB';
    } else {
        elements.simulatorMemory.textContent = stats.simulator_memory_mb.toFixed(1) + ' MB';
    }

    // System memory
    elements.systemMemory.textContent = stats.used_memory_gb.toFixed(1) + ' / ' + stats.total_memory_gb.toFixed(1) + ' GB';
    elements.memoryPercent.textContent = stats.memory_usage_percent.toFixed(1) + '% used';

    // CPU usage
    elements.cpuUsage.textContent = stats.cpu_usage_percent.toFixed(1) + '%';
    elements.cpuCores.textContent = stats.num_cpu + ' cores';

    // Load average
    elements.loadAverage.textContent = stats.load_avg_1.toFixed(2) + ' / ' + stats.load_avg_5.toFixed(2) + ' / ' + stats.load_avg_15.toFixed(2);
}

// === Provision modal (PR6) ============================================

const PROVISION_DRAFT_KEY = 'fleet.provision.draft';
const FABRIC_DRAFT_KEY = 'fleet.fabric.draft';

// Shared telemetry-export fields — identical across both wizards (steps 2–4).
const EMPTY_EXPORT_FIELDS = {
    flowCollector: '', flowProtocol: 'netflow9', flowActiveTimeout: '', flowInactiveTimeout: '',
    trapCollector: '', trapMode: 'trap', trapCommunity: 'public', trapInterval: '', trapInformTimeout: '', trapInformRetries: '',
    syslogCollector: '', syslogFormat: '5424', syslogInterval: ''
};

const EMPTY_DRAFT = Object.assign({
    startIp: '192.168.100.1', count: 5, netmask: '24',
    category: '', resourceFile: ''
}, EMPTY_EXPORT_FIELDS);

// Fabric draft: step 1 configures a k-ary fat-tree (k + base subnet); steps
// 2–4 reuse the shared export fields.
const EMPTY_FABRIC_DRAFT = Object.assign({
    k: 20, baseSubnet: '10.42.0.0/16'
}, EMPTY_EXPORT_FIELDS);

const PROVISION_STEPS = [
    { id: 'basics', label: 'Basics', optional: false },
    { id: 'traps', label: 'SNMP traps', optional: true },
    { id: 'syslog', label: 'Syslog', optional: true },
    { id: 'flow', label: 'Flow', optional: true }
];

// Fabric wizard: only step 1 differs from the device-set wizard.
const FABRIC_STEPS = [
    { id: 'fabric', label: 'Fabric', optional: false },
    { id: 'traps', label: 'SNMP traps', optional: true },
    { id: 'syslog', label: 'Syslog', optional: true },
    { id: 'flow', label: 'Flow', optional: true }
];

const STEP_FIELDS = {
    basics: ['startIp', 'count', 'netmask', 'category', 'resourceFile'],
    fabric: ['k', 'baseSubnet'],
    traps: ['trapCollector', 'trapMode', 'trapCommunity', 'trapInterval', 'trapInformTimeout', 'trapInformRetries'],
    syslog: ['syslogCollector', 'syslogFormat', 'syslogInterval'],
    flow: ['flowCollector', 'flowProtocol', 'flowActiveTimeout', 'flowInactiveTimeout']
};

const PROVISION_IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const PROVISION_HOSTPORT_RE = /^(\[[0-9a-fA-F:]+\]|[\w.-]+):\d{1,5}$/;
const FABRIC_SUBNET_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

// wizardKind selects which flow the modal is driving: 'devices' (the original
// device-set wizard) or 'fabric' (the Clos topology builder). It governs the
// step list, the active draft + its localStorage key, the title, step 1, and
// the submit path.
let wizardKind = 'devices';
let provisionDraft = Object.assign({}, EMPTY_DRAFT, loadDraftFor(PROVISION_DRAFT_KEY) || {});
let provisionStep = 0;
let provisionDirty = false;
let provisionBusy = false;

function provisionSteps() { return wizardKind === 'fabric' ? FABRIC_STEPS : PROVISION_STEPS; }
function emptyDraftForKind() { return wizardKind === 'fabric' ? EMPTY_FABRIC_DRAFT : EMPTY_DRAFT; }
function provisionDraftKey() { return wizardKind === 'fabric' ? FABRIC_DRAFT_KEY : PROVISION_DRAFT_KEY; }

function loadDraftFor(key) {
    try { return JSON.parse(localStorage.getItem(key) || 'null') || null; }
    catch (_) { return null; }
}
function loadProvisionDraft() { return loadDraftFor(provisionDraftKey()); }
function saveProvisionDraft() {
    try { localStorage.setItem(provisionDraftKey(), JSON.stringify(provisionDraft)); }
    catch (_) { /* quota / private-mode */ }
}
function clearProvisionDraft() {
    try { localStorage.removeItem(provisionDraftKey()); }
    catch (_) {}
}

// _provisionPriorFocus remembers the element that opened the modal so
// the close handler can restore keyboard focus to it (WAI-ARIA dialog
// pattern). Without this, Escape leaves focus on <body> and the user's
// tab position is lost.
let _provisionPriorFocus = null;

function openProvisionModal(kind) {
    if (provisionBusy) return;
    wizardKind = (kind === 'fabric') ? 'fabric' : 'devices';
    // Load the draft for the selected wizard (each kind has its own key) so the
    // two flows never clobber each other's saved values.
    provisionDraft = Object.assign({}, emptyDraftForKind(), loadProvisionDraft() || {});
    provisionStep = 0;
    provisionDirty = false;
    _provisionPriorFocus = (document.activeElement && document.activeElement !== document.body)
        ? document.activeElement : null;
    document.body.style.overflow = 'hidden';
    const scrim = document.getElementById('provisionModal');
    scrim.style.display = 'flex';
    scrim.setAttribute('aria-hidden', 'false');
    // Render inside try/finally so a thrown render error doesn't leak
    // the body scroll lock (the page would otherwise become permanently
    // unscrollable until refresh).
    try {
        renderProvisionModal();
        // Focus the first interactive control (Basics → Start IP input)
        // after layout settles so screen-reader / keyboard users land
        // inside the modal, not on the toolbar button that opened it.
        const firstInput = document.querySelector('#provisionBody [data-field]');
        if (firstInput) firstInput.focus();
    } catch (err) {
        document.body.style.overflow = '';
        scrim.style.display = 'none';
        scrim.setAttribute('aria-hidden', 'true');
        throw err;
    }
}

function closeProvisionModal(force) {
    if (!force && provisionDirty) {
        if (!confirm('Discard your provision draft?')) return;
    }
    document.body.style.overflow = '';
    const scrim = document.getElementById('provisionModal');
    scrim.style.display = 'none';
    scrim.setAttribute('aria-hidden', 'true');
    provisionDirty = false;
    if (_provisionPriorFocus && typeof _provisionPriorFocus.focus === 'function') {
        _provisionPriorFocus.focus();
    }
    _provisionPriorFocus = null;
}

function resetProvisionStep(stepId) {
    const fields = STEP_FIELDS[stepId] || [];
    const empty = emptyDraftForKind();
    fields.forEach(f => { provisionDraft[f] = empty[f]; });
    provisionDirty = true;
    saveProvisionDraft();
    renderProvisionModal();
}

function isProvisionStepValid(stepId) {
    if (stepId === 'basics') {
        // parseInt('1e3', 10) === 1 silently truncates scientific
        // notation that <input type="number"> accepts. Use Number()
        // for full parse and require a positive integer.
        const count = Number(provisionDraft.count);
        const validCount = Number.isFinite(count) && Number.isInteger(count) && count >= 1;
        return PROVISION_IP_RE.test(String(provisionDraft.startIp || '').trim()) && validCount;
    }
    if (stepId === 'fabric') {
        // Gate on exactly what the generator accepts so "valid" never disagrees
        // with submit. TopologyLogic is loaded by the time the modal opens; the
        // regex/inline checks are a defensive fallback only.
        const k = Number(provisionDraft.k);
        const L = window.TopologyLogic;
        const kOK = L ? !L.closKError(k) : (Number.isInteger(k) && k >= 2 && k <= 32 && k % 2 === 0);
        const subnetOK = L ? !L.closSubnetError(provisionDraft.baseSubnet)
            : FABRIC_SUBNET_RE.test(String(provisionDraft.baseSubnet || '').trim());
        return kOK && subnetOK;
    }
    const collectorField = stepId === 'traps' ? 'trapCollector'
                         : stepId === 'syslog' ? 'syslogCollector'
                         : stepId === 'flow' ? 'flowCollector' : null;
    if (!collectorField) return true;
    const v = provisionDraft[collectorField];
    return !v || PROVISION_HOSTPORT_RE.test(v.trim());
}

function isProvisionStepConfigured(stepId) {
    if (stepId === 'traps') return !!provisionDraft.trapCollector;
    if (stepId === 'syslog') return !!provisionDraft.syslogCollector;
    if (stepId === 'flow') return !!provisionDraft.flowCollector;
    return false;
}

function renderProvisionModal() {
    const steps = provisionSteps();
    const step = steps[provisionStep];
    document.getElementById('provisionModalTitle').textContent =
        wizardKind === 'fabric' ? 'Build a Clos fabric' : 'Provision a new device set';
    document.getElementById('provisionStepIndicator').textContent =
        'Create · Step ' + (provisionStep + 1) + ' of ' + steps.length;
    renderProvisionStepper();
    renderProvisionBody(step);
    renderProvisionFooter(step);
}

function renderProvisionStepper() {
    const steps = provisionSteps();
    const ol = document.getElementById('provisionStepper');
    const checkIcon = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-11"/></svg>';
    ol.innerHTML = steps.map((s, i) => {
        const isCurrent = i === provisionStep;
        const isDone = i < provisionStep;
        const cls = ['modal-step', isCurrent ? 'is-current' : '', isDone ? 'is-done' : ''].filter(Boolean).join(' ');
        const configured = isProvisionStepConfigured(s.id) && !isCurrent;
        const aria = isCurrent ? ' aria-current="step"' : '';
        return '<li class="' + cls + '">' +
            '<button type="button" class="modal-step-btn" data-action="modal-jump-step" data-step="' + i + '"' +
                (i > provisionStep ? ' disabled' : '') + aria + '>' +
                '<span class="modal-step-num">' + (isDone ? checkIcon : (i + 1)) + '</span>' +
                '<span class="modal-step-label">' + escapeHtml(s.label) +
                    (s.optional ? '<span class="modal-step-tag muted"> optional</span>' : '') +
                    (configured ? '<span class="modal-step-dot" title="Configured"></span>' : '') +
                '</span>' +
            '</button>' +
            (i < steps.length - 1 ? '<span class="modal-step-sep" aria-hidden="true"></span>' : '') +
        '</li>';
    }).join('');
}

function renderProvisionBody(step) {
    const body = document.getElementById('provisionBody');
    let html;
    if (step.id === 'basics') html = renderProvisionBasicsStep();
    else if (step.id === 'fabric') html = renderFabricStep();
    else if (step.id === 'traps') html = renderProvisionTrapsStep();
    else if (step.id === 'syslog') html = renderProvisionSyslogStep();
    else if (step.id === 'flow') html = renderProvisionFlowStep();
    body.innerHTML = html;
    wireProvisionFieldListeners(step.id);
}

// fabricPreviewHtml renders the live summary box for the current k. Pure
// formatting over TopologyLogic.closCounts / closKError — no side effects.
function fabricPreviewHtml() {
    const k = Number(provisionDraft.k);
    const L = window.TopologyLogic;
    const err = L ? L.closKError(k) : (Number.isInteger(k) ? null : 'k must be an integer');
    if (err) {
        return '<div class="fabric-preview is-invalid" data-fabric-preview>' +
            escapeHtml('Enter an even k between 2 and 32 — ' + err + '.') + '</div>';
    }
    const c = L.closCounts(k);
    return '<div class="fabric-preview" data-fabric-preview>' +
        '<div class="fabric-preview-row"><span class="fabric-preview-tiers mono">' +
            c.core + ' core <span class="muted">+</span> ' + c.agg + ' aggregation <span class="muted">+</span> ' +
            c.edge + ' edge <span class="muted">+</span> ' + c.host + ' hosts' +
        '</span></div>' +
        '<div class="fabric-preview-row mono"><strong>' + c.devices + '</strong> devices <span class="muted">·</span> <strong>' +
            c.links + '</strong> LLDP links</div>' +
    '</div>';
}

function renderFabricStep() {
    return '<div class="modal-form">' +
        '<p class="tab-summary">A folded 3-tier Clos (k-ary fat-tree): k pods of k/2 edge + k/2 aggregation switches, (k/2)² core switches, and k³/4 hosts, fully wired with LLDP links. Required to provision.</p>' +
        '<div class="form-group"><label>Fabric size k (even, 2–32)</label>' +
            '<input type="number" min="2" max="32" step="2" data-field="k" value="' + escapeHtml(provisionDraft.k) + '" required></div>' +
        '<div class="form-group"><label>Base subnet (/16)</label>' +
            '<input type="text" class="mono" data-field="baseSubnet" value="' + escapeHtml(provisionDraft.baseSubnet) + '" placeholder="10.42.0.0/16" required></div>' +
        '<div class="form-group form-group-wide"><label>Preview</label>' + fabricPreviewHtml() + '</div>' +
    '</div>';
}

// updateFabricPreview swaps just the preview box (and not the whole step body)
// so editing k/baseSubnet doesn't steal focus or reset the caret.
function updateFabricPreview() {
    const box = document.querySelector('#provisionBody [data-fabric-preview]');
    if (box) box.outerHTML = fabricPreviewHtml();
}

function renderProvisionBasicsStep() {
    const categoryOptions = '<option value="">All categories</option>' +
        resourceCategories().map(c =>
            '<option value="' + escapeHtml(c) + '"' + (provisionDraft.category === c ? ' selected' : '') + '>' + escapeHtml(c) + '</option>'
        ).join('');
    const filtered = resourcesForCategory(provisionDraft.category);
    const rrLabel = provisionDraft.category || ('all ' + filtered.length + ' types');
    const resourceOptions = '<option value="">Default (auto-detect)</option>' +
        '<option value="__round_robin__"' + (provisionDraft.resourceFile === '__round_robin__' ? ' selected' : '') + '>Round Robin (' + escapeHtml(rrLabel) + ')</option>' +
        filtered.map(r =>
            '<option value="' + escapeHtml(r.filename) + '"' + (provisionDraft.resourceFile === r.filename ? ' selected' : '') + '>' + escapeHtml(r.name + ' (' + r.type + ')') + '</option>'
        ).join('');
    return '<div class="modal-form">' +
        '<p class="tab-summary">Address range, profile strategy, and netmask. Required to provision.</p>' +
        '<div class="form-group"><label>Start IP address</label>' +
            '<input type="text" class="mono" data-field="startIp" value="' + escapeHtml(provisionDraft.startIp) + '" placeholder="192.168.100.1" required></div>' +
        '<div class="form-group"><label>Device count</label>' +
            '<input type="number" min="1" data-field="count" value="' + escapeHtml(provisionDraft.count) + '" required></div>' +
        '<div class="form-group"><label>Netmask</label>' +
            '<select data-field="netmask">' +
                ['24', '16', '8', '32'].map(n => '<option value="' + n + '"' + (provisionDraft.netmask === n ? ' selected' : '') + '>' + n + ' (/' + n + ')</option>').join('') +
            '</select></div>' +
        '<div class="form-group"><label>Category</label>' +
            '<select data-field="category">' + categoryOptions + '</select></div>' +
        '<div class="form-group form-group-wide"><label>Device type</label>' +
            '<select data-field="resourceFile">' + resourceOptions + '</select></div>' +
    '</div>';
}

function renderProvisionTrapsStep() {
    const hintHidden = provisionDraft.trapCollector ? ' style="display:none"' : '';
    const skipHint = '<div class="step-skip-hint" data-skip-hint role="note"' + hintHidden + '>No collector — this step will be skipped.</div>';
    return '<div class="modal-form">' +
        '<p class="tab-summary">Devices fire SNMPv2c traps or INFORM requests at a Poisson cadence. Leave the collector blank to skip traps for this batch.</p>' +
        skipHint +
        '<div class="form-group form-group-wide"><label>Collector (host:port)</label>' +
            '<input type="text" class="mono" data-field="trapCollector" value="' + escapeHtml(provisionDraft.trapCollector) + '" placeholder="192.168.1.10:162"></div>' +
        '<div class="form-group"><label>Mode</label>' +
            '<select data-field="trapMode">' +
                ['trap', 'inform'].map(m => '<option value="' + m + '"' + (provisionDraft.trapMode === m ? ' selected' : '') + '>' + (m === 'trap' ? 'TRAP (fire-and-forget)' : 'INFORM (acknowledged)') + '</option>').join('') +
            '</select></div>' +
        '<div class="form-group"><label>Community</label>' +
            '<input type="text" class="mono" data-field="trapCommunity" value="' + escapeHtml(provisionDraft.trapCommunity) + '" placeholder="public"></div>' +
        '<div class="form-group"><label>Interval (Poisson mean)</label>' +
            '<input type="text" class="mono" data-field="trapInterval" value="' + escapeHtml(provisionDraft.trapInterval) + '" placeholder="30s"></div>' +
        '<div class="form-group"><label>INFORM retry timeout</label>' +
            '<input type="text" class="mono" data-field="trapInformTimeout" value="' + escapeHtml(provisionDraft.trapInformTimeout) + '" placeholder="5s"></div>' +
        '<div class="form-group"><label>INFORM max retries</label>' +
            '<input type="number" min="0" data-field="trapInformRetries" value="' + escapeHtml(provisionDraft.trapInformRetries) + '" placeholder="2"></div>' +
    '</div>';
}

function renderProvisionSyslogStep() {
    const hintHidden = provisionDraft.syslogCollector ? ' style="display:none"' : '';
    const skipHint = '<div class="step-skip-hint" data-skip-hint role="note"' + hintHidden + '>No collector — this step will be skipped.</div>';
    return '<div class="modal-form">' +
        '<p class="tab-summary">Devices emit syslog messages at a Poisson cadence. Leave the collector blank to skip syslog for this batch.</p>' +
        skipHint +
        '<div class="form-group form-group-wide"><label>Collector (host:port)</label>' +
            '<input type="text" class="mono" data-field="syslogCollector" value="' + escapeHtml(provisionDraft.syslogCollector) + '" placeholder="192.168.1.10:514"></div>' +
        '<div class="form-group"><label>Format</label>' +
            '<select data-field="syslogFormat">' +
                ['5424', '3164'].map(f => '<option value="' + f + '"' + (provisionDraft.syslogFormat === f ? ' selected' : '') + '>' + (f === '5424' ? 'RFC 5424 (structured)' : 'RFC 3164 (legacy BSD)') + '</option>').join('') +
            '</select></div>' +
        '<div class="form-group"><label>Interval (Poisson mean)</label>' +
            '<input type="text" class="mono" data-field="syslogInterval" value="' + escapeHtml(provisionDraft.syslogInterval) + '" placeholder="10s"></div>' +
    '</div>';
}

function renderProvisionFlowStep() {
    const hintHidden = provisionDraft.flowCollector ? ' style="display:none"' : '';
    const skipHint = '<div class="step-skip-hint" data-skip-hint role="note"' + hintHidden + '>No collector — this step will be skipped.</div>';
    return '<div class="modal-form">' +
        '<p class="tab-summary">Devices emit synthetic flow telemetry. Leave the collector blank to skip flow export for this batch.</p>' +
        skipHint +
        '<div class="form-group form-group-wide"><label>Collector (host:port)</label>' +
            '<input type="text" class="mono" data-field="flowCollector" value="' + escapeHtml(provisionDraft.flowCollector) + '" placeholder="192.168.1.10:2055"></div>' +
        '<div class="form-group"><label>Protocol</label>' +
            '<select data-field="flowProtocol">' +
                [['netflow9', 'NetFlow v9 (default)'], ['ipfix', 'IPFIX'], ['netflow5', 'NetFlow v5'], ['sflow', 'sFlow v5']]
                    .map(p => '<option value="' + p[0] + '"' + (provisionDraft.flowProtocol === p[0] ? ' selected' : '') + '>' + p[1] + '</option>').join('') +
            '</select></div>' +
        '<div class="form-group"><label>Active timeout</label>' +
            '<input type="text" class="mono" data-field="flowActiveTimeout" value="' + escapeHtml(provisionDraft.flowActiveTimeout) + '" placeholder="30s"></div>' +
        '<div class="form-group"><label>Inactive timeout</label>' +
            '<input type="text" class="mono" data-field="flowInactiveTimeout" value="' + escapeHtml(provisionDraft.flowInactiveTimeout) + '" placeholder="15s"></div>' +
    '</div>';
}

// fabricDeviceCount returns the total device count for the current k, or 0
// when k is invalid / TopologyLogic isn't loaded yet.
function fabricDeviceCount() {
    const k = Number(provisionDraft.k);
    const c = (window.TopologyLogic && window.TopologyLogic.closCounts) ? window.TopologyLogic.closCounts(k) : null;
    return c ? c.devices : 0;
}

// setProvisionProgress overwrites the footer hint with a live fan-out progress
// line; an empty message restores the default "Draft saved automatically." text.
function setProvisionProgress(msg) {
    const el = document.querySelector('#provisionModal .modal-foot-hint');
    if (el) el.textContent = msg || 'Draft saved automatically.';
}

function renderProvisionFooter(step) {
    const steps = provisionSteps();
    const isLast = provisionStep === steps.length - 1;
    const isFirst = provisionStep === 0;
    const valid = isProvisionStepValid(step.id);
    document.getElementById('modalBackBtn').disabled = isFirst;
    const nextBtn = document.getElementById('modalNextBtn');
    if (isLast) {
        const count = wizardKind === 'fabric' ? fabricDeviceCount() : (Number(provisionDraft.count) || 0);
        nextBtn.innerHTML = 'Create ' + count + ' device' + (count === 1 ? '' : 's');
        nextBtn.disabled = !valid || provisionBusy;
        nextBtn.setAttribute('data-action', 'modal-submit');
        nextBtn.title = valid ? '' : 'Fill required fields to continue';
    } else {
        nextBtn.textContent = 'Next';
        nextBtn.disabled = !valid;
        nextBtn.setAttribute('data-action', 'modal-next');
        nextBtn.title = valid ? '' : 'Fill required fields to continue';
    }
}

function wireProvisionFieldListeners(stepId) {
    const body = document.getElementById('provisionBody');
    body.querySelectorAll('[data-field]').forEach(el => {
        el.addEventListener('input', onProvisionFieldChange);
        el.addEventListener('change', onProvisionFieldChange);
    });
}

function onProvisionFieldChange(e) {
    const el = e.target;
    const key = el.getAttribute('data-field');
    if (!key) return;
    provisionDraft[key] = el.value;
    provisionDirty = true;
    saveProvisionDraft();
    // Re-render footer (validity changes) and, for category, the
    // resourceFile select; for resourceFile (round-robin label).
    // Stepper also re-renders so the "configured" dot updates.
    renderProvisionStepper();
    renderProvisionFooter(provisionSteps()[provisionStep]);
    // When a telemetry collector field changes, the "this step will be
    // skipped" hint visibility flips. Toggle directly on the DOM
    // (preserves focus / caret in the input the user is editing).
    if (key === 'trapCollector' || key === 'syslogCollector' || key === 'flowCollector') {
        const hint = document.querySelector('#provisionBody [data-skip-hint]');
        if (hint) hint.style.display = el.value ? 'none' : '';
    }
    // Fabric step: k / base subnet drives the live preview. Update just the
    // preview box (not the whole body) to keep focus in the field.
    if (key === 'k' || key === 'baseSubnet') {
        updateFabricPreview();
    }
    if (key === 'category') {
        // Category change must repopulate the resourceFile select with
        // the filtered set. Easiest is to re-render the basics body.
        renderProvisionBody(provisionSteps()[provisionStep]);
    }
}

// buildExportSnapshot reads the shared telemetry-export fields off the current
// draft into the per-device export block shape the API expects, dropping
// undefined keys so omitempty fires server-side. Shared by both wizards.
function buildExportSnapshot() {
    const snapshot = {
        flow: provisionDraft.flowCollector ? {
            collector: provisionDraft.flowCollector.trim(),
            protocol: provisionDraft.flowProtocol,
            active_timeout: provisionDraft.flowActiveTimeout || undefined,
            inactive_timeout: provisionDraft.flowInactiveTimeout || undefined
        } : null,
        traps: provisionDraft.trapCollector ? (function () {
            const b = {
                collector: provisionDraft.trapCollector.trim(),
                mode: provisionDraft.trapMode,
                community: provisionDraft.trapCommunity || undefined,
                interval: provisionDraft.trapInterval || undefined,
                inform_timeout: provisionDraft.trapInformTimeout || undefined
            };
            if (provisionDraft.trapInformRetries !== '' && provisionDraft.trapInformRetries != null) {
                b.inform_retries = parseInt(provisionDraft.trapInformRetries, 10);
            }
            return b;
        })() : null,
        syslog: provisionDraft.syslogCollector ? {
            collector: provisionDraft.syslogCollector.trim(),
            format: provisionDraft.syslogFormat,
            interval: provisionDraft.syslogInterval || undefined
        } : null
    };
    for (const k of ['flow', 'traps', 'syslog']) {
        if (snapshot[k]) {
            for (const f of Object.keys(snapshot[k])) {
                if (snapshot[k][f] === undefined) delete snapshot[k][f];
            }
        }
    }
    return snapshot;
}

async function submitProvision() {
    if (provisionBusy) return;
    // Build the export snapshot from the draft, then run the strict
    // validator that the inline form's submit used. Cheap insurance:
    // catches duration / inform_retries shape issues the per-step
    // host:port regex doesn't cover.
    const snapshot = buildExportSnapshot();
    const err = validateExportBlocksSnapshot(snapshot);
    if (err) {
        showAlert(err, 'error');
        return;
    }
    provisionBusy = true;
    renderProvisionFooter(provisionSteps()[provisionStep]);
    try {
        await createDevices(
            provisionDraft.startIp,
            Number(provisionDraft.count),
            provisionDraft.netmask,
            provisionDraft.resourceFile,
            provisionDraft.category,
            snapshot
        );
        clearProvisionDraft();
        provisionDraft = Object.assign({}, EMPTY_DRAFT);
        provisionDirty = false;
        closeProvisionModal(true);
    } catch (_) {
        // createDevices already pushed a toast; keep the modal open so
        // the operator can correct and retry.
    } finally {
        provisionBusy = false;
        renderProvisionFooter(provisionSteps()[provisionStep]);
    }
}

// submitFabric builds the k-ary fat-tree client-side and fans it out: per-tier
// device creation then a chunked topology load (see createClosFabric). On any
// failed request the modal stays open with a toast naming the failed stage.
async function submitFabric() {
    if (provisionBusy) return;
    if (!window.TopologyLogic) {
        showAlert('Topology module not loaded — reload the page and try again.', 'error');
        return;
    }
    const snapshot = buildExportSnapshot();
    const verr = validateExportBlocksSnapshot(snapshot);
    if (verr) { showAlert(verr, 'error'); return; }

    let fabric;
    try {
        fabric = window.TopologyLogic.buildClosFabric(Number(provisionDraft.k), provisionDraft.baseSubnet);
    } catch (e) {
        showAlert('Invalid fabric: ' + e.message, 'error');
        return;
    }

    provisionBusy = true;
    renderProvisionFooter(provisionSteps()[provisionStep]);
    let lastStage = '';
    try {
        const result = await createClosFabric(fabric, snapshot, (msg) => { lastStage = msg; setProvisionProgress(msg); });
        // Reconcile what the server actually created against the intended fabric:
        // a shortfall means some devices failed to start, so the links to them
        // will show as "unresolved" in the topology. Surface it rather than
        // claiming the full count.
        const failed = result.requested - result.created;
        if (failed > 0) {
            showAlert('Clos fabric created with issues: ' + result.created + ' of ' + result.requested +
                ' devices started (' + failed + ' failed). ' + fabric.links.length +
                ' links posted — links to the ' + failed + ' missing device(s) will show as unresolved.', 'error');
        } else {
            showAlert('Clos fabric created: ' + result.created + ' devices, ' + fabric.links.length + ' links.', 'success');
        }
        startStatusPolling();
        await loadDevices();
        clearProvisionDraft();
        provisionDraft = Object.assign({}, EMPTY_FABRIC_DRAFT);
        provisionDirty = false;
        closeProvisionModal(true);
    } catch (e) {
        // Keep the modal open so the operator can retry; name the stage that
        // failed (the progress callback recorded the last one in flight).
        showAlert('Failed during "' + (lastStage || 'fan-out') + '": ' + e.message, 'error');
    } finally {
        provisionBusy = false;
        setProvisionProgress('');
        renderProvisionFooter(provisionSteps()[provisionStep]);
    }
}

// Track whether a press started on the scrim itself. A `click` fires on the
// nearest common ancestor of its mousedown/mouseup targets, so selecting a
// field value by dragging past the input bounds (mousedown in the input,
// mouseup on the backdrop) produces a click whose target is the scrim — which
// would otherwise read as a backdrop click and (with a dirty draft) pop the
// "Discard your provision draft?" confirm. Only treat it as a backdrop click
// when the press also began on the backdrop.
let _scrimPressOnBackdrop = false;
document.getElementById('provisionModal').addEventListener('mousedown', (e) => {
    _scrimPressOnBackdrop = (e.target.id === 'provisionModal');
});

// Event delegation for all modal interactions.
document.getElementById('provisionModal').addEventListener('click', (e) => {
    // Consume the press-origin flag on every click so its lifetime is exactly
    // one press→click pair: a backdrop press that releases *inside* the modal
    // can't leave it set for a later click to misread.
    const pressedBackdrop = _scrimPressOnBackdrop;
    _scrimPressOnBackdrop = false;
    if (e.target.id === 'provisionModal') {
        // Backdrop click — only when the press began on the backdrop, so a
        // text-selection drag that merely ends here doesn't close the modal.
        if (pressedBackdrop) closeProvisionModal();
        return;
    }
    const trigger = e.target.closest('[data-action]');
    if (!trigger) return;
    const action = trigger.getAttribute('data-action');
    switch (action) {
        case 'modal-close':
        case 'modal-cancel':
            closeProvisionModal();
            break;
        case 'modal-reset':
            resetProvisionStep(provisionSteps()[provisionStep].id);
            break;
        case 'modal-back':
            if (provisionStep > 0) { provisionStep--; renderProvisionModal(); }
            break;
        case 'modal-next':
            if (provisionStep < provisionSteps().length - 1) { provisionStep++; renderProvisionModal(); }
            break;
        case 'modal-submit':
            if (wizardKind === 'fabric') submitFabric(); else submitProvision();
            break;
        case 'modal-jump-step': {
            const idx = parseInt(trigger.getAttribute('data-step'), 10);
            // Strict `<` so clicking the current step is a no-op (no
            // re-render that would blow away mid-edit focus).
            if (!isNaN(idx) && idx < provisionStep) { provisionStep = idx; renderProvisionModal(); }
            break;
        }
    }
});

// Keyboard handler for the modal: Escape closes (with dirty confirm),
// Tab cycles focus inside the dialog so it can't escape to the
// disabled toolbar buttons behind the scrim (WAI-ARIA dialog pattern).
window.addEventListener('keydown', (e) => {
    const scrim = document.getElementById('provisionModal');
    if (!scrim || scrim.style.display === 'none') return;

    if (e.key === 'Escape') {
        // If a child element handled the Escape (e.g., the browser
        // closed an open <select> popup), don't also close the modal.
        if (e.defaultPrevented) return;
        closeProvisionModal();
        return;
    }

    if (e.key === 'Tab') {
        const focusables = scrim.querySelectorAll(
            'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
            last.focus();
            e.preventDefault();
        } else if (!e.shiftKey && document.activeElement === last) {
            first.focus();
            e.preventDefault();
        }
    }
});

// Toolbar [+ Create devices] / [+ Create Clos topology] buttons open the modal
// in the matching wizard mode.
elements.createDevicesBtn.addEventListener('click', () => openProvisionModal('devices'));
if (elements.createClosBtn) elements.createClosBtn.addEventListener('click', () => openProvisionModal('fabric'));

elements.exportBtn.addEventListener('click', exportDevicesCSV);
elements.routeScriptBtn.addEventListener('click', downloadRouteScript);
elements.refreshBtn.addEventListener('click', loadDevices);
elements.pprofMemoryBtn.addEventListener('click', downloadPprofMemory);
elements.cpuProfileBtn.addEventListener('click', downloadCpuProfile);
elements.deleteAllBtn.addEventListener('click', deleteAllDevices);

// Pagination event listeners
elements.prevPageBtn.addEventListener('click', goToPreviousPage);
elements.nextPageBtn.addEventListener('click', goToNextPage);

// Filter event listeners (attached once during initialization)
elements.filterDeviceId.addEventListener('input', applyFilters);
elements.filterIp.addEventListener('input', applyFilters);
elements.filterInterface.addEventListener('input', applyFilters);
elements.filterDeviceType.addEventListener('input', applyFilters);
elements.filterPorts.addEventListener('input', applyFilters);
elements.filterStatus.addEventListener('change', applyFilters);
elements.filterExports.addEventListener('change', applyFilters);
elements.clearFiltersBtn.addEventListener('click', clearAllFilters);

// Delegated click handler for every action-emitting element inside the
// device-table region (per-row SSH / Ping / Delete buttons, port-pill
// copy buttons, empty-state CTA). Attached ONCE at module init —
// previously renderDevices re-attached a fresh listener to every
// matching child on every render, which at fleet scale meant
// re-allocating ~N×4 closures per 30s poll. Single listener walks the
// `closest('[data-action]')` chain on each click.
elements.deviceTable.addEventListener('click', (e) => {
    const t = e.target.closest('[data-action]');
    if (!t) return;
    const action = t.getAttribute('data-action');
    const ip = t.getAttribute('data-ip');
    const port = t.getAttribute('data-port');
    const deviceId = t.getAttribute('data-device-id');
    switch (action) {
        case 'test-ssh':
            testConnection(ip, parseInt(port));
            break;
        case 'ping':
            pingDevice(ip);
            break;
        case 'delete':
            deleteDevice(deviceId);
            break;
        case 'copy-port':
            copyPortToClipboard(t, ip, port);
            break;
        case 'open-provision':
            openProvisionModal();
            break;
    }
});

// Each periodic poller is wrapped so it no-ops when the tab is hidden
// (background tabs don't need fresh device lists / system stats /
// telemetry aggregates). The first refresh on visibility-restore is
// triggered by the visibilitychange handler below.
function whenVisible(fn) {
    return () => {
        if (!document.hidden) fn();
    };
}

setInterval(whenVisible(loadDevices), 30000);
setInterval(whenVisible(loadSystemStats), 5000); // Refresh system stats every 5 seconds
setInterval(whenVisible(loadExportStatuses), 10000); // Per-subsystem aggregate poll (phase 6)

document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        // Catch up immediately on focus; the next interval tick will
        // resume normal cadence.
        loadDevices();
        loadSystemStats();
        loadExportStatuses();
    }
});

document.addEventListener('DOMContentLoaded', () => {
    loadDevices();
    loadResources();
    loadSystemStats(); // Initial system stats load
    loadExportStatuses(); // Initial export-status load (phase 6)
    checkStatus(); // Initial status check
    loadVersion(); // One-shot: version is immutable per process
});
