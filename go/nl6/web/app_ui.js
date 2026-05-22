// nl6 Device Simulator - UI Functions

const elements = {
    createDevicesBtn: document.getElementById('createDevicesBtn'),
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
function getFilteredDevices() {
    return devices.filter(device => {
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
            : '<button class="btn btn-primary" data-action="open-provision" style="margin-top:10px">+ Create your first device set</button>';
        const icon = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>';
        elements.deviceTable.innerHTML =
            '<div class="empty-state">' +
                icon +
                '<div class="empty-title">' + title + '</div>' +
                '<div class="empty-sub">' + sub + '</div>' +
                cta +
            '</div>';
        // CTA opens the provision modal.
        const ctaBtn = elements.deviceTable.querySelector('[data-action="open-provision"]');
        if (ctaBtn) ctaBtn.addEventListener('click', openProvisionModal);
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

    // Wire row-action + port-pill click handlers.
    elements.deviceTable.querySelectorAll('[data-action]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const t = e.currentTarget;
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
            }
        });
    });

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
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(addr).then(flash).catch(() => {
            showAlert('Could not access clipboard — address: ' + addr, 'warning');
        });
        return;
    }
    showAlert('Clipboard unavailable on this connection — address: ' + addr, 'warning');
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

const EMPTY_DRAFT = {
    startIp: '192.168.100.1', count: 5, netmask: '24',
    category: '', resourceFile: '',
    flowCollector: '', flowProtocol: 'netflow9', flowActiveTimeout: '', flowInactiveTimeout: '',
    trapCollector: '', trapMode: 'trap', trapCommunity: 'public', trapInterval: '', trapInformTimeout: '', trapInformRetries: '',
    syslogCollector: '', syslogFormat: '5424', syslogInterval: ''
};

const PROVISION_STEPS = [
    { id: 'basics', label: 'Basics', optional: false },
    { id: 'traps', label: 'SNMP traps', optional: true },
    { id: 'syslog', label: 'Syslog', optional: true },
    { id: 'flow', label: 'Flow', optional: true }
];

const STEP_FIELDS = {
    basics: ['startIp', 'count', 'netmask', 'category', 'resourceFile'],
    traps: ['trapCollector', 'trapMode', 'trapCommunity', 'trapInterval', 'trapInformTimeout', 'trapInformRetries'],
    syslog: ['syslogCollector', 'syslogFormat', 'syslogInterval'],
    flow: ['flowCollector', 'flowProtocol', 'flowActiveTimeout', 'flowInactiveTimeout']
};

const PROVISION_IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const PROVISION_HOSTPORT_RE = /^(\[[0-9a-fA-F:]+\]|[\w.-]+):\d{1,5}$/;

let provisionDraft = Object.assign({}, EMPTY_DRAFT, loadProvisionDraft() || {});
let provisionStep = 0;
let provisionDirty = false;
let provisionBusy = false;

function loadProvisionDraft() {
    try { return JSON.parse(localStorage.getItem(PROVISION_DRAFT_KEY) || 'null') || null; }
    catch (_) { return null; }
}
function saveProvisionDraft() {
    try { localStorage.setItem(PROVISION_DRAFT_KEY, JSON.stringify(provisionDraft)); }
    catch (_) { /* quota / private-mode */ }
}
function clearProvisionDraft() {
    try { localStorage.removeItem(PROVISION_DRAFT_KEY); }
    catch (_) {}
}

function openProvisionModal() {
    if (provisionBusy) return;
    provisionStep = 0;
    provisionDirty = false;
    document.body.style.overflow = 'hidden';
    const scrim = document.getElementById('provisionModal');
    scrim.style.display = 'flex';
    scrim.setAttribute('aria-hidden', 'false');
    renderProvisionModal();
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
}

function resetProvisionStep(stepId) {
    const fields = STEP_FIELDS[stepId] || [];
    fields.forEach(f => { provisionDraft[f] = EMPTY_DRAFT[f]; });
    provisionDirty = true;
    saveProvisionDraft();
    renderProvisionModal();
}

function isProvisionStepValid(stepId) {
    if (stepId === 'basics') {
        return PROVISION_IP_RE.test(String(provisionDraft.startIp || '').trim()) &&
            parseInt(provisionDraft.count, 10) >= 1;
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
    const step = PROVISION_STEPS[provisionStep];
    document.getElementById('provisionStepIndicator').textContent =
        'Create · Step ' + (provisionStep + 1) + ' of ' + PROVISION_STEPS.length;
    renderProvisionStepper();
    renderProvisionBody(step);
    renderProvisionFooter(step);
}

function renderProvisionStepper() {
    const ol = document.getElementById('provisionStepper');
    const checkIcon = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-11"/></svg>';
    ol.innerHTML = PROVISION_STEPS.map((s, i) => {
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
            (i < PROVISION_STEPS.length - 1 ? '<span class="modal-step-sep" aria-hidden="true"></span>' : '') +
        '</li>';
    }).join('');
}

function renderProvisionBody(step) {
    const body = document.getElementById('provisionBody');
    let html;
    if (step.id === 'basics') html = renderProvisionBasicsStep();
    else if (step.id === 'traps') html = renderProvisionTrapsStep();
    else if (step.id === 'syslog') html = renderProvisionSyslogStep();
    else if (step.id === 'flow') html = renderProvisionFlowStep();
    body.innerHTML = html;
    wireProvisionFieldListeners(step.id);
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
    const skipHint = !provisionDraft.trapCollector
        ? '<div class="step-skip-hint" role="note">No collector — this step will be skipped.</div>' : '';
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
    const skipHint = !provisionDraft.syslogCollector
        ? '<div class="step-skip-hint" role="note">No collector — this step will be skipped.</div>' : '';
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
    const skipHint = !provisionDraft.flowCollector
        ? '<div class="step-skip-hint" role="note">No collector — this step will be skipped.</div>' : '';
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

function renderProvisionFooter(step) {
    const isLast = provisionStep === PROVISION_STEPS.length - 1;
    const isFirst = provisionStep === 0;
    const valid = isProvisionStepValid(step.id);
    document.getElementById('modalBackBtn').disabled = isFirst;
    const nextBtn = document.getElementById('modalNextBtn');
    if (isLast) {
        const count = parseInt(provisionDraft.count, 10) || 0;
        nextBtn.innerHTML = '+ Create ' + count + ' device' + (count === 1 ? '' : 's');
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
    renderProvisionFooter(PROVISION_STEPS[provisionStep]);
    if (key === 'category') {
        // Category change must repopulate the resourceFile select with
        // the filtered set. Easiest is to re-render the basics body.
        renderProvisionBody(PROVISION_STEPS[provisionStep]);
    }
}

async function submitProvision() {
    if (provisionBusy) return;
    // Build the export snapshot from the draft, then run the strict
    // validator that the inline form's submit used. Cheap insurance:
    // catches duration / inform_retries shape issues the per-step
    // host:port regex doesn't cover.
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
    // Strip undefined keys so omitempty fires server-side.
    for (const k of ['flow', 'traps', 'syslog']) {
        if (snapshot[k]) {
            for (const f of Object.keys(snapshot[k])) {
                if (snapshot[k][f] === undefined) delete snapshot[k][f];
            }
        }
    }
    const err = validateExportBlocksSnapshot(snapshot);
    if (err) {
        showAlert(err, 'error');
        return;
    }
    provisionBusy = true;
    renderProvisionFooter(PROVISION_STEPS[provisionStep]);
    try {
        await createDevices(
            provisionDraft.startIp,
            provisionDraft.count,
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
        renderProvisionFooter(PROVISION_STEPS[provisionStep]);
    }
}

// Event delegation for all modal interactions.
document.getElementById('provisionModal').addEventListener('click', (e) => {
    if (e.target.id === 'provisionModal') {
        // Scrim click
        closeProvisionModal();
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
            resetProvisionStep(PROVISION_STEPS[provisionStep].id);
            break;
        case 'modal-back':
            if (provisionStep > 0) { provisionStep--; renderProvisionModal(); }
            break;
        case 'modal-next':
            if (provisionStep < PROVISION_STEPS.length - 1) { provisionStep++; renderProvisionModal(); }
            break;
        case 'modal-submit':
            submitProvision();
            break;
        case 'modal-jump-step': {
            const idx = parseInt(trigger.getAttribute('data-step'), 10);
            if (!isNaN(idx) && idx <= provisionStep) { provisionStep = idx; renderProvisionModal(); }
            break;
        }
    }
});

// Escape closes the modal (with dirty confirm).
window.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const scrim = document.getElementById('provisionModal');
    if (scrim && scrim.style.display !== 'none') closeProvisionModal();
});

// Toolbar [+ Create devices] button opens the modal.
elements.createDevicesBtn.addEventListener('click', openProvisionModal);

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
