// nl6 Device Simulator - UI Functions

const elements = {
    createForm: document.getElementById('createForm'),
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
            : '<button class="btn btn-primary" data-action="scroll-to-create" style="margin-top:10px">Create your first device set</button>';
        const icon = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>';
        elements.deviceTable.innerHTML =
            '<div class="empty-state">' +
                icon +
                '<div class="empty-title">' + title + '</div>' +
                '<div class="empty-sub">' + sub + '</div>' +
                cta +
            '</div>';
        // CTA scrolls to the still-existing inline #create section until PR6 lands the modal.
        const ctaBtn = elements.deviceTable.querySelector('[data-action="scroll-to-create"]');
        if (ctaBtn) {
            ctaBtn.addEventListener('click', () => {
                const target = document.getElementById('create');
                if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        }
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
// modern Clipboard API and flashes `.is-copied` on the pill for ~900ms.
// Falls back silently if clipboard access is unavailable (non-secure
// context); the flash still runs so the user sees feedback.
function copyPortToClipboard(btn, ip, port) {
    const addr = ip + ':' + port;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(addr).catch(() => {});
        }
    } catch (_) {
        // no-op — pre-secure-context browsers
    }
    btn.classList.add('is-copied');
    setTimeout(() => btn.classList.remove('is-copied'), 900);
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

// Event listeners
elements.createForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = elements.createForm.querySelector('button[type="submit"]');
    const startIp = document.getElementById('startIp').value;
    const deviceCount = document.getElementById('deviceCount').value;
    const netmask = document.getElementById('netmask').value;
    const resourceFile = document.getElementById('resourceFile').value;
    if (!startIp || !deviceCount) {
        showAlert('Please fill in all required fields', 'error');
        return;
    }
    // Snapshot the three per-device export blocks ONCE so the
    // validator and the request body see identical input. Without this,
    // an operator typing into a field between validate and POST could
    // slip unvalidated data past the client check.
    const exportSnapshot = readAllExportBlocks();
    const exportError = validateExportBlocksSnapshot(exportSnapshot);
    if (exportError) {
        showAlert(exportError, 'error');
        return;
    }
    // Disable the submit button + mark aria-busy for the duration of
    // the POST so a double-click can't fire two device-create batches.
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.setAttribute('aria-busy', 'true');
    }
    try {
        await createDevices(startIp, deviceCount, netmask, resourceFile, exportSnapshot);
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.removeAttribute('aria-busy');
        }
    }
    elements.createForm.reset();
    document.getElementById('deviceCount').value = '1';
    document.getElementById('netmask').value = '24';
    document.getElementById('resourceFile').value = '';
    // Reset the export sections: close the <details> and clear inputs.
    ['flowSection', 'trapSection', 'syslogSection'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.open = false;
    });
});

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
