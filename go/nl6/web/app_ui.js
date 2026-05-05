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

        return matchesId && matchesIp && matchesInterface && matchesDeviceType && matchesPorts && matchesStatus;
    });
}

function updateFiltersFromInputs() {
    filters.id = elements.filterDeviceId.value;
    filters.ip = elements.filterIp.value;
    filters.interface = elements.filterInterface.value;
    filters.deviceType = elements.filterDeviceType.value;
    filters.ports = elements.filterPorts.value;
    filters.status = elements.filterStatus.value;
}

function clearAllFilters() {
    filters.id = '';
    filters.ip = '';
    filters.interface = '';
    filters.deviceType = '';
    filters.ports = '';
    filters.status = '';

    elements.filterDeviceId.value = '';
    elements.filterIp.value = '';
    elements.filterInterface.value = '';
    elements.filterDeviceType.value = '';
    elements.filterPorts.value = '';
    elements.filterStatus.value = '';

    currentPage = 1;
    renderDevices();
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
        // Update page info
        const showingCount = getCurrentPageDevices().length;
        const totalFiltered = filteredDevices.length;
        const totalDevices = devices.length;

        let pageInfoText = 'Page ' + currentPage + ' of ' + totalPages + ' (' + showingCount + ' of ' + totalFiltered + ' devices';
        if (totalFiltered !== totalDevices) {
            pageInfoText += ' filtered from ' + totalDevices + ' total';
        }
        pageInfoText += ')';

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
    // Filter controls are always visible

    if (devices.length === 0) {
        elements.deviceTable.innerHTML = '<div class="empty-state"><h3>No devices yet</h3><p>Create a device set to populate the simulator inventory.</p></div>';
        updatePaginationControls();
        return;
    }

    const filteredDevices = getFilteredDevices();
    if (filteredDevices.length === 0) {
        elements.deviceTable.innerHTML = '<div class="empty-state"><h3>No matching devices</h3><p>Adjust the filters or clear them to review the full fleet.</p></div>';
        updatePaginationControls();
        return;
    }

    const tableHTML = '<table>' +
        '<thead>' +
        '<tr>' +
        '<th>Device ID</th>' +
        '<th>IP Address</th>' +
        '<th>Interface</th>' +
        '<th>Device Type</th>' +
        '<th>Ports</th>' +
        '<th>Exports</th>' +
        '<th>Status</th>' +
        '<th>Actions</th>' +
        '</tr>' +
        '</thead>' +
        '<tbody>' +
        getCurrentPageDevices().map(device =>
            '<tr>' +
            '<td><span class="device-id">' + device.id + '</span></td>' +
            '<td><span class="device-ip">' + device.ip + '</span></td>' +
            '<td><span class="device-interface">' + (device.interface || 'N/A') + '</span></td>' +
            '<td><span class="device-type">' + (device.device_type || 'Unknown') + '</span></td>' +
            '<td><span class="device-ports">SNMP ' + device.snmp_port + ' · SSH ' + device.ssh_port + '</span></td>' +
            '<td>' + renderExportBadges(device) + '</td>' +
            '<td><span class="device-status ' + (device.running ? 'status-running' : 'status-stopped') + '">' +
            (device.running ? 'Running' : 'Stopped') + '</span></td>' +
            '<td><div class="device-actions">' +
            '<button class="btn btn-secondary btn-small" data-action="test-ssh" data-ip="' + device.ip + '" data-port="' + device.ssh_port + '">SSH</button>' +
            '<button class="btn btn-secondary btn-small" data-action="ping" data-ip="' + device.ip + '">Ping</button>' +
            '<button class="btn btn-danger btn-small" data-action="delete" data-device-id="' + device.id + '">Delete</button>' +
            '</div></td>' +
            '</tr>'
        ).join('') +
        '</tbody>' +
        '</table>';

    elements.deviceTable.innerHTML = tableHTML;

    // Add event listeners for device actions
    document.querySelectorAll('[data-action]').forEach(button => {
        button.addEventListener('click', (e) => {
            const action = e.target.getAttribute('data-action');
            const ip = e.target.getAttribute('data-ip');
            const port = e.target.getAttribute('data-port');
            const deviceId = e.target.getAttribute('data-device-id');

            switch(action) {
                case 'test-ssh':
                    testConnection(ip, parseInt(port));
                    break;
                case 'ping':
                    pingDevice(ip);
                    break;
                case 'delete':
                    deleteDevice(deviceId);
                    break;
            }
        });
    });


    // Update pagination controls
    updatePaginationControls();
}

// renderExportBadges returns an inline-HTML snippet showing three
// per-subsystem badges (F/T/S). Configured subsystems render with the
// accent colour; unconfigured render muted. Each tile carries an
// `aria-label` describing the state + destination so screen readers
// don't just hear "F T S" with no context (color-only state
// communication fails WCAG 1.1.1 / 1.4.1). The `title` attribute
// duplicates the label as a sighted-user hover-tooltip.
function renderExportBadges(device) {
    return '<div class="device-exports" role="group" aria-label="Export configuration">' +
        renderOneBadge('F', 'Flow', device.flow, b => (b.protocol || 'netflow9')) +
        renderOneBadge('T', 'SNMP traps', device.traps, b => (b.mode || 'trap')) +
        renderOneBadge('S', 'Syslog', device.syslog, b => (b.format || '5424')) +
        '</div>';
}

function renderOneBadge(letter, kind, block, kindSuffix) {
    if (block && block.collector) {
        const desc = kind + ' export to ' + block.collector + ' (' + kindSuffix(block) + ')';
        return '<span class="device-export-badge" role="img" aria-label="' + escapeHtml(desc) +
            '" title="' + escapeHtml(desc) + '">' + letter + '</span>';
    }
    const desc = kind + ' export disabled';
    return '<span class="device-export-badge device-export-badge-muted" role="img" aria-label="' + escapeHtml(desc) +
        '" title="' + escapeHtml(desc) + '">' + letter + '</span>';
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
