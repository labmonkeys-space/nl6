// nl6 Device Simulator - API Functions

const API_BASE = '/api/v1';
let devices = [];
let resources = [];
let isStatusPolling = false;
let statusAlertMessage = '';

// Pagination state
const DEVICES_PER_PAGE = 50;
let currentPage = 1;

// Filter state
let filters = {
    id: '',
    ip: '',
    interface: '',
    deviceType: '',
    ports: '',
    status: ''
};

async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(API_BASE + endpoint, {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options
        });
        if (!response.ok) throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

async function loadDevices() {
    try {
        setLoading('refreshLoading', true);
        const response = await apiCall('/devices');
        devices = response.data || [];
        renderDevices();
        updateStats();
    } catch (error) {
        showAlert('Failed to load devices: ' + error.message, 'error');
    } finally {
        setLoading('refreshLoading', false);
    }
}

async function checkStatus() {
    try {
        const response = await apiCall('/status');
        const status = response.data;
        updateStatusDisplay(status);

        // Start/stop status polling based on activity
        if ((status.is_pre_allocating || status.is_creating_devices) && !isStatusPolling) {
            startStatusPolling();
        } else if (!status.is_pre_allocating && !status.is_creating_devices && isStatusPolling) {
            stopStatusPolling();
            // Refresh devices list when operations complete
            await loadDevices();
        }
    } catch (error) {
        console.error('Failed to check status:', error);
    }
}

function startStatusPolling() {
    if (isStatusPolling) return;
    isStatusPolling = true;
    const pollInterval = setInterval(async () => {
        if (!isStatusPolling) {
            clearInterval(pollInterval);
            return;
        }
        await checkStatus();
    }, 1000); // Poll every second during operations
}

function stopStatusPolling() {
    isStatusPolling = false;
}

function updateStatusDisplay(status) {
    if (status.is_pre_allocating) {
        const progress = status.pre_alloc_total > 0 ? Math.round((status.pre_alloc_progress / status.pre_alloc_total) * 100) : 0;
        const nextMessage = 'Preparing interfaces: ' + status.pre_alloc_progress + ' of ' + status.pre_alloc_total + ' (' + progress + '%)';
        if (statusAlertMessage !== nextMessage) {
            showAlert(nextMessage, 'warning');
            statusAlertMessage = nextMessage;
        }
    } else if (status.is_creating_devices) {
        const progress = status.device_create_total > 0 ? Math.round((status.device_create_progress / status.device_create_total) * 100) : 0;
        const nextMessage = 'Creating devices: ' + status.device_create_progress + ' of ' + status.device_create_total + ' (' + progress + '%)';
        if (statusAlertMessage !== nextMessage) {
            showAlert(nextMessage, 'warning');
            statusAlertMessage = nextMessage;
        }
    } else {
        statusAlertMessage = '';
    }
}

async function loadResources() {
    try {
        const response = await apiCall('/resources');
        resources = response.data || [];
        populateResourceSelect();
    } catch (error) {
        console.error('Failed to load resources: ' + error.message);
        showAlert('Failed to load device types: ' + error.message, 'warning');
    }
}

function populateResourceSelect() {
    const categorySelect = document.getElementById('deviceCategory');

    // Build unique sorted category list
    const categories = [...new Set(resources.map(r => r.category))].sort();
    categorySelect.innerHTML = '<option value="">All categories</option>';
    categories.forEach(cat => {
        const option = document.createElement('option');
        option.value = cat;
        option.textContent = cat;
        categorySelect.appendChild(option);
    });

    // Populate device type dropdown (initially all)
    updateDeviceTypeDropdown('');

    // Filter device types when category changes
    categorySelect.addEventListener('change', function() {
        updateDeviceTypeDropdown(this.value);
    });
}

function updateDeviceTypeDropdown(category) {
    const select = document.getElementById('resourceFile');
    const filtered = category ? resources.filter(r => r.category === category) : resources;
    const count = filtered.length;
    const label = category ? category : 'All ' + count + ' types';
    select.innerHTML = '<option value="">Default (Auto-detect)</option><option value="__round_robin__">Round Robin (' + label + ')</option>';

    filtered.forEach(resource => {
        const option = document.createElement('option');
        option.value = resource.filename;
        option.textContent = resource.name + ' (' + resource.type + ')';
        select.appendChild(option);
    });
}

async function createDevices(startIp, deviceCount, netmask, resourceFile, exportSnapshot) {
    try {
        setLoading('createLoading', true);
        const requestData = {
            start_ip: startIp,
            device_count: parseInt(deviceCount),
            netmask: netmask
        };

        // Check if round robin mode is selected
        if (resourceFile === '__round_robin__') {
            requestData.round_robin = true;
            const category = document.getElementById('deviceCategory').value;
            if (category) {
                requestData.category = category;
            }
        } else if (resourceFile) {
            // Add resource file if selected (not round robin)
            requestData.resource_file = resourceFile;
        }

        // Per-device export blocks — captured by the caller in the same
        // snapshot validateExportBlocksSnapshot saw, so a user typing
        // into a field between validate and submit can't slip
        // unvalidated data past us. See docs/reference/web-api.md
        // "Per-device export blocks" for the schema.
        if (exportSnapshot) {
            if (exportSnapshot.flow) requestData.flow = exportSnapshot.flow;
            if (exportSnapshot.traps) requestData.traps = exportSnapshot.traps;
            if (exportSnapshot.syslog) requestData.syslog = exportSnapshot.syslog;
        }

        const response = await apiCall('/devices', {
            method: 'POST',
            body: JSON.stringify(requestData)
        });
        showAlert(response.message, 'success');

        // Start status polling to track progress
        startStatusPolling();

        await loadDevices();
    } catch (error) {
        showAlert('Failed to create devices: ' + error.message, 'error');
    } finally {
        setLoading('createLoading', false);
    }
}

// --- Per-device export block readers -------------------------------------
//
// Each reader returns null when the operator left the collector field
// empty (the feature is opt-in per batch) and returns a populated
// object otherwise. Field validation is enforced at form-submit time
// in app_ui.js via validateExportBlocks(); these readers assume input
// has passed validation.

// Go duration format — a sequence of decimal-number + unit pairs,
// units from ns|us|µs|ms|s|m|h. Matches what DeviceXConfig.Validate
// accepts on the server. Bare "0" is also accepted as Go does (zero
// has no required unit). Empty string and plain non-zero integers
// (e.g. "30") fail.
const DURATION_RE = /^(0|(\d+(?:\.\d+)?(ns|us|µs|ms|s|m|h))+)$/;

// host:port — anything-non-empty:port with port 1-65535. Intentionally
// loose on host shape (can be IP, hostname, [v6]), strict on port.
const HOSTPORT_RE = /^.+:\d{1,5}$/;
function validHostPort(s) {
    if (!HOSTPORT_RE.test(s)) return false;
    const port = parseInt(s.slice(s.lastIndexOf(':') + 1), 10);
    return port >= 1 && port <= 65535;
}

function readFlowBlock() {
    const collector = document.getElementById('flowCollector').value.trim();
    if (!collector) return null;
    const block = { collector };
    const protocol = document.getElementById('flowProtocol').value;
    if (protocol) block.protocol = protocol;
    const active = document.getElementById('flowActiveTimeout').value.trim();
    if (active) block.active_timeout = active;
    const inactive = document.getElementById('flowInactiveTimeout').value.trim();
    if (inactive) block.inactive_timeout = inactive;
    return block;
}

function readTrapBlock() {
    const collector = document.getElementById('trapCollector').value.trim();
    if (!collector) return null;
    const block = { collector };
    const mode = document.getElementById('trapMode').value;
    if (mode) block.mode = mode;
    const community = document.getElementById('trapCommunity').value.trim();
    if (community) block.community = community;
    const interval = document.getElementById('trapInterval').value.trim();
    if (interval) block.interval = interval;
    const informTimeout = document.getElementById('trapInformTimeout').value.trim();
    if (informTimeout) block.inform_timeout = informTimeout;
    const informRetries = document.getElementById('trapInformRetries').value.trim();
    // `!== ''` instead of truthy because `"0"` is a legitimate value (0
    // retries means "fire once, no retransmit"). The other duration
    // fields use `if (foo)` because empty-string suppression is correct
    // there — don't normalise this to match without reading the test
    // for the zero-retries case in DeviceTrapConfig.Validate.
    if (informRetries !== '') block.inform_retries = parseInt(informRetries, 10);
    return block;
}

function readSyslogBlock() {
    const collector = document.getElementById('syslogCollector').value.trim();
    if (!collector) return null;
    const block = { collector };
    const format = document.getElementById('syslogFormat').value;
    if (format) block.format = format;
    const interval = document.getElementById('syslogInterval').value.trim();
    if (interval) block.interval = interval;
    return block;
}

// readAllExportBlocks captures the three blocks once so validate and
// submit operate on the same snapshot — avoids a TOCTOU window where
// an operator typing into a field between validate and POST sends data
// the validator never saw.
function readAllExportBlocks() {
    return {
        flow: readFlowBlock(),
        traps: readTrapBlock(),
        syslog: readSyslogBlock()
    };
}

// validateExportBlocksSnapshot returns an error message string when any
// enabled block has an invalid field, or null when everything is OK.
// Enforces the same rules the server's DeviceXConfig.Validate applies:
// host:port shape (with strict 1..65535 port range) and Go-duration
// strings for duration fields. Field names in alerts use the on-screen
// labels so operators can find the offending input without mapping
// snake_case JSON keys back to UI labels.
function validateExportBlocksSnapshot(snapshot) {
    const flow = snapshot.flow;
    if (flow) {
        if (!validHostPort(flow.collector)) return 'Flow → Collector must be host:port with port 1..65535 (e.g. 192.168.1.10:2055).';
        if (flow.active_timeout && !DURATION_RE.test(flow.active_timeout)) {
            return 'Flow → Active timeout must be a Go duration string (e.g. "30s", "1m30s").';
        }
        if (flow.inactive_timeout && !DURATION_RE.test(flow.inactive_timeout)) {
            return 'Flow → Inactive timeout must be a Go duration string (e.g. "15s", "1m").';
        }
    }
    const trap = snapshot.traps;
    if (trap) {
        if (!validHostPort(trap.collector)) return 'SNMP Traps → Collector must be host:port with port 1..65535 (e.g. 192.168.1.10:162).';
        if (trap.interval && !DURATION_RE.test(trap.interval)) {
            return 'SNMP Traps → Interval must be a Go duration string (e.g. "30s").';
        }
        if (trap.inform_timeout && !DURATION_RE.test(trap.inform_timeout)) {
            return 'SNMP Traps → INFORM retry timeout must be a Go duration string (e.g. "5s").';
        }
        if ('inform_retries' in trap) {
            const r = trap.inform_retries;
            // Reject NaN explicitly: typeof NaN === 'number' so the
            // typeof guard alone passes a NaN through to the server.
            if (typeof r !== 'number' || Number.isNaN(r) || r < 0 || !Number.isInteger(r)) {
                return 'SNMP Traps → INFORM max retries must be a non-negative integer.';
            }
        }
    }
    const syslog = snapshot.syslog;
    if (syslog) {
        if (!validHostPort(syslog.collector)) return 'Syslog → Collector must be host:port with port 1..65535 (e.g. 192.168.1.10:514).';
        if (syslog.interval && !DURATION_RE.test(syslog.interval)) {
            return 'Syslog → Interval must be a Go duration string (e.g. "10s", "1m").';
        }
    }
    return null;
}

// --- Export-status pollers -----------------------------------------------
//
// Poll the three status endpoints on a slow cadence and render a compact
// per-collector aggregate into the overview panel. Per-poller in-flight
// flags prevent stacking when the server stalls — a fresh tick is
// skipped while the previous fetch is still outstanding. The pollers
// fail visibly: errors update the summary line to "fetch failed" rather
// than just logging to console (silent-fail is the wrong default for
// observability surface).

const _exportStatusInFlight = { flow: false, trap: false, syslog: false };

async function loadExportStatuses() {
    await Promise.allSettled([
        loadFlowStatus(),
        loadTrapStatus(),
        loadSyslogStatus()
    ]);
}

async function loadFlowStatus() {
    if (_exportStatusInFlight.flow) return;
    _exportStatusInFlight.flow = true;
    try {
        const response = await apiCall('/flows/status');
        // /flows/status IS enveloped via sendDataResponse; trap and
        // syslog status endpoints are NOT (verified against
        // docs/reference/web-api.md). Don't normalise these without
        // updating both sides.
        const data = (response && response.data) ? response.data : (response || {});
        renderExportStatus('flow', data, {
            tupleKey: c => c.collector + ' / ' + (c.protocol || '?'),
            metricLine: c => 'pkts=' + (c.sent_packets || 0) + ' · bytes=' + (c.sent_bytes || 0)
        });
    } catch (error) {
        console.error('Failed to load flow status:', error);
        renderExportStatusError('flow');
    } finally {
        _exportStatusInFlight.flow = false;
    }
}

async function loadTrapStatus() {
    if (_exportStatusInFlight.trap) return;
    _exportStatusInFlight.trap = true;
    try {
        const data = await apiCall('/traps/status'); // status endpoint is not enveloped
        renderExportStatus('trap', data || {}, {
            tupleKey: c => c.collector + ' / ' + (c.mode || '?'),
            metricLine: c => {
                const parts = ['sent=' + (c.sent || 0)];
                if (c.mode === 'inform') {
                    parts.push('acked=' + (c.informs_acked || 0));
                    parts.push('failed=' + (c.informs_failed || 0));
                }
                return parts.join(' · ');
            }
        });
    } catch (error) {
        console.error('Failed to load trap status:', error);
        renderExportStatusError('trap');
    } finally {
        _exportStatusInFlight.trap = false;
    }
}

async function loadSyslogStatus() {
    if (_exportStatusInFlight.syslog) return;
    _exportStatusInFlight.syslog = true;
    try {
        const data = await apiCall('/syslog/status'); // not enveloped
        renderExportStatus('syslog', data || {}, {
            tupleKey: c => c.collector + ' / ' + (c.format || '?'),
            metricLine: c => 'sent=' + (c.sent || 0) + ' · failures=' + (c.send_failures || 0)
        });
    } catch (error) {
        console.error('Failed to load syslog status:', error);
        renderExportStatusError('syslog');
    } finally {
        _exportStatusInFlight.syslog = false;
    }
}

function renderExportStatus(kind, data, opts) {
    const summary = document.getElementById(kind + 'StatusSummary');
    const list = document.getElementById(kind + 'StatusList');
    if (!summary || !list) return;

    const collectors = Array.isArray(data.collectors) ? data.collectors : [];
    const devices = data.devices_exporting || 0;
    // Truthy check rather than `=== true` so a server schema that adds
    // / renames the field doesn't render populated data as "not
    // running"; if collectors is non-empty, we trust that signal too.
    const active = !!data.subsystem_active || collectors.length > 0;

    if (!active) {
        summary.textContent = 'not running';
        list.innerHTML = '';
        return;
    }
    if (collectors.length === 0) {
        summary.textContent = 'running · 0 collectors';
        list.innerHTML = '';
        return;
    }
    summary.textContent = collectors.length + (collectors.length === 1 ? ' collector' : ' collectors') + ' · ' + devices + ' devices';
    list.innerHTML = collectors.map(c =>
        '<li><strong>' + escapeHtml(opts.tupleKey(c)) + '</strong> — ' +
        escapeHtml((c.devices || 0) + ' dev · ' + opts.metricLine(c)) + '</li>'
    ).join('');
}

function renderExportStatusError(kind) {
    const summary = document.getElementById(kind + 'StatusSummary');
    const list = document.getElementById(kind + 'StatusList');
    if (summary) summary.textContent = 'fetch failed';
    if (list) list.innerHTML = '';
}

// escapeHtml is the single sanitiser for both element text and
// double-quoted attribute values. Covers `&`, `<`, `>`, `"`, `'` so
// callers don't need to know which context they're embedding into.
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

async function deleteDevice(deviceId) {
    try {
        const response = await apiCall('/devices/' + deviceId, { method: 'DELETE' });
        showAlert(response.message, 'success');
        await loadDevices();
    } catch (error) {
        showAlert('Failed to delete device: ' + error.message, 'error');
    }
}

async function deleteAllDevices() {
    if (!confirm('Delete all simulated devices?')) return;
    try {
        setLoading('deleteAllLoading', true);
        const response = await apiCall('/devices', { method: 'DELETE' });
        showAlert(response.message, 'success');
        await loadDevices();
    } catch (error) {
        showAlert('Failed to delete all devices: ' + error.message, 'error');
    } finally {
        setLoading('deleteAllLoading', false);
    }
}

function exportDevicesCSV() {
    try {
        setLoading('exportLoading', true);

        if (devices.length === 0) {
            showAlert('No devices to export', 'warning');
            return;
        }

        // Direct download from API endpoint
        const link = document.createElement('a');
        link.href = API_BASE + '/devices/export';
        link.download = 'devices.csv';
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        showAlert('Device list exported successfully', 'success');
    } catch (error) {
        showAlert('Failed to export devices: ' + error.message, 'error');
    } finally {
        setLoading('exportLoading', false);
    }
}

function downloadRouteScript() {
    try {
        setLoading('routeScriptLoading', true);

        if (devices.length === 0) {
            showAlert('No devices to generate routes for', 'warning');
            return;
        }

        // Direct download from API endpoint
        const link = document.createElement('a');
        link.href = API_BASE + '/devices/routes';
        link.download = 'add_simulator_routes.sh';
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        showAlert('Route script downloaded. The routes will persist after reboot.', 'success');
    } catch (error) {
        showAlert('Failed to download route script: ' + error.message, 'error');
    } finally {
        setLoading('routeScriptLoading', false);
    }
}

function testConnection(ip, port) {
    showAlert('SSH command: ssh simadmin@' + ip + ' on port ' + port + ' (password: simadmin)', 'warning');
}

function pingDevice(ip) {
    showAlert('Ping from your terminal with: ping ' + ip, 'warning');
}

function downloadPprofMemory() {
    try {
        setLoading('pprofMemoryLoading', true);
        const link = document.createElement('a');
        link.href = API_BASE + '/debug/pprof-memory';
        link.download = 'nl6_heap.pprof';
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showAlert('Heap profile download started', 'success');
    } catch (error) {
        showAlert('Failed to download heap profile: ' + error.message, 'error');
    } finally {
        setLoading('pprofMemoryLoading', false);
    }
}

function downloadCpuProfile() {
    try {
        setLoading('cpuProfileLoading', true);
        showAlert('Capturing CPU profile for 5 seconds...', 'warning');
        const link = document.createElement('a');
        link.href = API_BASE + '/debug/cpu-profile';
        link.download = 'nl6_cpu.pprof';
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        // The server takes 5 seconds to respond, so keep the spinner a bit
        setTimeout(() => {
            setLoading('cpuProfileLoading', false);
            showAlert('CPU profile captured (5 seconds)', 'success');
        }, 6000);
    } catch (error) {
        showAlert('Failed to capture CPU profile: ' + error.message, 'error');
        setLoading('cpuProfileLoading', false);
    }
}

async function loadSystemStats() {
    try {
        const response = await apiCall('/system-stats');
        const stats = response.data;
        updateSystemStatsDisplay(stats);
    } catch (error) {
        console.error('Failed to load system stats:', error);
    }
}

// loadVersion fetches the simulator's self-reported version and writes
// it into both the app-bar (#appVersion) and footer (#appFooterVersion)
// version slots. The version is immutable per process so this runs once
// on page load — never in a polling interval. textContent (not
// innerHTML) is load-bearing: keeps any unexpected characters in the
// version string from creating a DOM-injection surface.
async function loadVersion() {
    try {
        const response = await fetch('/api/v1/version');
        if (!response.ok) return;
        const payload = await response.json();
        if (!payload || !payload.version) return;
        const text = payload.version;
        for (const id of ['appVersion', 'appFooterVersion']) {
            const el = document.getElementById(id);
            if (el) el.textContent = text;
        }
    } catch (error) {
        console.error('Failed to load version:', error);
    }
}
