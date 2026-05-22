// nl6 Device Simulator - API Functions

const API_BASE = '/api/v1';
let devices = [];
let resources = [];
let isStatusPolling = false;

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
    status: '',
    exports: ''
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
    renderProgressBanner(status);
    // Toolbar [+ Create devices] is disabled whenever the simulator is
    // already busy with a pre-alloc or create batch — clicking it now
    // would just queue a second batch behind the first.
    const busy = !!(status.is_pre_allocating || status.is_creating_devices);
    if (elements && elements.createDevicesBtn) {
        elements.createDevicesBtn.disabled = busy;
        elements.createDevicesBtn.title = busy
            ? 'Provisioning in progress…'
            : 'Create new device set';
    }
}

// renderProgressBanner mounts a persistent progress bar above the
// alerts region while pre-allocation or device creation is active.
// When both flags are false the banner is removed from the DOM (not
// merely hidden — keeps the layout calm when idle). The banner is
// the sole in-progress signal; the redundant warning-toast path was
// retired during code review of PR4 (banner replaces it).
function renderProgressBanner(status) {
    const slot = document.getElementById('progressBanner');
    if (!slot) return;
    if (!status.is_pre_allocating && !status.is_creating_devices) {
        slot.innerHTML = '';
        slot.className = '';
        return;
    }
    let label, progress, total;
    if (status.is_pre_allocating) {
        label = 'Preparing TUN interfaces';
        progress = Number(status.pre_alloc_progress) || 0;
        total = Number(status.pre_alloc_total) || 0;
    } else {
        label = 'Creating devices';
        progress = Number(status.device_create_progress) || 0;
        total = Number(status.device_create_total) || 0;
    }
    // Clamp pct to [0, 100] — a race in the server's atomic counter
    // store can briefly report progress > total during batch boundaries.
    const pct = total > 0 ? Math.min(100, Math.max(0, Math.round((progress / total) * 100))) : 0;
    slot.className = 'progress-banner';
    slot.innerHTML =
        '<div class="progress-banner-row">' +
            '<span class="eyebrow">In progress</span>' +
            '<span class="mono">' + escapeHtml(label) + ': ' + progress + ' / ' + total + ' (' + pct + '%)</span>' +
        '</div>' +
        '<div class="progress-track">' +
            '<div class="progress-fill" style="width: ' + pct + '%"></div>' +
        '</div>';
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

// populateResourceSelect is now a no-op stub kept for backwards
// compatibility with the loadResources() call site. The inline
// #create form (which owned `deviceCategory` + `resourceFile`
// selects) was removed in PR6; the provision modal owns its own
// selects and populates them via renderProvisionBody on each open.
function populateResourceSelect() {
    // intentionally empty; modal handles its own dropdown population
}

// resourceCategories returns the sorted unique list of categories from
// the loaded resources. Used by the provision modal's basics step.
function resourceCategories() {
    return [...new Set(resources.map(r => r.category))].sort();
}

// resourcesForCategory returns the resource entries filtered by
// category (empty string returns all). Used by the provision modal
// when populating the device-type select.
function resourcesForCategory(category) {
    return category ? resources.filter(r => r.category === category) : resources;
}

async function createDevices(startIp, deviceCount, netmask, resourceFile, category, exportSnapshot) {
    try {
        const requestData = {
            start_ip: startIp,
            device_count: parseInt(deviceCount),
            netmask: netmask
        };

        // Check if round robin mode is selected
        if (resourceFile === '__round_robin__') {
            requestData.round_robin = true;
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
        throw error;
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

// _telemetryOpen tracks per-card collapsed state for the telemetry
// streams panel. Closure-scoped — not persisted across reloads
// (design.md §D5: open-state persistence here would solve a non-problem).
// Each card's open/closed state is also cached alongside its last-rendered
// data so the toggle handler can re-render without an extra fetch.
const _telemetryOpen = { flow: false, trap: false, syslog: false };
const _telemetryLastData = { flow: null, trap: null, syslog: null };

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
        renderTelemetryCard('flow', data, FLOW_SPEC);
    } catch (error) {
        console.error('Failed to load flow status:', error);
        renderTelemetryCardError('flow', 'Flow');
    } finally {
        _exportStatusInFlight.flow = false;
    }
}

async function loadTrapStatus() {
    if (_exportStatusInFlight.trap) return;
    _exportStatusInFlight.trap = true;
    try {
        const data = await apiCall('/traps/status'); // status endpoint is not enveloped
        renderTelemetryCard('trap', data || {}, TRAP_SPEC);
    } catch (error) {
        console.error('Failed to load trap status:', error);
        renderTelemetryCardError('trap', 'SNMP traps');
    } finally {
        _exportStatusInFlight.trap = false;
    }
}

async function loadSyslogStatus() {
    if (_exportStatusInFlight.syslog) return;
    _exportStatusInFlight.syslog = true;
    try {
        const data = await apiCall('/syslog/status'); // not enveloped
        renderTelemetryCard('syslog', data || {}, SYSLOG_SPEC);
    } catch (error) {
        console.error('Failed to load syslog status:', error);
        renderTelemetryCardError('syslog', 'Syslog');
    } finally {
        _exportStatusInFlight.syslog = false;
    }
}

// fmtCount formats a counter as a compact string with k/M/B suffix.
function fmtCount(n) {
    const v = Number(n) || 0;
    if (v < 1000) return String(v);
    if (v < 1e6) return (v / 1e3).toFixed(v >= 1e4 ? 0 : 1) + 'k';
    if (v < 1e9) return (v / 1e6).toFixed(v >= 1e7 ? 0 : 1) + 'M';
    return (v / 1e9).toFixed(1) + 'B';
}

// fmtBytes formats a byte count with KiB / MiB / GiB suffix.
function fmtBytes(n) {
    const v = Number(n) || 0;
    if (v < 1024) return v + ' B';
    if (v < 1048576) return (v / 1024).toFixed(v >= 10240 ? 0 : 1) + ' KiB';
    if (v < 1073741824) return (v / 1048576).toFixed(v >= 10485760 ? 0 : 1) + ' MiB';
    return (v / 1073741824).toFixed(1) + ' GiB';
}

// Per-kind spec for renderTelemetryCard. Each spec exposes:
//   label          — display name for the card head
//   columns        — column names shown in the per-collector breakdown
//   summary(arr)   — array of {k, v, warn?} for the always-visible summary row
//   collectorStats(c) — array of {k, v, warn?, title?} for one breakdown row
//   collectorMeta(c)  — HTML for the meta slot to the right of the collector address
const FLOW_SPEC = {
    label: 'Flow',
    columns: ['pkts', 'bytes'],
    summary: collectors => {
        const pkts = collectors.reduce((a, c) => a + (c.sent_packets || 0), 0);
        const bytes = collectors.reduce((a, c) => a + (c.sent_bytes || 0), 0);
        return [
            { k: 'pkts', v: fmtCount(pkts) },
            { k: 'bytes', v: fmtBytes(bytes) }
        ];
    },
    collectorStats: c => [
        { k: 'pkts', v: fmtCount(c.sent_packets || 0) },
        { k: 'bytes', v: fmtBytes(c.sent_bytes || 0) }
    ],
    collectorMeta: c => '<span class="mono">' + escapeHtml(c.protocol || '?') + '</span>'
};

const TRAP_SPEC = {
    label: 'SNMP traps',
    columns: ['sent', 'failed'],
    summary: collectors => {
        const sent = collectors.reduce((a, c) => a + (c.sent || 0), 0);
        const failed = collectors.reduce((a, c) => a + (c.informs_failed || 0), 0);
        return [
            { k: 'sent', v: fmtCount(sent) },
            { k: 'failed', v: fmtCount(failed), warn: failed > 0 }
        ];
    },
    collectorStats: c => {
        const sent = c.sent || 0;
        const failed = c.informs_failed || 0;
        const title = c.mode === 'inform'
            ? sent + ' sent (acked ' + (c.informs_acked || 0) + ')'
            : sent + ' sent';
        return [
            { k: 'sent', v: fmtCount(sent), title: title },
            { k: 'failed', v: fmtCount(failed), warn: failed > 0, title: failed + ' failed' }
        ];
    },
    collectorMeta: c => {
        const isInform = (c.mode || '').toUpperCase() === 'INFORM';
        const version = c.version || 'v2c';
        const tipText = (isInform ? 'Inform' : 'Trap') + ' ' + version;
        return '<span class="trap-mode" title="' + escapeHtml(tipText) + '">' +
            '<span class="trap-mode-ver mono">' + escapeHtml(version) + '</span>' +
            '<span class="trap-mode-arrow mono" aria-hidden="true">' + (isInform ? '↔' : '→') + '</span>' +
        '</span>';
    }
};

const SYSLOG_SPEC = {
    label: 'Syslog',
    columns: ['sent', 'failed'],
    summary: collectors => {
        const sent = collectors.reduce((a, c) => a + (c.sent || 0), 0);
        const failed = collectors.reduce((a, c) => a + (c.send_failures || 0), 0);
        return [
            { k: 'sent', v: fmtCount(sent) },
            { k: 'failed', v: fmtCount(failed), warn: failed > 0 }
        ];
    },
    collectorStats: c => {
        const failed = c.send_failures || 0;
        return [
            { k: 'sent', v: fmtCount(c.sent || 0) },
            { k: 'failed', v: fmtCount(failed), warn: failed > 0 }
        ];
    },
    collectorMeta: c => '<span class="mono">' + escapeHtml(c.format || '?') + '</span>'
};

// renderTelemetryCard builds one telemetry card (Flow / Traps / Syslog).
// The card has a clickable head with on/off pill, an always-visible
// summary row (devices count + per-stream summary stats), and an
// expand-to-show per-collector breakdown table. Open state lives in
// _telemetryOpen; the toggle handler calls back into this function with
// the cached last data so flipping open/closed is instant.
function renderTelemetryCard(kind, data, spec) {
    const card = document.getElementById(kind + 'Card');
    if (!card) return;
    _telemetryLastData[kind] = data;

    const collectors = Array.isArray(data.collectors) ? data.collectors : [];
    const devices = Number(data.devices_exporting) || 0;
    // Truthy check rather than `=== true` so a server schema that adds
    // / renames the field doesn't render populated data as "not running";
    // if collectors is non-empty, we trust that signal too.
    const enabled = !!data.subsystem_active || collectors.length > 0;
    const isOpen = _telemetryOpen[kind];

    const chevRight = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>';
    const chevDown  = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>';

    const head =
        '<button type="button" class="export-card-head" aria-expanded="' + (isOpen ? 'true' : 'false') + '">' +
            '<span class="export-card-chev">' + (isOpen ? chevDown : chevRight) + '</span>' +
            '<span class="status-label">' + escapeHtml(spec.label) + '</span>' +
            '<span class="export-pill ' + (enabled ? 'on' : 'off') + '">' + (enabled ? 'on' : 'off') + '</span>' +
        '</button>';

    const summary = spec.summary(collectors);
    const summaryBody =
        '<div class="export-card-summary">' +
            '<div class="summary-stat">' +
                '<span class="summary-stat-val mono" style="color: ' + (devices > 0 ? 'var(--accent)' : 'var(--fg-3)') + '">' + devices + '</span>' +
                '<span class="summary-stat-key">devices</span>' +
            '</div>' +
            summary.map(s =>
                '<div class="summary-stat">' +
                    '<span class="summary-stat-val mono' + (s.warn ? ' is-warn' : '') + '">' + escapeHtml(s.v) + '</span>' +
                    '<span class="summary-stat-key">' + escapeHtml(s.k) + '</span>' +
                '</div>'
            ).join('') +
            '<span class="summary-collectors muted mono">' + collectors.length + ' coll.</span>' +
        '</div>';

    let breakdown = '';
    if (isOpen) {
        const cols = spec.columns;
        const headRow =
            '<div class="collector-head" style="--stat-cols: ' + cols.length + '">' +
                '<span class="collector-head-cell">Collector</span>' +
                '<span class="collector-head-cell col-dev">dev</span>' +
                cols.map(c => '<span class="collector-head-cell">' + escapeHtml(c) + '</span>').join('') +
            '</div>';
        const rows = collectors.length === 0
            ? '<li class="collector-empty muted">No active collectors yet.</li>'
            : collectors.map(c => {
                const stats = spec.collectorStats(c);
                return '<li style="--stat-cols: ' + stats.length + '">' +
                    '<div class="collector-row">' +
                        '<span class="mono">' + escapeHtml(c.collector || '?') + '</span>' +
                        '<span class="muted"> · </span>' +
                        spec.collectorMeta(c) +
                    '</div>' +
                    '<span class="collector-count mono">' + (Number(c.devices) || 0) + '</span>' +
                    stats.map(s =>
                        '<span class="collector-stat' + (s.warn ? ' is-warn' : '') + '"' +
                        (s.title ? ' title="' + escapeHtml(s.title) + '"' : '') + '>' +
                        escapeHtml(s.v) + '</span>'
                    ).join('') +
                '</li>';
            }).join('');
        breakdown = headRow + '<ul class="export-status-list">' + rows + '</ul>';
    }

    card.className = 'export-status-card' + (enabled ? '' : ' is-off') + (isOpen ? ' is-open' : '');
    card.innerHTML = head + summaryBody + breakdown;

    const btn = card.querySelector('.export-card-head');
    if (btn) {
        btn.addEventListener('click', () => {
            _telemetryOpen[kind] = !_telemetryOpen[kind];
            renderTelemetryCard(kind, _telemetryLastData[kind] || {}, spec);
        });
    }
}

function renderTelemetryCardError(kind, label) {
    const card = document.getElementById(kind + 'Card');
    if (!card) return;
    card.className = 'export-status-card is-off';
    card.innerHTML =
        '<button type="button" class="export-card-head" disabled>' +
            '<span class="export-card-chev"></span>' +
            '<span class="status-label">' + escapeHtml(label) + '</span>' +
            '<span class="export-pill off">err</span>' +
        '</button>' +
        '<div class="export-card-summary"><span class="muted">fetch failed</span></div>';
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
