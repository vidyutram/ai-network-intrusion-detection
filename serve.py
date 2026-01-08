

from datetime import datetime

from typing import List, Dict

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from model import load_model, predict_single
from ae_model import has_autoencoder, anomaly_score
from threat_intel import is_malicious_ip
from behavior_detection import register_event


app = FastAPI(title="Network Intrusion Detection API with Dashboard")

model = load_model()   # ensure nids_model.joblib exists (run train.py first)

# In-memory store for recent events (for dashboard)
recent_events: List[Dict] = []
MAX_EVENTS = 1000  # keep more so filters have data


class ConnectionData(BaseModel):
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: float
    dst_bytes: float
    land: int
    wrong_fragment: int
    urgent: int
    hot: int
    num_failed_logins: int
    logged_in: int
    num_compromised: int
    root_shell: int
    su_attempted: int
    num_root: int
    num_file_creations: int
    num_shells: int
    num_access_files: int
    num_outbound_cmds: int
    is_host_login: int
    is_guest_login: int
    count: float
    srv_count: float
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: float
    dst_host_srv_count: float
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None



@app.post("/predict")
def predict_api(conn: ConnectionData):
    feature_dict = conn.dict()
    label, proba = predict_single(model, feature_dict)

    # Autoencoder anomaly score (if available)
    if has_autoencoder():
        anom = anomaly_score(feature_dict)
    else:
        anom = None

    # Threat intel lookup on src/dst IP
    src_ip = feature_dict.get("src_ip")
    dst_ip = feature_dict.get("dst_ip")
    src_port = feature_dict.get("src_port")
    dst_port = feature_dict.get("dst_port")

    intel_src = is_malicious_ip(src_ip)
    intel_dst = is_malicious_ip(dst_ip)
    intel_flag = intel_src or intel_dst

    # Behavioral detection (port scan / DoS) based on src/dst/dport
    behavior_alerts = register_event(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
    ) if src_ip and dst_port is not None else []

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "protocol_type": feature_dict.get("protocol_type"),
        "service": feature_dict.get("service"),
        "prediction": label,
        "attack_probability": proba,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "anomaly_score": anom,
        "intel_malicious": intel_flag,
        "behavior_alerts": behavior_alerts,
    }

    recent_events.append(event)
    if len(recent_events) > MAX_EVENTS:
        del recent_events[0 : len(recent_events) - MAX_EVENTS]

    return event



@app.get("/events")
def get_events():
    """
    Return recent prediction events for dashboard.
    """
    return {"events": recent_events}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    """
    Enhanced HTML dashboard with:
    - Nicer styling
    - Summary cards (totals)
    - Auto refresh toggle + interval
    - Threshold slider for high-risk alerts
    - Filters and search
    - Live chart + alert banner
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>NIDS Real-Time Dashboard</title>
        <meta charset="UTF-8">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            :root {
                --bg-dark: #020617;
                --bg-panel: #020617;
                --bg-panel-soft: #020617;
                --border-subtle: #1f2937;
                --accent: #38bdf8;
                --accent-soft: #0ea5e9;
                --text-main: #e5e7eb;
                --text-muted: #9ca3af;
                --danger: #7f1d1d;
                --danger-soft: #fecaca;
                --success: #065f46;
                --success-soft: #bbf7d0;
            }
            * {
                box-sizing: border-box;
            }
            body {
                font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                background: radial-gradient(circle at top, #020617 0, #020617 40%, #020617 100%);
                color: var(--text-main);
                margin: 0;
                padding: 20px;
            }
            h1 {
                text-align: center;
                margin-bottom: 4px;
            }
            .subtitle {
                text-align: center;
                color: var(--text-muted);
                margin-bottom: 10px;
                font-size: 13px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                background: var(--bg-panel-soft);
            }
            th, td {
                padding: 8px 10px;
                border-bottom: 1px solid var(--border-subtle);
                text-align: left;
                font-size: 13px;
            }
            th {
                background: #0b1220;
                position: sticky;
                top: 0;
                z-index: 2;
            }
            tr:nth-child(even) {
                background: #020617;
            }
            tbody tr:hover {
                background: #030712;
            }
            .pill {
                padding: 2px 8px;
                border-radius: 999px;
                font-size: 11px;
            }
            .pill-attack {
                background: var(--danger);
                color: var(--danger-soft);
            }
            .pill-normal {
                background: var(--success);
                color: var(--success-soft);
            }
            .footer {
                margin-top: 10px;
                text-align: center;
                font-size: 12px;
                color: var(--text-muted);
            }
            .controls {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                justify-content: space-between;
                align-items: center;
                margin: 15px 0;
                padding: 10px;
                background: rgba(15,23,42,0.8);
                border-radius: 0.75rem;
                border: 1px solid var(--border-subtle);
                backdrop-filter: blur(6px);
            }
            .controls-group {
                display: flex;
                gap: 8px;
                align-items: center;
                flex-wrap: wrap;
            }
            select, input[type="text"], input[type="range"] {
                background: #020617;
                border: 1px solid #374151;
                color: var(--text-main);
                padding: 4px 8px;
                border-radius: 0.5rem;
                font-size: 13px;
            }
            select:focus, input[type="text"]:focus, input[type="range"]:focus {
                outline: none;
                border-color: var(--accent);
            }
            .badge {
                font-size: 11px;
                padding: 2px 6px;
                border-radius: 999px;
                background: #111827;
                color: var(--text-muted);
            }
            .btn {
                border-radius: 999px;
                padding: 4px 10px;
                font-size: 12px;
                border: 1px solid var(--border-subtle);
                background: #020617;
                color: var(--text-main);
                cursor: pointer;
            }
            .btn:hover {
                border-color: var(--accent);
            }
            .btn-ghost {
                background: transparent;
            }
            .btn-danger {
                border-color: var(--danger);
                color: var(--danger-soft);
            }
            .alert-banner {
                margin: 10px auto;
                max-width: 1200px;
                padding: 10px 14px;
                border-radius: 0.75rem;
                display: none;
                align-items: center;
                justify-content: space-between;
                border: 1px solid var(--danger);
                background: #111827;
                color: var(--danger-soft);
            }
            .alert-banner.danger {
                background: var(--danger);
                color: #fee2e2;
                border-color: var(--danger-soft);
            }
            .alert-text {
                font-size: 13px;
            }
            .alert-strong {
                font-weight: bold;
                margin-right: 4px;
            }
            .alert-blink {
                animation: blink 1s linear infinite;
            }
            @keyframes blink {
                0%, 50%, 100% { opacity: 1; }
                25%, 75% { opacity: 0.3; }
            }
            .chart-container {
                margin: 10px 0 20px 0;
                padding: 10px 14px 14px 14px;
                background: rgba(15,23,42,0.9);
                border-radius: 0.75rem;
                border: 1px solid var(--border-subtle);
                backdrop-filter: blur(8px);
            }
            .chart-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 6px;
            }
            .chart-title {
                font-size: 13px;
                color: var(--text-main);
            }
            .chart-subtitle {
                font-size: 11px;
                color: var(--text-muted);
            }
            .stats-row {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 10px;
                margin-top: 10px;
            }
            .stat-card {
                background: #020617;
                border-radius: 0.75rem;
                border: 1px solid var(--border-subtle);
                padding: 8px 10px;
                font-size: 12px;
            }
            .stat-label {
                color: var(--text-muted);
                margin-bottom: 4px;
            }
            .stat-value {
                font-size: 16px;
                font-weight: 600;
            }
            .stat-tag {
                font-size: 10px;
                color: var(--text-muted);
            }
            .stat-attack {
                color: var(--danger-soft);
            }
            .stat-normal {
                color: var(--success-soft);
            }
            @media (max-width: 900px) {
                .stats-row {
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                }
            }
            @media (max-width: 600px) {
                .controls {
                    flex-direction: column;
                    align-items: flex-start;
                }
                .stats-row {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Network Intrusion Detection – Live Dashboard</h1>
            <div class="subtitle">
                Streaming predictions from live packet capture & simulators via FastAPI.
            </div>

            <div id="alert-banner" class="alert-banner">
                <div class="alert-text">
                    <span class="alert-strong">System status:</span>
                    <span id="alert-message">No high-risk attacks detected.</span>
                </div>
                <span class="badge" id="alert-count"></span>
            </div>

            <div class="controls">
                <div class="controls-group">
                    <span class="badge">Prediction</span>
                    <select id="filter-prediction">
                        <option value="all">All</option>
                        <option value="ATTACK">Only ATTACK</option>
                        <option value="NORMAL">Only NORMAL</option>
                    </select>

                    <span class="badge">Time range</span>
                    <select id="time-range">
                        <option value="last100">Last 100 events</option>
                        <option value="last5min">Last 5 minutes</option>
                        <option value="today">Today</option>
                    </select>

                    <span class="badge">Search</span>
                    <input id="search-text" type="text" placeholder="Filter by protocol/service...">
                </div>

                <div class="controls-group">
                    <span class="badge">Auto refresh</span>
                    <button id="toggle-refresh" class="btn btn-ghost">ON</button>

                    <span class="badge">Interval</span>
                    <select id="refresh-interval">
                        <option value="1000">1s</option>
                        <option value="2000" selected>2s</option>
                        <option value="5000">5s</option>
                        <option value="10000">10s</option>
                    </select>

                    <span class="badge">High-risk threshold</span>
                    <input id="threshold-slider" type="range" min="0.3" max="0.99" step="0.01" value="0.5">
                    <span id="threshold-label" class="badge">0.50</span>

                    <button id="clear-view" class="btn btn-danger">Clear view</button>
                </div>
            </div>

            <div class="chart-container">
                <div class="chart-header">
                    <div>
                        <div class="chart-title">Attack vs Normal distribution</div>
                        <div class="chart-subtitle">Based on current filters & time range</div>
                    </div>
                    <div class="badge" id="total-events-badge">0 events</div>
                </div>
                <canvas id="attackChart" height="80"></canvas>

                <div class="stats-row">
                    <div class="stat-card">
                        <div class="stat-label">Total events in view</div>
                        <div class="stat-value" id="stat-total">0</div>
                        <div class="stat-tag">After all filters</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Normal traffic</div>
                        <div class="stat-value stat-normal" id="stat-normal">0</div>
                        <div class="stat-tag">Predicted as NORMAL</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Attack traffic</div>
                        <div class="stat-value stat-attack" id="stat-attack">0</div>
                        <div class="stat-tag">Predicted as ATTACK</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Attack ratio</div>
                        <div class="stat-value" id="stat-ratio">0%</div>
                        <div class="stat-tag">ATTACK / Total</div>
                    </div>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Time (Local)</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Prediction</th>
                        <th>Attack Prob.</th>
                    </tr>
                </thead>
                <tbody id="events-body">
                    <tr><td colspan="5">Waiting for events...</td></tr>
                </tbody>
            </table>
            <div class="footer">
                Auto refresh can be toggled above. All filters are applied client-side.
            </div>
        </div>

        <script>
            let attackChart = null;
            let lastHighRiskTimestamp = null;
            let HIGH_RISK_THRESHOLD = 0.5;
            let autoRefresh = true;
            let refreshIntervalMs = 2000;
            let refreshTimerId = null;
            let lastFilteredEvents = [];

            function formatTimestamp(ts) {
                try {
                    const d = new Date(ts);
                    return d.toLocaleString('en-IN', {
                        year: 'numeric',
                        month: 'short',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                    });
                } catch (e) {
                    return ts || '';
                }
            }

            function isWithinTimeRange(ev, range) {
                if (!ev.timestamp) return false;
                const evTime = new Date(ev.timestamp);
                const now = new Date();

                if (range === 'last100') {
                    return true; // limit applied later
                } else if (range === 'last5min') {
                    return (now - evTime) <= 5 * 60 * 1000;
                } else if (range === 'today') {
                    return evTime.toDateString() === now.toDateString();
                }
                return true;
            }

            function playBeep() {
                try {
                    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                    const oscillator = audioCtx.createOscillator();
                    const gainNode = audioCtx.createGain();
                    oscillator.connect(gainNode);
                    gainNode.connect(audioCtx.destination);
                    oscillator.type = 'square';
                    oscillator.frequency.value = 880;
                    gainNode.gain.setValueAtTime(0.04, audioCtx.currentTime);
                    oscillator.start();
                    oscillator.stop(audioCtx.currentTime + 0.25);
                } catch (e) {
                    console.warn("Audio beep not supported:", e);
                }
            }

            function updateStats(events) {
                const total = events.length;
                let attackCount = 0;
                let normalCount = 0;
                events.forEach(ev => {
                    if (ev.prediction === 'ATTACK') attackCount++;
                    else if (ev.prediction === 'NORMAL') normalCount++;
                });

                const ratio = total > 0 ? ((attackCount / total) * 100).toFixed(1) : '0.0';

                document.getElementById('stat-total').textContent = total;
                document.getElementById('stat-normal').textContent = normalCount;
                document.getElementById('stat-attack').textContent = attackCount;
                document.getElementById('stat-ratio').textContent = ratio + '%';
            }

            function updateAlertBanner(events) {
                const banner = document.getElementById('alert-banner');
                const msg = document.getElementById('alert-message');
                const countBadge = document.getElementById('alert-count');

                const highRisk = events.filter(ev =>
                    ev.prediction === 'ATTACK' &&
                    typeof ev.attack_probability === 'number' &&
                    ev.attack_probability >= HIGH_RISK_THRESHOLD
                );

                if (highRisk.length > 0) {
                    banner.style.display = 'flex';
                    banner.classList.add('danger', 'alert-blink');
                    msg.textContent = 'High-risk attacks detected! Investigate immediately.';
                    countBadge.textContent = highRisk.length + ' high-risk events';

                    const newest = highRisk[highRisk.length - 1];
                    if (newest.timestamp && newest.timestamp !== lastHighRiskTimestamp) {
                        lastHighRiskTimestamp = newest.timestamp;
                        playBeep();
                    }
                } else {
                    banner.style.display = 'flex';
                    banner.classList.remove('danger', 'alert-blink');
                    msg.textContent = 'No high-risk attacks detected.';
                    countBadge.textContent = events.length + ' events in view';
                }
            }

            function updateChart(events) {
                const ctx = document.getElementById('attackChart').getContext('2d');

                let attackCount = 0;
                let normalCount = 0;

                events.forEach(ev => {
                    if (ev.prediction === 'ATTACK') attackCount++;
                    else if (ev.prediction === 'NORMAL') normalCount++;
                });

                const totalBadge = document.getElementById('total-events-badge');
                totalBadge.textContent = (attackCount + normalCount) + ' events';

                const data = {
                    labels: ['NORMAL', 'ATTACK'],
                    datasets: [{
                        label: 'Count',
                        data: [normalCount, attackCount],
                    }]
                };

                if (!attackChart) {
                    attackChart = new Chart(ctx, {
                        type: 'bar',
                        data: data,
                        options: {
                            responsive: true,
                            plugins: {
                                legend: { display: false }
                            },
                            scales: {
                                x: { ticks: { color: '#e5e7eb' } },
                                y: {
                                    beginAtZero: true,
                                    ticks: { color: '#e5e7eb' }
                                }
                            }
                        }
                    });
                } else {
                    attackChart.data = data;
                    attackChart.update();
                }
            }

            async function fetchEvents() {
                try {
                    const resp = await fetch('/events');
                    const data = await resp.json();
                    const tbody = document.getElementById('events-body');
                    tbody.innerHTML = '';

                    let events = data.events || [];

                    const filterPrediction = document.getElementById('filter-prediction').value;
                    const timeRange = document.getElementById('time-range').value;
                    const searchText = document.getElementById('search-text').value.toLowerCase();

                    // Time filtering
                    events = events.filter(ev => isWithinTimeRange(ev, timeRange));

                    // For "last100", apply count limit AFTER time filter
                    if (timeRange === 'last100' && events.length > 100) {
                        events = events.slice(events.length - 100);
                    }

                    // Prediction filter
                    if (filterPrediction !== 'all') {
                        events = events.filter(ev => ev.prediction === filterPrediction);
                    }

                    // Search filter
                    if (searchText) {
                        events = events.filter(ev =>
                            (ev.protocol_type || '').toLowerCase().includes(searchText) ||
                            (ev.service || '').toLowerCase().includes(searchText)
                        );
                    }

                    lastFilteredEvents = events;

                    updateAlertBanner(events);
                    updateChart(events);
                    updateStats(events);

                    if (!events || events.length === 0) {
                        const row = document.createElement('tr');
                        const cell = document.createElement('td');
                        cell.colSpan = 5;
                        cell.textContent = 'No events match the current filters.';
                        row.appendChild(cell);
                        tbody.appendChild(row);
                        return;
                    }

                    // Show newest first
                    events.slice().reverse().forEach(ev => {
                        const row = document.createElement('tr');

                        const ts = document.createElement('td');
                        ts.textContent = formatTimestamp(ev.timestamp);
                        row.appendChild(ts);

                        const proto = document.createElement('td');
                        proto.textContent = ev.protocol_type || '';
                        row.appendChild(proto);

                        const svc = document.createElement('td');
                        svc.textContent = ev.service || '';
                        row.appendChild(svc);

                        const pred = document.createElement('td');
                        const pill = document.createElement('span');
                        pill.classList.add('pill');
                        if (ev.prediction === 'ATTACK') {
                            pill.classList.add('pill-attack');
                            pill.textContent = 'ATTACK';
                        } else {
                            pill.classList.add('pill-normal');
                            pill.textContent = 'NORMAL';
                        }
                        pred.appendChild(pill);
                        row.appendChild(pred);

                        const prob = document.createElement('td');
                        if (typeof ev.attack_probability === 'number') {
                            prob.textContent = ev.attack_probability.toFixed(4);
                        } else {
                            prob.textContent = '-';
                        }
                        row.appendChild(prob);

                        tbody.appendChild(row);
                    });
                } catch (e) {
                    console.error('Error fetching events', e);
                }
            }

            function scheduleRefresh() {
                if (refreshTimerId) {
                    clearInterval(refreshTimerId);
                    refreshTimerId = null;
                }
                if (autoRefresh) {
                    refreshTimerId = setInterval(fetchEvents, refreshIntervalMs);
                }
            }

            document.addEventListener('DOMContentLoaded', () => {
                const filterPrediction = document.getElementById('filter-prediction');
                const timeRange = document.getElementById('time-range');
                const searchText = document.getElementById('search-text');
                const toggleRefreshBtn = document.getElementById('toggle-refresh');
                const refreshIntervalSel = document.getElementById('refresh-interval');
                const thresholdSlider = document.getElementById('threshold-slider');
                const thresholdLabel = document.getElementById('threshold-label');
                const clearViewBtn = document.getElementById('clear-view');

                filterPrediction.addEventListener('change', fetchEvents);
                timeRange.addEventListener('change', fetchEvents);
                searchText.addEventListener('input', () => {
                    if (window.searchTimeout) clearTimeout(window.searchTimeout);
                    window.searchTimeout = setTimeout(fetchEvents, 200);
                });

                toggleRefreshBtn.addEventListener('click', () => {
                    autoRefresh = !autoRefresh;
                    toggleRefreshBtn.textContent = autoRefresh ? 'ON' : 'OFF';
                    toggleRefreshBtn.classList.toggle('btn-danger', !autoRefresh);
                    scheduleRefresh();
                });

                refreshIntervalSel.addEventListener('change', () => {
                    refreshIntervalMs = parseInt(refreshIntervalSel.value, 10) || 2000;
                    scheduleRefresh();
                });

                thresholdSlider.addEventListener('input', () => {
                    HIGH_RISK_THRESHOLD = parseFloat(thresholdSlider.value);
                    thresholdLabel.textContent = HIGH_RISK_THRESHOLD.toFixed(2);
                    // re-evaluate alert banner with current events
                    updateAlertBanner(lastFilteredEvents);
                });

                clearViewBtn.addEventListener('click', () => {
                    const tbody = document.getElementById('events-body');
                    tbody.innerHTML = '';
                    lastFilteredEvents = [];
                    updateAlertBanner([]);
                    updateChart([]);
                    updateStats([]);
                });

                // Initial load + auto refresh
                fetchEvents();
                scheduleRefresh();
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
