/**
 * Network Autopsy Dashboard Frontend Controller
 * Live telemetry polling, Chart.js graphs, incident management,
 * and sandbox demo fault injection.
 */

let latencyLossChart = null;
let protocolChart = null;
const maxDataPoints = 20;
const historyLabels = [];
const historyLatency = [];
const historyLoss = [];

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    setupEventListeners();
    fetchDashboardData();
    setInterval(fetchDashboardData, 5000); // 5-second polling interval
});

function initCharts() {
    // 1. Latency & Loss Time-Series Chart
    const ctx1 = document.getElementById('latencyLossChart').getContext('2d');
    latencyLossChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: historyLabels,
            datasets: [
                {
                    label: 'Avg Latency (ms)',
                    data: historyLatency,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    yAxisID: 'y',
                    tension: 0.35,
                    fill: true,
                    borderWidth: 2,
                    pointRadius: 2,
                },
                {
                    label: 'Packet Loss (%)',
                    data: historyLoss,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    yAxisID: 'y1',
                    tension: 0.35,
                    fill: true,
                    borderWidth: 2,
                    pointRadius: 2,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    grid: { color: '#1f2937' },
                    ticks: { color: '#9ca3af', font: { family: 'JetBrains Mono', size: 10 } }
                },
                y: {
                    type: 'linear',
                    position: 'left',
                    title: { display: true, text: 'Latency (ms)', color: '#3b82f6' },
                    grid: { color: '#1f2937' },
                    ticks: { color: '#9ca3af' },
                    min: 0
                },
                y1: {
                    type: 'linear',
                    position: 'right',
                    title: { display: true, text: 'Loss (%)', color: '#ef4444' },
                    grid: { drawOnChartArea: false },
                    ticks: { color: '#f87171' },
                    min: 0,
                    max: 100
                }
            },
            plugins: {
                legend: { labels: { color: '#f3f4f6', font: { family: 'Inter', size: 12 } } }
            }
        }
    });

    // 2. Protocol Distribution Doughnut Chart
    const ctx2 = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(ctx2, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
            datasets: [{
                data: [65, 20, 10, 4, 1],
                backgroundColor: ['#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#8b5cf6'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#f3f4f6', font: { family: 'Inter', size: 11 } }
                }
            },
            cutout: '70%'
        }
    });
}

function setupEventListeners() {
    // Manual diagnostic trigger
    document.getElementById('btnRunDiagnostic').addEventListener('click', runDiagnostic);

    // Fault injection trigger
    document.getElementById('btnInjectFault').addEventListener('click', injectFault);

    // Clear faults trigger
    document.getElementById('btnClearFaults').addEventListener('click', clearFaults);

    // Modal close
    document.getElementById('modalCloseBtn').addEventListener('click', () => {
        document.getElementById('incidentModal').classList.remove('open');
    });
}

async function fetchDashboardData() {
    try {
        // Fetch Health Grade
        const healthRes = await fetch('/api/health');
        if (healthRes.ok) {
            const health = await healthRes.json();
            updateHealthBadge(health);
        }

        // Fetch Latest Metrics
        const metricsRes = await fetch('/api/latest-metrics');
        if (metricsRes.ok) {
            const data = await metricsRes.json();
            updateMetricsView(data);
        }

        // Fetch Hop Data
        const hopsRes = await fetch('/api/hops/8.8.8.8');
        if (hopsRes.ok) {
            const hops = await hopsRes.json();
            updateHopsView(hops);
        }

        // Fetch Incidents
        const incRes = await fetch('/api/incidents?limit=10');
        if (incRes.ok) {
            const incidents = await incRes.json();
            updateIncidentsTimeline(incidents);
        }
    } catch (err) {
        console.warn('Dashboard telemetry poll warning:', err);
    }
}

function updateHealthBadge(health) {
    const circle = document.getElementById('healthGradeCircle');
    const desc = document.getElementById('healthDesc');
    const sub = document.getElementById('healthSub');

    circle.className = `grade-circle ${health.grade}`;
    circle.textContent = health.grade;
    desc.textContent = health.status_summary;
    sub.textContent = `Score: ${health.score}/100 | ${health.active_incidents} active incident(s)`;
}

function updateMetricsView(data) {
    const feat = data.features || {};

    document.getElementById('valLatency').textContent = `${feat.avg_latency || 0} ms`;
    document.getElementById('valLoss').textContent = `${feat.loss_pct || 0} %`;
    document.getElementById('valJitter').textContent = `${feat.jitter || 0} ms`;
    document.getElementById('valDns').textContent = `${feat.dns_latency || 0} ms`;
    document.getElementById('valRetrans').textContent = feat.retrans_count || 0;
    document.getElementById('valHttpStatus').textContent = feat.http_status_code || 200;

    // Update time-series line chart
    const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (historyLabels.length >= maxDataPoints) {
        historyLabels.shift();
        historyLatency.shift();
        historyLoss.shift();
    }
    historyLabels.push(nowStr);
    historyLatency.push(feat.avg_latency || 0);
    historyLoss.push(feat.loss_pct || 0);
    latencyLossChart.update('none');

    // Update protocol chart if stats are provided
    if (data.passive_stats && data.passive_stats.protocols) {
        const p = data.passive_stats.protocols;
        const total = (p.TCP || 0) + (p.UDP || 0) + (p.ICMP || 0) + (p.ARP || 0) + (p.OTHER || 0);
        if (total > 0) {
            protocolChart.data.datasets[0].data = [p.TCP || 0, p.UDP || 0, p.ICMP || 0, p.ARP || 0, p.OTHER || 0];
            protocolChart.update('none');
        }
    }
}

function updateHopsView(hopData) {
    const tbody = document.getElementById('hopsTableBody');
    const hops = hopData.hops || [];
    tbody.innerHTML = '';

    if (hops.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #6b7280;">No hops recorded yet</td></tr>';
        return;
    }

    hops.forEach(h => {
        const tr = document.createElement('tr');
        const lossClass = h.loss_pct > 20 ? 'style="color: #ef4444; font-weight: bold;"' : '';
        tr.innerHTML = `
            <td>#${h.hop_number}</td>
            <td>${h.ip}</td>
            <td>${h.rtt_ms} ms</td>
            <td ${lossClass}>${h.loss_pct}%</td>
        `;
        tbody.appendChild(tr);
    });

    const confBadge = document.getElementById('hopConfidenceBadge');
    if (confBadge && hopData.hop_analysis) {
        const ha = hopData.hop_analysis;
        confBadge.className = `confidence-badge ${ha.hop_confidence}`;
        confBadge.textContent = `${ha.hop_location} (${ha.hop_confidence} Confidence)`;
    }
}

function updateIncidentsTimeline(incidents) {
    const list = document.getElementById('incidentsList');
    list.innerHTML = '';

    if (!incidents || incidents.length === 0) {
        list.innerHTML = '<div style="padding: 1rem; color: #9ca3af; text-align: center;">No network failures detected. Baseline is healthy.</div>';
        return;
    }

    incidents.forEach(inc => {
        const item = document.createElement('div');
        item.className = 'incident-item';
        item.onclick = () => openIncidentReport(inc.id);

        const timeStr = new Date(inc.timestamp * 1000).toLocaleTimeString();
        item.innerHTML = `
            <div class="incident-info">
                <div class="incident-badge-circle" style="background: ${inc.status === 'RESOLVED' ? '#10b981' : '#ef4444'}"></div>
                <div>
                    <div class="incident-cause">${inc.probable_cause}</div>
                    <div class="incident-meta">${inc.symptom} • ${timeStr}</div>
                </div>
            </div>
            <div style="text-align: right;">
                <span class="confidence-badge ${inc.hop_confidence}">${(inc.confidence_score * 100).toFixed(0)}% Conf.</span>
                <span style="font-size: 0.8rem; color: #3b82f6; margin-left: 0.5rem;">View Report →</span>
            </div>
        `;
        list.appendChild(item);
    });
}

async function openIncidentReport(incidentId) {
    try {
        const res = await fetch(`/api/incidents/${incidentId}`);
        if (!res.ok) return;
        const inc = await res.json();
        const ev = inc.evidence || {};

        const content = document.getElementById('modalBody');
        content.innerHTML = `
            <div style="border-bottom: 1px solid #374151; padding-bottom: 1rem; margin-bottom: 1rem;">
                <span style="font-size: 0.75rem; color: #9ca3af; text-transform: uppercase; font-family: monospace;">INCIDENT #${inc.id}</span>
                <h2 style="font-size: 1.4rem; color: #f3f4f6; margin-top: 0.25rem;">${inc.probable_cause}</h2>
                <p style="color: #f87171; font-weight: 500; margin-top: 0.25rem;">${inc.symptom}</p>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; background: #1f2937; padding: 1rem; border-radius: 8px;">
                <div>
                    <div style="font-size: 0.7rem; color: #9ca3af; text-transform: uppercase;">Affected OSI Layer</div>
                    <div style="font-weight: 600; color: #60a5fa;">${inc.affected_layer}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; color: #9ca3af; text-transform: uppercase;">Hop Attribution</div>
                    <div style="font-weight: 600;">${inc.hop_location}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; color: #9ca3af; text-transform: uppercase;">Confidence Level</div>
                    <div style="font-weight: 700; color: #10b981;">${(inc.confidence_score * 100).toFixed(1)}% (${inc.hop_confidence})</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; color: #9ca3af; text-transform: uppercase;">Status</div>
                    <div style="font-weight: 600; color: ${inc.status === 'RESOLVED' ? '#34d399' : '#f87171'};">${inc.status}</div>
                </div>
            </div>

            <div style="background: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; padding: 1rem; border-radius: 0 6px 6px 0; margin-bottom: 1.5rem;">
                <div style="font-weight: 600; color: #93c5fd; margin-bottom: 0.25rem;">Prescribed Remediation</div>
                <div style="font-size: 0.9rem; color: #e5e7eb;">${inc.remediation_text}</div>
            </div>

            <div style="display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 1.5rem;">
                <a href="/incidents/${inc.id}/view" target="_blank" class="btn btn-primary">Open Dedicated HTML Post-Mortem ↗</a>
            </div>
        `;
        document.getElementById('incidentModal').classList.add('open');
    } catch (err) {
        console.error('Error opening incident modal:', err);
    }
}

async function runDiagnostic() {
    showBanner('Running full active network probe and diagnostic engine cycle...', 'info');
    try {
        const res = await fetch('/api/run-diagnostic', { method: 'POST' });
        if (res.ok) {
            const data = await res.json();
            showBanner(`Diagnostic completed in ${data.cycle_duration_ms}ms. ${data.incidents_generated.length} incident(s) evaluated.`, 'info');
            fetchDashboardData();
        }
    } catch (err) {
        showBanner('Diagnostic execution failed: ' + err, 'alert');
    }
}

async function injectFault() {
    const faultType = document.getElementById('selectFaultType').value;
    showBanner(`Injecting test network fault: ${faultType}...`, 'alert');
    try {
        const res = await fetch('/api/inject-fault', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fault_type: faultType })
        });
        if (res.ok) {
            const data = await res.json();
            showBanner(`Fault '${faultType}' applied. Diagnostic engine will analyze degradation.`, 'alert');
            fetchDashboardData();
        }
    } catch (err) {
        showBanner('Fault injection failed: ' + err, 'alert');
    }
}

async function clearFaults() {
    try {
        const res = await fetch('/api/clear-faults', { method: 'POST' });
        if (res.ok) {
            showBanner('All injected faults cleared. Returning to healthy baseline.', 'info');
            fetchDashboardData();
        }
    } catch (err) {
        showBanner('Failed clearing faults: ' + err, 'alert');
    }
}

function showBanner(msg, type) {
    const b = document.getElementById('statusBanner');
    b.textContent = msg;
    b.className = `status-banner show ${type}`;
    setTimeout(() => {
        b.className = 'status-banner';
    }, 6000);
}
