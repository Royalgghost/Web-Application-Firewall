// Dashboard Logic & Chart Telemetry

let attackChart = null;
let trafficChart = null;

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    loadDashboardData();

    // Event listeners
    const refreshBtn = document.getElementById('refresh-stats-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', loadDashboardData);

    const thresholdSlider = document.getElementById('ctrl-threshold');
    const thresholdVal = document.getElementById('ctrl-threshold-val');
    if (thresholdSlider && thresholdVal) {
        thresholdSlider.addEventListener('input', (e) => {
            thresholdVal.innerText = `${e.target.value} pts`;
        });
    }

    const saveConfigBtn = document.getElementById('save-config-btn');
    if (saveConfigBtn) {
        saveConfigBtn.addEventListener('click', async () => {
            const engine_mode = document.getElementById('ctrl-engine-mode').value;
            const blocking_mode = document.getElementById('ctrl-blocking-mode').value;
            const threshold = parseInt(document.getElementById('ctrl-threshold').value);

            try {
                const res = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ engine_mode, blocking_mode, threshold })
                });
                const data = await res.json();
                showToast('WAF configuration updated successfully!', 'success');
                fetchConfig(); // update global header
                loadDashboardData();
            } catch (err) {
                showToast('Failed to save WAF configuration', 'error');
            }
        });
    }
});

function initCharts() {
    const attackCtx = document.getElementById('attack-chart')?.getContext('2d');
    if (attackCtx) {
        attackChart = new Chart(attackCtx, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'RCE', 'LFI', 'SSRF', 'Scanners', 'Protocol'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#ef4444', // red
                        '#f97316', // orange
                        '#8b5cf6', // purple
                        '#eab308', // yellow
                        '#3b82f6', // blue
                        '#06b6d4', // cyan
                        '#64748b'  // slate
                    ],
                    borderWidth: 2,
                    borderColor: '#0f172a'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 10 }
                    }
                },
                cutout: '70%'
            }
        });
    }

    const trafficCtx = document.getElementById('traffic-chart')?.getContext('2d');
    if (trafficCtx) {
        trafficChart = new Chart(trafficCtx, {
            type: 'bar',
            data: {
                labels: ['Allowed (200 OK)', 'Blocked (403 Forbidden)'],
                datasets: [{
                    label: 'Requests',
                    data: [0, 0],
                    backgroundColor: ['#10b981', '#ef4444'],
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#94a3b8', stepSize: 1 },
                        grid: { color: '#1e293b' }
                    },
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { display: false }
                    }
                }
            }
        });
    }
}

async function loadDashboardData() {
    try {
        // Fetch stats
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();

        // Update KPIs
        document.getElementById('stat-total').innerText = stats.total_requests;
        document.getElementById('stat-blocked').innerText = stats.blocked_requests;
        document.getElementById('stat-allowed').innerText = stats.allowed_requests;
        document.getElementById('stat-rate').innerText = `${stats.block_rate}%`;
        document.getElementById('stat-rules').innerText = stats.active_rules_count;

        // Sync control inputs
        const modeSelect = document.getElementById('ctrl-engine-mode');
        if (modeSelect) modeSelect.value = stats.engine_mode;

        const blockSelect = document.getElementById('ctrl-blocking-mode');
        if (blockSelect) blockSelect.value = stats.blocking_mode;

        const threshInput = document.getElementById('ctrl-threshold');
        const threshVal = document.getElementById('ctrl-threshold-val');
        if (threshInput && threshVal) {
            threshInput.value = stats.threshold;
            threshVal.innerText = `${stats.threshold} pts`;
        }

        // Update Attack Distribution Chart
        if (attackChart && stats.attack_categories) {
            const cat = stats.attack_categories;
            const values = [
                cat['SQL Injection'] || 0,
                cat['Cross-Site Scripting (XSS)'] || 0,
                cat['Remote Code Execution (RCE)'] || 0,
                cat['Local File Inclusion (LFI)'] || 0,
                cat['SSRF'] || 0,
                cat['Scanner Detection'] || 0,
                cat['Protocol Enforcement'] || 0
            ];
            // If all 0, provide placeholder visuals
            const hasData = values.some(v => v > 0);
            attackChart.data.datasets[0].data = hasData ? values : [1, 1, 1, 1, 1, 1, 1];
            attackChart.data.datasets[0].backgroundColor = hasData ? [
                '#ef4444', '#f97316', '#8b5cf6', '#eab308', '#3b82f6', '#06b6d4', '#64748b'
            ] : Array(7).fill('#1e293b');
            attackChart.update();
        }

        // Update Traffic Chart
        if (trafficChart) {
            trafficChart.data.datasets[0].data = [stats.allowed_requests, stats.blocked_requests];
            trafficChart.update();
        }

        // Fetch recent logs
        const logsRes = await fetch('/api/logs?limit=8');
        const logsData = await logsRes.json();
        renderThreatStream(logsData.logs || []);

    } catch (err) {
        console.error('Error loading dashboard data:', err);
    }
}

function renderThreatStream(logs) {
    const tbody = document.getElementById('recent-threats-tbody');
    if (!tbody) return;

    if (logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="py-8 text-center text-slate-500 font-sans">
                    <i class="fa-solid fa-radar text-2xl mb-2 block"></i>
                    No requests captured yet. Send requests using the <a href="/simulator" class="text-cyan-400 underline">Attack Sandbox</a>.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = logs.map(log => {
        const statusBadge = log.is_blocked
            ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">403 BLOCKED</span>`
            : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">200 ALLOWED</span>`;

        const scoreColor = log.anomaly_score >= 5 ? 'text-red-400 font-bold' : (log.anomaly_score > 0 ? 'text-amber-400' : 'text-slate-400');

        const rulesList = log.matched_rules && log.matched_rules.length > 0
            ? log.matched_rules.map(r => `<span class="inline-block bg-slate-800 text-slate-200 px-1.5 py-0.5 rounded text-[10px] mr-1 mb-1 border border-slate-700" title="${r.message}">#${r.rule_id}</span>`).join('')
            : '<span class="text-slate-500 text-[10px] font-sans">None</span>';

        return `
            <tr class="hover:bg-slate-800/40 transition">
                <td class="py-3 px-4">${statusBadge}</td>
                <td class="py-3 px-4 text-slate-400 text-[11px]">${log.timestamp}</td>
                <td class="py-3 px-4">
                    <span class="text-cyan-400 font-bold">${log.method}</span>
                    <span class="text-slate-200 ml-1 truncate max-w-xs inline-block align-bottom" title="${log.uri}">${log.uri}</span>
                </td>
                <td class="py-3 px-4 text-slate-300 text-[11px]">${log.client_ip}</td>
                <td class="py-3 px-4 ${scoreColor}">${log.anomaly_score} pts</td>
                <td class="py-3 px-4 max-w-xs">${rulesList}</td>
            </tr>
        `;
    }).join('');
}
