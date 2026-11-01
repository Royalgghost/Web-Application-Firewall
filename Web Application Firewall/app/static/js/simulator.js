// Attack Sandbox & Request Simulator Logic

const PRESETS = {
    // SQL Injection
    sqli_boolean: {
        method: 'POST',
        uri: '/login',
        client_ip: '198.51.100.4',
        headers: 'Host: app.local\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nContent-Type: application/x-www-form-urlencoded',
        body: "username=admin' OR 1=1 --&password=anything"
    },
    sqli_union: {
        method: 'GET',
        uri: '/search?q=smartphones%20UNION%20SELECT%20null,username,password%20FROM%20users',
        client_ip: '198.51.100.4',
        headers: 'Host: app.local\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: text/html',
        body: ''
    },
    sqli_sleep: {
        method: 'GET',
        uri: '/products?id=12+AND+(SELECT+SLEEP(5))',
        client_ip: '198.51.100.12',
        headers: 'Host: app.local\nUser-Agent: Mozilla/5.0',
        body: ''
    },
    sqli_stacked: {
        method: 'POST',
        uri: '/api/items',
        client_ip: '198.51.100.20',
        headers: 'Host: app.local\nContent-Type: application/x-www-form-urlencoded',
        body: 'name=TestItem;+DROP+TABLE+users'
    },

    // Cross-Site Scripting (XSS)
    xss_script: {
        method: 'GET',
        uri: '/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E',
        client_ip: '203.0.113.88',
        headers: 'Host: app.local\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        body: ''
    },
    xss_onerror: {
        method: 'POST',
        uri: '/comments',
        client_ip: '203.0.113.90',
        headers: 'Host: app.local\nContent-Type: application/x-www-form-urlencoded',
        body: 'comment=<img+src="x"+onerror="alert(1)">'
    },
    xss_svg: {
        method: 'POST',
        uri: '/profile/update',
        client_ip: '203.0.113.95',
        headers: 'Host: app.local\nContent-Type: application/x-www-form-urlencoded',
        body: 'bio=<svg+onload=eval("alert(1)")>'
    },
    xss_uri: {
        method: 'GET',
        uri: '/redirect?target=javascript:alert(window.origin)',
        client_ip: '203.0.113.99',
        headers: 'Host: app.local',
        body: ''
    },

    // Remote Code Execution (RCE)
    rce_semicolon: {
        method: 'POST',
        uri: '/ping',
        client_ip: '192.0.2.14',
        headers: 'Host: app.local\nContent-Type: application/x-www-form-urlencoded',
        body: 'ip=127.0.0.1;+whoami'
    },
    rce_pipe: {
        method: 'POST',
        uri: '/ping',
        client_ip: '192.0.2.16',
        headers: 'Host: app.local\nContent-Type: application/x-www-form-urlencoded',
        body: 'ip=127.0.0.1|+cat+/etc/passwd'
    },
    rce_powershell: {
        method: 'GET',
        uri: '/exec?cmd=powershell+-ExecutionPolicy+Bypass+-command+Get-Process',
        client_ip: '192.0.2.18',
        headers: 'Host: app.local',
        body: ''
    },

    // Local File Inclusion (LFI)
    lfi_passwd: {
        method: 'GET',
        uri: '/view-file?file=../../../../etc/passwd',
        client_ip: '198.51.100.55',
        headers: 'Host: app.local',
        body: ''
    },
    lfi_win_ini: {
        method: 'GET',
        uri: '/view-file?file=..\\..\\windows\\win.ini',
        client_ip: '198.51.100.56',
        headers: 'Host: app.local',
        body: ''
    },
    lfi_php_filter: {
        method: 'GET',
        uri: '/view-file?file=php://filter/convert.base64-encode/resource=index.php',
        client_ip: '198.51.100.57',
        headers: 'Host: app.local',
        body: ''
    },

    // SSRF & Scanners
    ssrf_metadata: {
        method: 'GET',
        uri: '/fetch-url?url=http://169.254.169.254/latest/meta-data/',
        client_ip: '203.0.113.12',
        headers: 'Host: app.local',
        body: ''
    },
    scanner_sqlmap: {
        method: 'GET',
        uri: '/login.php?id=1',
        client_ip: '198.51.100.250',
        headers: 'Host: app.local\nUser-Agent: sqlmap/1.6.4#stable (http://sqlmap.org)\nAccept: */*',
        body: ''
    },
    scanner_nikto: {
        method: 'GET',
        uri: '/test.cgi',
        client_ip: '198.51.100.251',
        headers: 'Host: app.local\nUser-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)',
        body: ''
    },

    // Benign
    benign_search: {
        method: 'GET',
        uri: '/search?q=wireless+noise+cancelling+headphones',
        client_ip: '192.168.1.100',
        headers: 'Host: app.local\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: text/html',
        body: ''
    },
    benign_login: {
        method: 'POST',
        uri: '/login',
        client_ip: '192.168.1.100',
        headers: 'Host: app.local\nUser-Agent: Mozilla/5.0\nContent-Type: application/x-www-form-urlencoded',
        body: 'username=alice&password=SuperSecurePassword123!'
    },
    benign_json: {
        method: 'POST',
        uri: '/api/profile',
        client_ip: '192.168.1.100',
        headers: 'Host: app.local\nContent-Type: application/json',
        body: '{\n  "name": "Jane Doe",\n  "role": "Software Engineer",\n  "department": "Security"\n}'
    }
};

document.addEventListener('DOMContentLoaded', () => {
    // Preset selector change
    const presetSelector = document.getElementById('preset-selector');
    if (presetSelector) {
        presetSelector.addEventListener('change', (e) => {
            const key = e.target.value;
            if (key && PRESETS[key]) {
                loadPreset(PRESETS[key]);
            }
        });
    }

    // Body format buttons
    document.getElementById('body-format-form')?.addEventListener('click', () => {
        setBodyFormat('application/x-www-form-urlencoded');
    });
    document.getElementById('body-format-json')?.addEventListener('click', () => {
        setBodyFormat('application/json');
    });
    document.getElementById('body-format-clear')?.addEventListener('click', () => {
        document.getElementById('req-body').value = '';
    });

    // Reset button
    document.getElementById('reset-req-btn')?.addEventListener('click', () => {
        document.getElementById('req-method').value = 'GET';
        document.getElementById('req-uri').value = '/';
        document.getElementById('req-client-ip').value = '192.168.1.100';
        document.getElementById('req-headers').value = 'Host: app.local\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
        document.getElementById('req-body').value = '';
        if (presetSelector) presetSelector.value = '';
    });

    // Send Request button
    document.getElementById('send-request-btn')?.addEventListener('click', sendSimulationRequest);

    // Copy audit log
    document.getElementById('copy-audit-log-btn')?.addEventListener('click', () => {
        const text = document.getElementById('raw-audit-log-pre')?.innerText;
        if (text) {
            navigator.clipboard.writeText(text);
            showToast('SecAuditLog copied to clipboard!', 'success');
        }
    });
});

function loadPreset(preset) {
    document.getElementById('req-method').value = preset.method;
    document.getElementById('req-uri').value = preset.uri;
    document.getElementById('req-client-ip').value = preset.client_ip;
    document.getElementById('req-headers').value = preset.headers;
    document.getElementById('req-body').value = preset.body;
    showToast(`Loaded preset payload`, 'info');
}

function setBodyFormat(contentType) {
    const headersArea = document.getElementById('req-headers');
    let lines = headersArea.value.split('\n').filter(l => !l.toLowerCase().startsWith('content-type:'));
    lines.push(`Content-Type: ${contentType}`);
    headersArea.value = lines.join('\n');
}

async function sendSimulationRequest() {
    const sendBtn = document.getElementById('send-request-btn');
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Inspecting Request...';

    const method = document.getElementById('req-method').value;
    const uri = document.getElementById('req-uri').value.trim();
    const client_ip = document.getElementById('req-client-ip').value.trim();
    const rawHeaders = document.getElementById('req-headers').value;
    const body = document.getElementById('req-body').value;

    // Parse headers string into dictionary
    const headers = {};
    rawHeaders.split('\n').forEach(line => {
        const idx = line.indexOf(':');
        if (idx !== -1) {
            const k = line.substring(0, idx).trim();
            const v = line.substring(idx + 1).trim();
            if (k) headers[k] = v;
        }
    });

    const payload = { method, uri, client_ip, headers, body };

    try {
        const res = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        renderInspectionResult(data);
    } catch (err) {
        showToast('Error during simulation request: ' + err.message, 'error');
    } finally {
        sendBtn.disabled = false;
        sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send & Inspect Through ModSecurity';
    }
}

function renderInspectionResult(data) {
    document.getElementById('idle-placeholder')?.classList.add('hidden');
    const activeResult = document.getElementById('active-result');
    activeResult.classList.remove('hidden');

    // 1. Status Banner
    const banner = document.getElementById('status-banner');
    const icon = document.getElementById('status-icon');
    const tag = document.getElementById('status-tag');
    const title = document.getElementById('status-title');
    const txId = document.getElementById('tx-id-badge');
    const execTime = document.getElementById('exec-time');

    txId.innerText = `TxID: ${data.transaction_id}`;
    execTime.innerText = `${data.execution_time_ms} ms`;

    if (data.is_blocked) {
        banner.className = 'p-4 rounded-xl border border-red-500/40 bg-red-950/40 flex items-center justify-between';
        icon.className = 'w-12 h-12 rounded-xl bg-red-500/20 text-red-400 border border-red-500/40 flex items-center justify-center text-xl';
        icon.innerHTML = '<i class="fa-solid fa-shield-virus"></i>';
        tag.className = 'text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30';
        tag.innerText = `HTTP ${data.status} FORBIDDEN`;
        title.innerText = 'Threat Intercepted & Blocked by ModSecurity';
    } else {
        banner.className = 'p-4 rounded-xl border border-emerald-500/40 bg-emerald-950/40 flex items-center justify-between';
        icon.className = 'w-12 h-12 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center text-xl';
        icon.innerHTML = '<i class="fa-solid fa-shield-check"></i>';
        tag.className = 'text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
        tag.innerText = `HTTP ${data.status} ALLOWED`;
        title.innerText = data.engine_mode === 'Off' ? 'WAF Disabled: Request Bypassed' : 'Clean Traffic: Passed Inspection';
    }

    // 2. Anomaly Score Progress & Breakdown
    const meterText = document.getElementById('score-meter-text');
    const progressBar = document.getElementById('score-progress-bar');
    const breakdownEl = document.getElementById('score-breakdown');

    const score = data.anomaly_score;
    const threshold = data.threshold;
    meterText.innerText = `${score} pts / ${threshold} (Threshold)`;

    const pct = Math.min(100, Math.round((score / Math.max(threshold, 1)) * 100));
    progressBar.style.width = `${pct}%`;

    if (score >= threshold) {
        progressBar.className = 'h-full rounded-full transition-all duration-500 bg-red-500 shadow-lg shadow-red-500/50';
        meterText.className = 'text-xs font-mono font-bold text-red-400';
    } else if (score > 0) {
        progressBar.className = 'h-full rounded-full transition-all duration-500 bg-amber-500 shadow-lg shadow-amber-500/50';
        meterText.className = 'text-xs font-mono font-bold text-amber-400';
    } else {
        progressBar.className = 'h-full rounded-full transition-all duration-500 bg-emerald-500';
        meterText.className = 'text-xs font-mono font-bold text-emerald-400';
    }

    // Category breakdown badges
    const b = data.breakdown || {};
    breakdownEl.innerHTML = `
        <span class="px-2 py-1 rounded bg-slate-900 border border-slate-800 ${b.sqli ? 'text-red-400 border-red-500/40' : 'text-slate-500'}">SQLi: +${b.sqli || 0}</span>
        <span class="px-2 py-1 rounded bg-slate-900 border border-slate-800 ${b.xss ? 'text-orange-400 border-orange-500/40' : 'text-slate-500'}">XSS: +${b.xss || 0}</span>
        <span class="px-2 py-1 rounded bg-slate-900 border border-slate-800 ${b.rce ? 'text-purple-400 border-purple-500/40' : 'text-slate-500'}">RCE: +${b.rce || 0}</span>
        <span class="px-2 py-1 rounded bg-slate-900 border border-slate-800 ${b.lfi ? 'text-yellow-400 border-yellow-500/40' : 'text-slate-500'}">LFI: +${b.lfi || 0}</span>
        <span class="px-2 py-1 rounded bg-slate-900 border border-slate-800 ${b.ssrf ? 'text-blue-400 border-blue-500/40' : 'text-slate-500'}">SSRF: +${b.ssrf || 0}</span>
    `;

    // 3. Pipeline Steps Trace
    const pipelineContainer = document.getElementById('pipeline-steps-container');
    pipelineContainer.innerHTML = '';

    (data.trace_steps || []).forEach((step, idx) => {
        const stepDiv = document.createElement('div');
        stepDiv.className = 'pipeline-step bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs';

        let badgeClass = 'bg-slate-800 text-slate-300';
        let stepIcon = 'fa-check text-emerald-400';

        if (step.status === 'blocked') {
            badgeClass = 'bg-red-500/20 text-red-400 border border-red-500/30';
            stepIcon = 'fa-ban text-red-400';
        } else if (step.status === 'warning') {
            badgeClass = 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
            stepIcon = 'fa-triangle-exclamation text-amber-400';
        }

        let matchesHtml = '';
        if (step.matches && step.matches.length > 0) {
            matchesHtml = `
                <div class="mt-2 space-y-1.5 pl-4 border-l-2 border-red-500/40">
                    ${step.matches.map(m => `
                        <div class="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
                            <div class="flex items-center justify-between font-mono text-[11px] mb-1">
                                <span class="text-amber-400 font-bold">Rule [${m.rule_id}]</span>
                                <span class="text-red-400 font-bold">+${m.score} pts</span>
                            </div>
                            <p class="text-slate-300 text-[11px]">${m.msg}</p>
                            <div class="text-[10px] text-slate-500 font-mono mt-0.5">Target: ${m.target}</div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        stepDiv.innerHTML = `
            <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2">
                    <i class="fa-solid ${stepIcon}"></i>
                    <span class="font-bold text-slate-200">${step.phase}</span>
                </div>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${badgeClass}">${step.status}</span>
            </div>
            <p class="text-slate-400 mt-1">${step.title || step.details || ''}</p>
            ${matchesHtml}
        `;
        pipelineContainer.appendChild(stepDiv);
    });

    // 4. Raw SecAuditLog
    const auditPre = document.getElementById('raw-audit-log-pre');
    auditPre.innerText = data.sec_audit_log || 'No audit log generated.';
}
