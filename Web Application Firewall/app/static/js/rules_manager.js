// ModSecurity Rule Set Manager Logic

let allRules = [];
let currentCategory = 'all';

document.addEventListener('DOMContentLoaded', () => {
    loadRules();

    // Search input
    document.getElementById('rule-search-input')?.addEventListener('input', filterAndRenderRules);

    // Category pills
    document.querySelectorAll('.cat-pill').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.cat-pill').forEach(p => {
                p.className = 'cat-pill px-3 py-1.5 rounded-xl font-medium transition bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800';
            });
            btn.className = 'cat-pill px-3 py-1.5 rounded-xl font-medium transition bg-cyan-500/20 text-cyan-300 border border-cyan-500/40';
            currentCategory = btn.getAttribute('data-cat');
            filterAndRenderRules();
        });
    });

    // Custom Rule Modal
    const modal = document.getElementById('custom-rule-modal');
    document.getElementById('open-custom-rule-modal-btn')?.addEventListener('click', () => {
        modal.classList.remove('hidden');
    });
    document.getElementById('close-modal-btn')?.addEventListener('click', () => {
        modal.classList.add('hidden');
    });
    document.getElementById('cancel-modal-btn')?.addEventListener('click', () => {
        modal.classList.add('hidden');
    });

    // View Modal
    const viewModal = document.getElementById('view-rule-modal');
    document.getElementById('close-view-modal-btn')?.addEventListener('click', () => {
        viewModal.classList.add('hidden');
    });

    // Submit Custom Rule
    document.getElementById('submit-custom-rule-btn')?.addEventListener('click', async () => {
        const directive = document.getElementById('custom-directive-input').value.trim();
        if (!directive) return;

        try {
            const res = await fetch('/api/rules/custom', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directive })
            });
            const data = await res.json();
            if (data.success) {
                showToast(`Custom Rule #${data.rule_id} injected!`, 'success');
                modal.classList.add('hidden');
                loadRules();
            } else {
                showToast(data.error || 'Failed to add rule', 'error');
            }
        } catch (err) {
            showToast('Error adding rule: ' + err.message, 'error');
        }
    });
});

async function loadRules() {
    try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        allRules = data.rules || [];
        document.getElementById('total-rules-count').innerText = allRules.length;
        filterAndRenderRules();
    } catch (err) {
        console.error('Error loading rules:', err);
    }
}

function filterAndRenderRules() {
    const search = (document.getElementById('rule-search-input')?.value || '').toLowerCase().trim();
    const tbody = document.getElementById('rules-tbody');

    const filtered = allRules.filter(r => {
        const matchesCat = (currentCategory === 'all' || r.category === currentCategory);
        const matchesSearch = !search ||
            r.id.toString().includes(search) ||
            r.msg.toLowerCase().includes(search) ||
            r.variables.toLowerCase().includes(search) ||
            r.category.toLowerCase().includes(search);
        return matchesCat && matchesSearch;
    });

    document.getElementById('visible-rules-count').innerText = filtered.length;

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="py-8 text-center text-slate-500 font-sans">
                    No matching ModSecurity rules found for this query.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = filtered.map(r => {
        const sevClass = r.severity === 'CRITICAL'
            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
            : (r.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-slate-800 text-slate-400');

        return `
            <tr class="hover:bg-slate-800/40 transition">
                <td class="py-3 px-4">
                    <label class="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRule(${r.id}, this.checked)" class="sr-only peer">
                        <div class="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-emerald-500"></div>
                    </label>
                </td>
                <td class="py-3 px-4 text-cyan-400 font-bold">#${r.id}</td>
                <td class="py-3 px-4 font-sans text-slate-300">${r.category}</td>
                <td class="py-3 px-4">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevClass}">${r.severity}</span>
                </td>
                <td class="py-3 px-4 text-slate-400">P${r.phase}</td>
                <td class="py-3 px-4 text-slate-300 truncate max-w-xs" title="${r.variables}">${r.variables}</td>
                <td class="py-3 px-4 font-sans text-slate-300 max-w-sm truncate" title="${r.msg}">${r.msg}</td>
                <td class="py-3 px-4 text-amber-400 font-bold">+${r.points}</td>
                <td class="py-3 px-4 text-right">
                    <button onclick="inspectRule(${r.id})" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-sans transition">
                        View
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

async function toggleRule(ruleId, enabled) {
    try {
        const res = await fetch(`/api/rules/${ruleId}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Rule #${ruleId} ${enabled ? 'enabled' : 'disabled'}`, 'info');
            const target = allRules.find(r => r.id === ruleId);
            if (target) target.enabled = enabled;
        }
    } catch (err) {
        showToast('Error toggling rule: ' + err.message, 'error');
    }
}

function inspectRule(ruleId) {
    const rule = allRules.find(r => r.id === ruleId);
    if (!rule) return;

    document.getElementById('view-rule-id').innerText = `#${rule.id}`;
    document.getElementById('view-rule-content').innerText = rule.raw_directive || `SecRule ${rule.variables} "${rule.operator} ${rule.pattern}" "id:${rule.id},phase:${rule.phase},msg:'${rule.msg}',severity:'${rule.severity}'"`;
    document.getElementById('view-rule-modal').classList.remove('hidden');
}
