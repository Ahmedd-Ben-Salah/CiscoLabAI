/**
 * CiscoLabAI — Frontend Application Logic v2
 * 
 * Handles:
 * - File upload (drag & drop + click)
 * - API communication with Flask backend
 * - vis.js topology graph rendering
 * - Per-device config display with syntax highlighting
 * - Settings management (AI provider, API key)
 * - Lab history (localStorage)
 * - Toast notifications
 */

const API_BASE = '';  // Same origin

// ═══════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════

const state = {
    sessionId: null,
    mode: 'config_only',
    filename: null,
    devices: [],
    connections: [],
    instructions: '',
    aiSolution: null,
    settings: {
        provider: '',
        model: '',
        apiKey: '',
        ollamaUrl: 'http://localhost:11434',
    },
    providers: {},
    networkInstance: null,
};

// ═══════════════════════════════════════════════════════════════
//  INITIALIZATION
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    loadProviders();
    setupEventListeners();
    loadHistory();
});

function setupEventListeners() {
    // Upload
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    
    uploadZone.addEventListener('click', () => fileInput.click());
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('drag-over');
    });
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length) handleFileUpload(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleFileUpload(e.target.files[0]);
    });



    // Settings modal
    document.getElementById('btn-settings').addEventListener('click', openSettings);
    document.getElementById('btn-close-settings').addEventListener('click', closeSettings);
    document.getElementById('btn-save-settings').addEventListener('click', saveSettingsFromModal);
    document.querySelector('#settings-modal .modal-overlay').addEventListener('click', closeSettings);

    // Provider change
    document.getElementById('select-provider').addEventListener('change', onProviderChange);

    // API key toggle visibility
    document.getElementById('btn-toggle-key').addEventListener('click', () => {
        const input = document.getElementById('input-api-key');
        input.type = input.type === 'password' ? 'text' : 'password';
    });

    // History modal
    document.getElementById('btn-history').addEventListener('click', openHistory);
    document.getElementById('btn-close-history').addEventListener('click', closeHistory);
    document.querySelector('#history-modal .modal-overlay').addEventListener('click', closeHistory);

    // Remarks toggle
    document.getElementById('btn-toggle-remarks').addEventListener('click', () => {
        const wrap = document.getElementById('remarks-wrap');
        const btn = document.getElementById('btn-toggle-remarks');
        const isHidden = wrap.classList.contains('hidden');
        wrap.classList.toggle('hidden');
        btn.classList.toggle('active', isHidden);
        if (isHidden) {
            document.getElementById('input-remarks').focus();
        }
    });

    // Actions
    document.getElementById('btn-solve').addEventListener('click', solveLab);
    document.getElementById('btn-auto-solve').addEventListener('click', autoSolveLab);
    document.getElementById('btn-apply').addEventListener('click', applyAndDownload);
    document.getElementById('btn-new-file').addEventListener('click', resetToUpload);

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeSettings();
            closeHistory();
        }
    });

    // Panel tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const targetId = e.currentTarget.getAttribute('data-tab');
            
            // Update buttons
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            e.currentTarget.classList.add('active');
            
            // Update contents
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(targetId).classList.add('active');
            
            // If audit tab clicked and we haven't loaded it yet, fetch it
            if (targetId === 'audit-tab' && !state.auditLoaded && state.sessionId) {
                loadAudit();
            }
            // Connectivity test always re-runs (reflects latest applied state)
            if (targetId === 'verify-tab' && state.sessionId) {
                loadVerify();
            }
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  CONNECTIVITY TEST (answer-key-independent oracle)
// ═══════════════════════════════════════════════════════════════

async function loadVerify() {
    if (!state.sessionId) {
        showToast('Upload a file first.', 'error');
        return;
    }
    const el = document.getElementById('verify-content');
    el.innerHTML = '<div class="placeholder-text"><p>Running connectivity simulation…</p></div>';
    try {
        const res = await fetch(`${API_BASE}/api/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: state.sessionId })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Verification failed');
        renderVerify(data.report);
    } catch (err) {
        el.innerHTML = `<div class="placeholder-text" style="color:var(--danger)"><p>Error: ${escapeHtml(err.message)}</p><button class="btn" style="margin-top:10px" onclick="loadVerify()">Try Again</button></div>`;
    }
}

function renderVerify(report) {
    const el = document.getElementById('verify-content');
    const s = report.summary || {};
    const reach = report.reachability || {};
    const inv = report.invariants || { findings: [], summary: {} };
    const verdict = report.verdict || 'WARN';
    const vColor = verdict === 'FAIL' ? 'var(--danger)' : (verdict === 'WARN' ? 'var(--warning)' : 'var(--success)');
    let html = '';

    html += `
        <div style="background: rgba(255,255,255,0.05); border: 1px solid ${vColor}; padding: 10px; border-radius: var(--radius-sm); margin-bottom: 14px;">
            <div style="font-weight:700; color:${vColor}; margin-bottom:6px;">VERIFICATION: ${verdict}</div>
            <div style="display:flex; gap:14px; flex-wrap:wrap; font-size:0.8rem;">
                ${s.tests_total ? `<span style="font-weight:700; color:${(s.tests_failed||0)===0?'var(--success)':'var(--danger)'};">tests ${s.tests_passed||0}/${s.tests_total} passed</span>` : ''}
                <span style="color:var(--success);">${s.reachable || 0} reachable</span>
                <span style="color:var(--danger);">${s.unreachable || 0} unreachable</span>
                <span style="color:var(--warning);">${s.uncertain || 0} uncertain</span>
                <span style="color:var(--danger);">${s.errors || 0} errors</span>
                <span style="color:var(--warning);">${s.warnings || 0} warnings</span>
                <span style="color:var(--text-dim);">${s.incomplete_endpoints || 0} incomplete</span>
                ${report.rubric && report.rubric.present ? `<span style="font-weight:700; color:${report.rubric.percent>=100?'var(--success)':(report.rubric.percent>=50?'var(--warning)':'var(--danger)')};">answer key ${report.rubric.percent}%</span>` : ''}
            </div>
        </div>`;

    // Answer key embedded in the .pka itself — exact expected values, highest precision.
    const rub = report.rubric;
    if (rub && rub.present) {
        const rc = rub.verdict === 'FAIL' ? 'var(--danger)' : (rub.verdict === 'WARN' ? 'var(--warning)' : 'var(--success)');
        html += `<div style="font-weight:600; margin:6px 0;">Answer key (embedded in the lab) — <span style="color:${rc};">${rub.earned_points}/${rub.possible_points} pts (${rub.percent}%)</span></div>`;
        html += `<div style="font-size:0.72rem; color:var(--text-dim); margin-bottom:6px;">Auto-checked ${rub.auto_checked_items} of ${rub.total_graded_items} graded items (hostname, interface IP/mask, VLANs, OSPF, static routes, default-gateway, DHCP); the rest aren't auto-verified yet.</div>`;
        if (!(rub.failures || []).length) {
            html += `<div style="padding:6px 8px; margin-bottom:4px; background:rgba(255,255,255,0.03); border-left:3px solid var(--success); border-radius:4px; font-size:0.8rem; color:var(--success);">✓ All auto-checked answer-key items match.</div>`;
        } else {
            rub.failures.forEach(r => {
                const where = escapeHtml(r.device + (r.interface ? (' ' + r.interface) : ''));
                html += `
                    <div style="padding:6px 8px; margin-bottom:4px; background:rgba(255,255,255,0.03); border-left:3px solid var(--danger); border-radius:4px; font-size:0.78rem;">
                        <span style="color:var(--danger); font-weight:700; margin-right:6px;">✗</span>
                        <span style="font-weight:500;">${where} — ${escapeHtml(r.attribute)}</span>
                        <div style="color:var(--text-dim); margin-top:2px; font-family:var(--font-mono);">expected ${escapeHtml(String(r.expected))} · got ${escapeHtml(String(r.actual))}</div>
                        ${r.feedback ? `<div style="color:var(--text-dim); margin-top:2px; font-style:italic;">→ ${escapeHtml(r.feedback)}</div>` : ''}
                    </div>`;
            });
        }
    }

    // Professor's tests (or auto connectivity tests) — the lab's success criteria.
    const obj = report.objective_tests;
    if (obj && (obj.results || []).length) {
        const title = obj.source === 'instructions'
            ? "Professor's tests (from the instructions)"
            : "Connectivity tests (auto — no explicit tests in instructions)";
        html += `<div style="font-weight:600; margin:6px 0;">${title} — ${obj.passed}/${obj.total} passed</div>`;
        (obj.results || []).forEach(t => {
            const c = t.status === 'pass' ? 'var(--success)' : (t.status === 'fail' ? 'var(--danger)' : 'var(--text-dim)');
            const mark = t.status === 'pass' ? '✓' : (t.status === 'fail' ? '✗' : '–');
            const dst = t.dst || 'network';
            html += `
                <div style="padding:6px 8px; margin-bottom:4px; background:rgba(255,255,255,0.03); border-left:3px solid ${c}; border-radius:4px; font-size:0.8rem;">
                    <span style="color:${c}; font-weight:700; margin-right:6px;">${mark}</span>
                    <span style="font-weight:500;">${escapeHtml(t.src)} → ${escapeHtml(dst)}</span>
                    <div style="color:var(--text-dim); margin-top:2px;">${escapeHtml(t.detail || '')}</div>
                    ${t.raw && obj.source === 'instructions' ? `<div style="color:var(--text-dim); margin-top:2px; font-style:italic;">“${escapeHtml(t.raw)}”</div>` : ''}
                </div>`;
        });
    }

    // Protocol consistency findings (VLAN/trunk/EtherChannel/STP/HSRP/DHCP/OSPF)
    if ((inv.findings || []).length) {
        html += `<div style="font-weight:600; margin:6px 0;">Protocol consistency</div>`;
        const order = { error: 0, warning: 1, info: 2 };
        const sorted = [...inv.findings].sort((a, b) => order[a.severity] - order[b.severity]);
        sorted.forEach(f => {
            const c = f.severity === 'error' ? 'var(--danger)' : (f.severity === 'warning' ? 'var(--warning)' : 'var(--text-dim)');
            const pre = f.preexisting
                ? `<span style="margin-left:6px; padding:0 5px; border:1px solid var(--text-dim); border-radius:3px; color:var(--text-dim); font-size:0.62rem;" title="Already present in the original lab — the professor's config, not introduced by the solver">PRE-EXISTING</span>`
                : '';
            html += `
                <div style="padding:6px 8px; margin-bottom:4px; background:rgba(255,255,255,0.03); border-left:3px solid ${c}; border-radius:4px; font-size:0.78rem;">
                    <span style="color:${c}; font-weight:700; text-transform:uppercase; font-size:0.68rem;">${f.severity}</span>
                    <span style="color:var(--text-dim); margin-left:6px;">[${escapeHtml(f.category)}]</span>${pre}
                    <div style="margin-top:2px;">${escapeHtml(f.message)}</div>
                    ${f.fix_hint ? `<div style="color:var(--text-dim); margin-top:2px; font-style:italic;">→ ${escapeHtml(f.fix_hint)}</div>` : ''}
                </div>`;
        });
    }

    // Endpoint config completeness
    html += `<div style="font-weight:600; margin:14px 0 6px;">Endpoint configuration</div>`;
    (reach.endpoint_status || []).forEach(e => {
        const ok = e.complete;
        const color = ok ? 'var(--success)' : 'var(--warning)';
        const detail = ok
            ? `${e.ip} / ${e.mask} → ${e.gw}`
            : `missing: ${e.missing.join(', ')}`;
        html += `
            <div style="display:flex; justify-content:space-between; padding:5px 8px; margin-bottom:4px; background:rgba(255,255,255,0.03); border-left:3px solid ${color}; border-radius:4px; font-size:0.8rem;">
                <span style="font-weight:500;">${escapeHtml(e.device)}</span>
                <span style="color:var(--text-dim); font-family:var(--font-mono);">${escapeHtml(detail)}</span>
            </div>`;
    });

    // Reachability results
    html += `<div style="font-weight:600; margin:14px 0 6px;">Host-to-host reachability</div>`;
    (reach.pairs || []).forEach(p => {
        const color = p.reachable ? (p.uncertain ? 'var(--warning)' : 'var(--success)') : 'var(--danger)';
        const mark = p.reachable ? (p.uncertain ? '?' : '✓') : '✗';
        html += `
            <div style="padding:5px 8px; margin-bottom:4px; background:rgba(255,255,255,0.03); border-left:3px solid ${color}; border-radius:4px; font-size:0.78rem;">
                <span style="color:${color}; font-weight:700; margin-right:6px;">${mark}</span>
                <span style="font-weight:500;">${escapeHtml(p.src)} → ${escapeHtml(p.dst)}</span>
                <div style="color:var(--text-dim); margin-top:2px;">${escapeHtml(p.reason)}</div>
            </div>`;
    });

    el.innerHTML = html;

    const badge = document.getElementById('verify-badge');
    if (badge) {
        badge.textContent = `${s.reachable || 0}/${(s.reachable || 0) + (s.unreachable || 0)}`;
        badge.className = '';
    }
}

// ═══════════════════════════════════════════════════════════════
//  FILE UPLOAD
// ═══════════════════════════════════════════════════════════════

async function handleFileUpload(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['pka', 'pkt'].includes(ext)) {
        showToast('Invalid file type. Please upload a .pka or .pkt file.', 'error');
        return;
    }

    const uploadZone = document.getElementById('upload-zone');
    uploadZone.classList.add('loading');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            body: formData,
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Upload failed');
        }

        // Store state
        state.sessionId = data.session_id;
        state.filename = data.filename;
        state.devices = data.devices;
        state.connections = data.connections;
        state.instructions = data.instructions;
        state.aiSolution = null;

        // Switch to workspace view
        showWorkspace(data);
        showToast(`Loaded ${data.filename} — ${data.device_count} devices, ${data.connection_count} connections`, 'success');

        // Save to history
        addToHistory(data.filename);

    } catch (err) {
        showToast(`Upload failed: ${err.message}`, 'error');
    } finally {
        uploadZone.classList.remove('loading');
    }
}

// ═══════════════════════════════════════════════════════════════
//  WORKSPACE
// ═══════════════════════════════════════════════════════════════

function showWorkspace(data) {
    document.getElementById('upload-section').classList.remove('visible');
    document.getElementById('upload-section').classList.add('hidden');
    document.getElementById('workspace').classList.remove('hidden');

    // File info bar
    document.getElementById('file-name').textContent = data.filename;
    document.getElementById('file-version').textContent = data.version || 'PKA';
    document.getElementById('file-devices-count').textContent = `${data.device_count} devices`;
    document.getElementById('file-connections-count').textContent = `${data.connection_count} links`;

    // Instructions
    renderInstructions(data.instructions);

    // Topology graph
    renderTopology(data.devices, data.connections);

    // Update Audit Badge
    const badge = document.getElementById('audit-badge');
    if (data.audit_summary) {
        const errors = data.audit_summary.total_errors || 0;
        if (errors > 0) {
            badge.textContent = errors;
            badge.classList.remove('badge-hidden');
            badge.style.background = 'var(--danger)';
        } else if (data.audit_summary.total_warnings > 0) {
            badge.textContent = data.audit_summary.total_warnings;
            badge.classList.remove('badge-hidden');
            badge.style.background = 'var(--warning)';
        } else {
            badge.classList.add('badge-hidden');
        }
    } else {
        badge.classList.add('badge-hidden');
    }
    
    // Reset audit tab state
    state.auditLoaded = false;
    document.getElementById('audit-content').innerHTML = `
        <div class="placeholder-text">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <p>Ready to validate network configuration</p>
            <button class="btn" style="margin-top: 15px;" onclick="loadAudit()">Run Full OSI Audit</button>
        </div>
    `;

    // Enable solve button (if settings are configured)
    updateSolveButton();

    // Reset config panel
    document.getElementById('config-tabs').innerHTML = '';
    document.getElementById('config-content').innerHTML = `
        <div class="placeholder-text">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.2">
                <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
            </svg>
            <p>Solve the lab to see device configurations</p>
        </div>`;
    document.getElementById('btn-apply').disabled = true;
    
    // Switch back to Instructions tab by default
    document.querySelector('.tab-btn[data-tab="instructions-tab"]').click();
}

function resetToUpload() {
    document.getElementById('workspace').classList.add('hidden');
    document.getElementById('upload-section').classList.remove('hidden');
    document.getElementById('upload-section').classList.add('visible');
    state.sessionId = null;
    state.aiSolution = null;
    if (state.networkInstance) {
        state.networkInstance.destroy();
        state.networkInstance = null;
    }
}

// ═══════════════════════════════════════════════════════════════
//  INSTRUCTIONS RENDERING
// ═══════════════════════════════════════════════════════════════

function renderInstructions(instructions) {
    const el = document.getElementById('instructions-content');
    
    if (!instructions || instructions.trim().length === 0) {
        el.innerHTML = `
            <div class="placeholder-text">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                </svg>
                <p>No instructions found in this file</p>
            </div>`;
        return;
    }

    // Check if it's HTML content
    if (instructions.includes('<') && instructions.includes('>')) {
        el.innerHTML = instructions;
    } else {
        // Plain text - format with line breaks and basic styling
        const formatted = instructions
            .replace(/\n{2,}/g, '</p><p>')
            .replace(/\n/g, '<br>')
            .replace(/(Partie \d+|Part \d+|Étape \d+|Step \d+)/gi, '<strong>$1</strong>')
            .replace(/(«\s*[^»]+\s*»)/g, '<code>$1</code>');
        
        el.innerHTML = `<div class="instruction-text"><p>${formatted}</p></div>`;
    }
}

// ═══════════════════════════════════════════════════════════════
//  AUDIT RENDERING
// ═══════════════════════════════════════════════════════════════

window.loadAudit = loadAudit;

async function loadAudit() {
    console.log("loadAudit called. Session ID:", state.sessionId);
    if (!state.sessionId) {
        showToast("Error: No session ID found. Please re-upload the file.", "error");
        return;
    }
    
    const loadingEl = document.getElementById('audit-loading');
    const contentEl = document.getElementById('audit-content');
    
    if (loadingEl) loadingEl.classList.remove('hidden');
    if (contentEl) contentEl.style.display = 'none';
    
    try {
        console.log("Fetching audit from /api/audit...");
        const res = await fetch(`${API_BASE}/api/audit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: state.sessionId })
        });
        
        const data = await res.json();
        console.log("Audit data received:", data);
        
        if (data.success && data.audit) {
            renderAudit(data.audit);
            state.auditLoaded = true;
        } else {
            throw new Error(data.error || 'Failed to load audit data');
        }
    } catch (err) {
        console.error("Audit fetch error:", err);
        if (contentEl) {
            contentEl.innerHTML = `<div class="placeholder-text" style="color:var(--danger)"><p>Error: ${err.message}</p><button class="btn" style="margin-top:10px" onclick="loadAudit()">Try Again</button></div>`;
        }
        showToast(`Audit error: ${err.message}`, 'error');
    } finally {
        if (loadingEl) loadingEl.classList.add('hidden');
        if (contentEl) contentEl.style.display = 'block';
    }
}

function renderAudit(audit) {
    const el = document.getElementById('audit-content');
    let html = '';
    
    // Status banner
    const status = audit.summary?.status || 'UNKNOWN';
    const statusColor = status === 'FAIL' ? 'var(--danger)' : (status === 'WARN' ? 'var(--warning)' : 'var(--success)');
    html += `
        <div style="background: rgba(255,255,255,0.05); border: 1px solid ${statusColor}; padding: 10px; border-radius: var(--radius-sm); margin-bottom: 15px; display: flex; align-items: center; justify-content: space-between;">
            <div style="font-weight: 600; color: ${statusColor}">AUDIT STATUS: ${status}</div>
            <div style="font-size: 0.8rem; color: var(--text-dim)">${audit.summary?.total_errors || 0} Errors • ${audit.summary?.total_warnings || 0} Warnings</div>
        </div>
    `;
    
    // Helper to render cards
    const renderCard = (type, title, msg, fix = null) => {
        let icon = '';
        if (type === 'error') icon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
        else if (type === 'warning') icon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
        else icon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        
        let fixHtml = fix ? `<div class="audit-card-fix">FIX: ${fix}</div>` : '';
        
        return `
            <div class="audit-card ${type}">
                <div class="audit-card-title">${icon} ${title}</div>
                <div class="audit-card-msg">${msg}</div>
                ${fixHtml}
            </div>
        `;
    };
    
    // IP Anchors
    if (audit.ip_anchors && Object.keys(audit.ip_anchors).length > 0) {
        html += '<div class="audit-section"><h3>IP Anchors (Immutable)</h3>';
        Object.entries(audit.ip_anchors).forEach(([net, info]) => {
            let msg = `Gateway: <strong>${info.gateway || 'Unknown'}</strong><br>`;
            info.members.forEach(m => {
                msg += `• ${m.device}:${m.interface} = ${m.ip}<br>`;
            });
            html += renderCard('pass', `Subnet ${net}`, msg);
        });
        html += '</div>';
    }
    
    // VLANs
    if (audit.vlan) {
        const hasErrors = audit.vlan.errors?.length > 0;
        const hasWarnings = audit.vlan.warnings?.length > 0;
        const hasFacts = audit.vlan.facts?.length > 0;
        
        if (hasErrors || hasWarnings || hasFacts) {
            html += '<div class="audit-section"><h3>VLAN & Trunking</h3>';
            audit.vlan.errors?.forEach(e => html += renderCard('error', e.type, e.message, e.fix));
            audit.vlan.warnings?.forEach(w => html += renderCard('warning', w.type, w.message));
            audit.vlan.facts?.slice(0, 5).forEach(f => html += renderCard('pass', 'Verified', f));
            if (audit.vlan.facts?.length > 5) html += renderCard('pass', 'More', `...and ${audit.vlan.facts.length - 5} more checks passed.`);
            html += '</div>';
        }
    }
    
    // Inter-VLAN
    if (audit.intervlan) {
        const hasErrors = audit.intervlan.errors?.length > 0;
        const hasFacts = audit.intervlan.facts?.length > 0;
        
        if (hasErrors || hasFacts) {
            html += '<div class="audit-section"><h3>Inter-VLAN Routing</h3>';
            audit.intervlan.errors?.forEach(e => html += renderCard('error', e.type, e.message));
            audit.intervlan.facts?.slice(0, 5).forEach(f => html += renderCard('pass', 'Verified', f));
            if (audit.intervlan.facts?.length > 5) html += renderCard('pass', 'More', `...and ${audit.intervlan.facts.length - 5} more routing checks passed.`);
            html += '</div>';
        }
    }
    
    // DHCP
    if (audit.dhcp) {
        const hasErrors = audit.dhcp.errors?.length > 0;
        const hasWarnings = audit.dhcp.warnings?.length > 0;
        const hasFacts = audit.dhcp.facts?.length > 0;
        
        if (hasErrors || hasWarnings || hasFacts) {
            html += '<div class="audit-section"><h3>DHCP Services</h3>';
            audit.dhcp.errors?.forEach(e => html += renderCard('error', e.type, e.message));
            audit.dhcp.warnings?.forEach(w => html += renderCard('warning', w.type, w.message));
            audit.dhcp.facts?.forEach(f => html += renderCard('pass', 'Pool Valid', f));
            html += '</div>';
        }
    }
    
    if (html === '') {
        html = '<div class="placeholder-text"><p>No audit data available</p></div>';
    }
    
    el.innerHTML = html;
}

// ═══════════════════════════════════════════════════════════════
//  TOPOLOGY VISUALIZATION (vis.js)
// ═══════════════════════════════════════════════════════════════

function renderTopology(devices, connections) {
    const container = document.getElementById('topology-graph');
    const placeholder = document.getElementById('topology-placeholder');
    
    if (!devices || devices.length === 0) {
        placeholder.style.display = 'flex';
        container.style.display = 'none';
        return;
    }

    placeholder.style.display = 'none';
    container.style.display = 'block';

    // Device category colors and shapes
    const categoryStyles = {
        router: { color: { background: '#00bceb', border: '#0099c4', highlight: { background: '#33d1f5', border: '#00bceb' } }, shape: 'diamond', size: 25 },
        switch: { color: { background: '#6c5ce7', border: '#5a4bd5', highlight: { background: '#8b7fef', border: '#6c5ce7' } }, shape: 'square', size: 22 },
        pc: { color: { background: '#00cec9', border: '#00b5b0', highlight: { background: '#33e0dc', border: '#00cec9' } }, shape: 'dot', size: 18 },
        server: { color: { background: '#fdcb6e', border: '#e0b345', highlight: { background: '#fdd98a', border: '#fdcb6e' } }, shape: 'star', size: 22 },
        phone: { color: { background: '#a29bfe', border: '#8b83e6', highlight: { background: '#b8b3fe', border: '#a29bfe' } }, shape: 'triangle', size: 18 },
        wireless: { color: { background: '#fd79a8', border: '#e0608b', highlight: { background: '#fd97bc', border: '#fd79a8' } }, shape: 'hexagon', size: 20 },
        cloud: { color: { background: '#636e72', border: '#535c5f', highlight: { background: '#7e898d', border: '#636e72' } }, shape: 'ellipse', size: 30 },
        generic: { color: { background: '#b2bec3', border: '#96a2a6', highlight: { background: '#c5ced2', border: '#b2bec3' } }, shape: 'dot', size: 18 },
    };

    // Build nodes
    const nodes = devices.map((dev, i) => {
        const style = categoryStyles[dev.category] || categoryStyles.generic;
        return {
            id: i,
            label: dev.name,
            title: `${dev.name}\n${dev.type} (${dev.model})\n${dev.interfaces?.length || 0} interfaces\nConfig: ${dev.has_config ? '✓' : '✗'}`,
            ...style,
            font: { color: '#e8e8f0', size: 12, face: 'Inter', strokeWidth: 2, strokeColor: '#060614' },
            x: dev.x ? dev.x * 2 : undefined,
            y: dev.y ? dev.y * 2 : undefined,
        };
    });

    // Build edges
    const deviceNameToId = {};
    devices.forEach((dev, i) => { deviceNameToId[dev.name] = i; });

    const edges = connections.map((conn, i) => ({
        id: i,
        from: deviceNameToId[conn.device1],
        to: deviceNameToId[conn.device2],
        title: `${conn.port1 || '?'} ↔ ${conn.port2 || '?'}\n${conn.cable_type || 'Cable'}`,
        color: { color: 'rgba(255,255,255,0.12)', highlight: '#00bceb', hover: 'rgba(255,255,255,0.25)' },
        width: 2,
        smooth: { type: 'continuous' },
    })).filter(e => e.from !== undefined && e.to !== undefined);

    // vis.js options
    const options = {
        physics: {
            enabled: !devices.some(d => d.x && d.y),
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -60,
                centralGravity: 0.008,
                springLength: 150,
                springConstant: 0.04,
                damping: 0.3,
            },
            stabilization: { iterations: 200, fit: true },
        },
        interaction: {
            hover: true,
            tooltipDelay: 100,
            zoomView: true,
            dragView: true,
        },
        nodes: {
            borderWidth: 2,
            shadow: { enabled: true, color: 'rgba(0,0,0,0.3)', size: 8 },
        },
        edges: {
            shadow: false,
        },
    };

    // Create network
    if (state.networkInstance) {
        state.networkInstance.destroy();
    }
    
    state.networkInstance = new vis.Network(container, { nodes, edges }, options);
}

// ═══════════════════════════════════════════════════════════════
//  SOLVE LAB
// ═══════════════════════════════════════════════════════════════

async function solveLab() {
    if (!state.sessionId) {
        showToast('Upload a file first', 'error');
        return;
    }

    const { provider, model, apiKey } = state.settings;

    if (!provider || !model) {
        showToast('Configure AI provider in Settings first', 'warning');
        openSettings();
        return;
    }

    const solveBtn = document.getElementById('btn-solve');
    const progressContainer = document.getElementById('progress-container');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');

    solveBtn.classList.add('loading');
    solveBtn.disabled = true;
    progressContainer.classList.remove('hidden');
    progressFill.style.width = '0%';

    // Animated progress
    const progressSteps = [
        { pct: 15, text: '📡 Analyzing topology...' },
        { pct: 30, text: '🧠 Processing lab instructions...' },
        { pct: 50, text: '⚙️ Generating configurations...' },
        { pct: 70, text: '🔗 Computing routing tables...' },
        { pct: 85, text: '✅ Validating IP assignments...' },
    ];

    let stepIdx = 0;
    const progressInterval = setInterval(() => {
        if (stepIdx < progressSteps.length) {
            progressFill.style.width = progressSteps[stepIdx].pct + '%';
            progressText.textContent = progressSteps[stepIdx].text;
            stepIdx++;
        }
    }, 2500);

    try {
        const response = await fetch(`${API_BASE}/api/solve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: state.sessionId,
                provider: provider,
                model: model,
                api_key: apiKey,
                mode: state.mode,
                remarks: (document.getElementById('input-remarks')?.value || '').trim(),
            }),
        });

        const data = await response.json();

        clearInterval(progressInterval);

        if (!response.ok || !data.success) {
            throw new Error(data.error || 'AI solving failed');
        }

        // Store solution
        state.aiSolution = data;

        // Update progress
        progressFill.style.width = '100%';
        progressText.textContent = '✅ Lab solved successfully!';

        // Render configs
        renderDeviceConfigs(data);

        // Enable apply button
        document.getElementById('btn-apply').disabled = false;

        showToast('Lab solved! Review the configurations and click Apply & Download.', 'success');

        // Update history
        updateHistoryWithSolution(state.filename);

    } catch (err) {
        clearInterval(progressInterval);
        progressFill.style.width = '0%';
        progressText.textContent = `❌ Error: ${err.message}`;
        showToast(`Solving failed: ${err.message}`, 'error');
    } finally {
        solveBtn.classList.remove('loading');
        solveBtn.disabled = false;
        setTimeout(() => {
            progressContainer.classList.add('hidden');
        }, 5000);
    }
}

// ═══════════════════════════════════════════════════════════════
//  AUTO-SOLVE (closed-loop: solve → verify → refine)
// ═══════════════════════════════════════════════════════════════

function switchToTab(targetId) {
    document.querySelectorAll('.tab-btn').forEach(b =>
        b.classList.toggle('active', b.getAttribute('data-tab') === targetId));
    document.querySelectorAll('.tab-content').forEach(c =>
        c.classList.toggle('active', c.id === targetId));
}

async function autoSolveLab() {
    if (!state.sessionId) { showToast('Upload a file first', 'error'); return; }
    const { provider, model, apiKey } = state.settings;
    if (!provider || !model) {
        showToast('Configure AI provider in Settings first', 'warning');
        openSettings();
        return;
    }

    const btn = document.getElementById('btn-auto-solve');
    const progressContainer = document.getElementById('progress-container');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');

    btn.classList.add('loading');
    btn.disabled = true;
    document.getElementById('btn-solve').disabled = true;
    progressContainer.classList.remove('hidden');
    progressText.textContent = '🔁 Solving, verifying & refining (several AI passes)…';
    let pulse = 15;
    const iv = setInterval(() => { pulse = Math.min(92, pulse + 7); progressFill.style.width = pulse + '%'; }, 3000);

    try {
        const res = await fetch(`${API_BASE}/api/solve_auto`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: state.sessionId,
                provider, model, api_key: apiKey,
                mode: state.mode,
                remarks: (document.getElementById('input-remarks')?.value || '').trim(),
                max_iterations: 3,
            }),
        });
        const data = await res.json();
        clearInterval(iv);
        if (!res.ok || !data.success) throw new Error(data.error || 'Auto-solve failed');

        state.aiSolution = data;
        progressFill.style.width = '100%';
        progressText.textContent = '✅ Done';
        renderDeviceConfigs(data);
        document.getElementById('btn-apply').disabled = false;

        switchToTab('verify-tab');
        renderAutoReport(data);

        const ok = data.verdict === 'PASS';
        showToast(`Auto-solve done — verdict ${data.verdict} (best iteration ${data.best_iteration}/${data.iterations.length})`,
                  ok ? 'success' : 'warning');
        updateHistoryWithSolution(state.filename);
    } catch (err) {
        clearInterval(iv);
        progressFill.style.width = '0%';
        showToast(`Auto-solve failed: ${err.message}`, 'error');
    } finally {
        btn.classList.remove('loading');
        setTimeout(() => progressContainer.classList.add('hidden'), 1500);
        updateSolveButton();
    }
}

function renderAutoReport(data) {
    // Prepend an iteration-history strip, then the standard verification report.
    renderVerify(data.report);
    const el = document.getElementById('verify-content');
    const rows = (data.iterations || []).map(it => {
        const s = it.summary || {};
        const col = it.iteration === data.best_iteration ? 'var(--success)' : 'var(--text-dim)';
        return `<div style="font-size:0.76rem; color:${col};">
            iter ${it.iteration}: score ${it.score} · ${s.reachable || 0} reachable, ${s.unreachable || 0} unreachable, ${it.num_failures} issues left
            ${it.iteration === data.best_iteration ? ' ◀ best' : ''}</div>`;
    }).join('');
    const strip = `
        <div style="background:rgba(255,255,255,0.04); border:1px solid var(--border); padding:8px 10px; border-radius:var(--radius-sm); margin-bottom:12px;">
            <div style="font-weight:600; margin-bottom:4px;">Refinement loop (${data.iterations.length} passes)</div>
            ${rows}
        </div>`;
    el.insertAdjacentHTML('afterbegin', strip);
}

// ═══════════════════════════════════════════════════════════════
//  CONFIG DISPLAY
// ═══════════════════════════════════════════════════════════════

function renderDeviceConfigs(solution) {
    const tabsEl = document.getElementById('config-tabs');
    const contentEl = document.getElementById('config-content');
    
    tabsEl.innerHTML = '';
    contentEl.innerHTML = '';

    const deviceConfigs = solution.device_configs || {};
    const deviceNames = Object.keys(deviceConfigs);

    if (deviceNames.length === 0) {
        contentEl.innerHTML = `
            <div class="placeholder-text">
                <p>No configurations generated.</p>
            </div>`;
        return;
    }

    // Add explanation card if available
    if (solution.explanation) {
        const explCard = document.createElement('div');
        explCard.className = 'explanation-card';
        explCard.innerHTML = `<strong>🧠 AI Summary:</strong> ${solution.explanation}`;
        contentEl.appendChild(explCard);
    }

    // Show topology changes if any
    if (solution.topology_changes) {
        const topoDiv = document.createElement('div');
        topoDiv.className = 'topo-changes';
        
        const addedDevices = solution.topology_changes.add_devices || [];
        const addedConns = solution.topology_changes.add_connections || [];
        
        addedDevices.forEach(dev => {
            topoDiv.innerHTML += `<span class="topo-change-badge add-device">+ ${dev.name} (${dev.type} ${dev.model})</span>`;
        });
        addedConns.forEach(conn => {
            topoDiv.innerHTML += `<span class="topo-change-badge add-cable">🔗 ${conn.device1}:${conn.port1} ↔ ${conn.device2}:${conn.port2}</span>`;
        });
        
        if (addedDevices.length || addedConns.length) {
            contentEl.appendChild(topoDiv);
        }
    }

    // Create tabs and content blocks for each device
    deviceNames.forEach((name, idx) => {
        const config = deviceConfigs[name];
        
        // Tab
        const tab = document.createElement('button');
        tab.className = `config-tab ${idx === 0 ? 'active' : ''}`;
        
        const iconMap = { router: '🔷', switch: '🟪', pc: '🖥️', server: '🖧' };
        const icon = iconMap[config.type] || '📦';
        
        tab.innerHTML = `<span class="tab-icon">${icon}</span>${name}`;
        tab.addEventListener('click', () => selectConfigTab(name));
        tabsEl.appendChild(tab);

        // Content block
        const block = document.createElement('div');
        block.className = `config-block ${idx === 0 ? 'active' : ''}`;
        block.id = `config-block-${name}`;

        if (config.type === 'pc' || config.type === 'server') {
            // ═══ FIX: Map AI response keys correctly ═══
            const ipConfig = config.ip_config || {};
            const ipAddr = ipConfig.ip_address || ipConfig.ip || '';
            const mask = ipConfig.subnet_mask || ipConfig.mask || '';
            const gw = ipConfig.default_gateway || ipConfig.gateway || '';
            const dns = ipConfig.dns || ipConfig.dns_server || '';
            const ipv6 = ipConfig.ipv6_address || '';
            const ipv6gw = ipConfig.ipv6_gateway || '';

            const makeRow = (label, value) => {
                const valClass = value ? 'ip-config-value' : 'ip-config-value not-set';
                return `<div class="ip-config-row">
                    <span class="ip-config-label">${label}</span>
                    <span class="${valClass}">${value || 'Not set'}</span>
                </div>`;
            };

            let ipRows = '';
            ipRows += makeRow('IP ADDRESS', ipAddr);
            ipRows += makeRow('SUBNET MASK', mask);
            ipRows += makeRow('GATEWAY', gw);
            ipRows += makeRow('DNS SERVER', dns);
            if (ipv6) ipRows += makeRow('IPv6 ADDRESS', ipv6);
            if (ipv6gw) ipRows += makeRow('IPv6 GATEWAY', ipv6gw);

            block.innerHTML = `
                <div class="config-block-header">
                    <span class="config-block-title">${name} — IP Configuration</span>
                </div>
                <div class="ip-config-card">
                    ${ipRows}
                </div>
            `;

            // Also show commands if present
            if (config.commands && config.commands.length > 0) {
                block.innerHTML += `
                    <div style="margin-top: 1rem;">
                        <div class="config-block-header">
                            <span class="config-block-title">CLI Commands</span>
                            <button class="btn-copy" onclick="copyConfig('${name}')">Copy</button>
                        </div>
                        <pre class="config-code" id="code-${name}">${highlightIOS(config.commands.join('\n'))}</pre>
                    </div>
                `;
            }
        } else {
            // Show CLI commands for routers/switches
            const cmds = config.commands || [];
            block.innerHTML = `
                <div class="config-block-header">
                    <span class="config-block-title">${name} — CLI Commands (${cmds.length} lines)</span>
                    <button class="btn-copy" onclick="copyConfig('${name}')">Copy</button>
                </div>
                <pre class="config-code" id="code-${name}">${highlightIOS(cmds.join('\n'))}</pre>
            `;
        }

        contentEl.appendChild(block);
    });
}

function selectConfigTab(name) {
    // Update tabs
    document.querySelectorAll('.config-tab').forEach(tab => {
        tab.classList.toggle('active', tab.textContent.includes(name));
    });
    // Update content blocks
    document.querySelectorAll('.config-block').forEach(block => {
        block.classList.toggle('active', block.id === `config-block-${name}`);
    });
}

function copyConfig(deviceName) {
    const codeEl = document.getElementById(`code-${deviceName}`);
    if (!codeEl) return;
    
    const text = codeEl.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = codeEl.previousElementSibling?.querySelector('.btn-copy') || 
                    document.querySelector(`#config-block-${deviceName} .btn-copy`);
        if (btn) {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        }
        showToast(`Copied ${deviceName} config to clipboard`, 'info');
    });
}

// Make copyConfig global for onclick handlers
window.copyConfig = copyConfig;

// ═══════════════════════════════════════════════════════════════
//  IOS SYNTAX HIGHLIGHTING
// ═══════════════════════════════════════════════════════════════

function highlightIOS(text) {
    if (!text) return '';
    
    return text.split('\n').map(line => {
        let s = escapeHtml(line);
        
        // Comments
        if (s.trim().startsWith('!')) {
            return `<span class="cmd-comment">${s}</span>`;
        }
        
        // Keywords
        const keywords = ['enable', 'configure terminal', 'conf t', 'end', 'exit', 'write memory', 
                          'wr', 'copy', 'no shutdown', 'shutdown', 'no', 'hostname', 'banner',
                          'service', 'logging', 'enable secret', 'enable password', 'line',
                          'login', 'password', 'transport input', 'exec-timeout'];
        
        for (const kw of keywords) {
            const regex = new RegExp(`^(\\s*)(${escapeRegex(kw)})\\b`, 'i');
            if (regex.test(s)) {
                s = s.replace(regex, `$1<span class="cmd-keyword">$2</span>`);
                break;
            }
        }
        
        // Interface lines
        if (/^\s*interface\s/i.test(line)) {
            s = s.replace(/(interface\s+)(\S+)/i, '<span class="cmd-keyword">$1</span><span class="cmd-interface">$2</span>');
        }
        
        // IP addresses
        s = s.replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, '<span class="cmd-ip">$1</span>');
        
        // Router config mode
        if (/^\s*router\s/i.test(line)) {
            s = s.replace(/(router\s+\S+)/i, '<span class="cmd-keyword">$1</span>');
        }
        
        return s;
    }).join('\n');
}

function escapeHtml(str) {
    const el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
}

function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ═══════════════════════════════════════════════════════════════
//  APPLY & DOWNLOAD
// ═══════════════════════════════════════════════════════════════

async function applyAndDownload() {
    if (!state.sessionId || !state.aiSolution) {
        showToast('No solution to apply', 'error');
        return;
    }

    const applyBtn = document.getElementById('btn-apply');
    applyBtn.classList.add('loading');
    applyBtn.disabled = true;

    try {
        // Apply configs
        const applyResponse = await fetch(`${API_BASE}/api/apply`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: state.sessionId }),
        });

        const applyData = await applyResponse.json();

        if (!applyResponse.ok || !applyData.success) {
            throw new Error(applyData.error || 'Apply failed');
        }

        showToast(`Configs applied! ${applyData.config_results?.configured?.length || 0} devices configured.`, 'success');

        // Build proper download filename
        const origName = state.filename || 'lab.pka';
        const nameParts = origName.split('.');
        const ext = nameParts.pop();
        const baseName = nameParts.join('.');
        const downloadName = `${baseName}_solved.${ext}`;
        
        // Native Browser Download via backend
        const downloadUrl = `${API_BASE}/api/download/${encodeURIComponent(downloadName)}?session_id=${state.sessionId}`;
        
        // Trigger the download directly
        window.location.href = downloadUrl;

        showToast('Download started! Open the file in Packet Tracer.', 'success');

    } catch (err) {
        console.error('[DOWNLOAD] error:', err);
        showToast(`Apply failed: ${err.message}`, 'error');
    } finally {
        applyBtn.classList.remove('loading');
        applyBtn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════
//  SETTINGS
// ═══════════════════════════════════════════════════════════════

async function loadProviders() {
    try {
        const response = await fetch(`${API_BASE}/api/providers`);
        if (response.ok) {
            state.providers = await response.json();
            populateProviderDropdown();
        }
    } catch (err) {
        // Backend not running — use defaults
        state.providers = {
            gemini: { name: 'Google Gemini', models: ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-2.5-pro'], requires_key: true, free_tier: true },
            openai: { name: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4.1', 'gpt-4.1-mini', 'o4-mini'], requires_key: true, free_tier: false },
            claude: { name: 'Anthropic Claude', models: ['claude-sonnet-4-20250514', 'claude-haiku-3'], requires_key: true, free_tier: false },
            groq: { name: 'Groq', models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768'], requires_key: true, free_tier: true },
            openrouter: { name: 'OpenRouter', models: ['google/gemini-2.5-flash', 'anthropic/claude-sonnet-4', 'openai/gpt-4o'], requires_key: true, free_tier: false },
            ollama: { name: 'Ollama (Local)', models: ['llama3.1', 'mistral', 'codellama', 'qwen2.5'], requires_key: false, free_tier: true },
        };
        populateProviderDropdown();
    }
}

function populateProviderDropdown() {
    const select = document.getElementById('select-provider');
    select.innerHTML = '<option value="">— Select Provider —</option>';
    
    for (const [key, info] of Object.entries(state.providers)) {
        const opt = document.createElement('option');
        opt.value = key;
        opt.textContent = `${info.name}${info.free_tier ? ' ★ Free' : ''}`;
        if (key === state.settings.provider) opt.selected = true;
        select.appendChild(opt);
    }

    // If provider is already set, populate models
    if (state.settings.provider) {
        onProviderChange();
    }
}

function onProviderChange() {
    const provider = document.getElementById('select-provider').value;
    const modelSelect = document.getElementById('select-model');
    const apiKeyGroup = document.getElementById('api-key-group');
    const ollamaGroup = document.getElementById('ollama-url-group');
    const hint = document.getElementById('provider-hint');

    const info = state.providers[provider];
    
    // Update model dropdown
    modelSelect.innerHTML = '';
    if (info) {
        info.models.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m;
            opt.textContent = m;
            if (m === state.settings.model) opt.selected = true;
            modelSelect.appendChild(opt);
        });
        
        // Show/hide API key
        apiKeyGroup.style.display = info.requires_key ? 'block' : 'none';
        ollamaGroup.style.display = provider === 'ollama' ? 'block' : 'none';
        
        hint.textContent = info.free_tier ? '✓ Free tier available' : '$ Paid API';
        hint.style.color = info.free_tier ? '#00cec9' : '#fdcb6e';
    } else {
        modelSelect.innerHTML = '<option value="">— Select provider first —</option>';
        hint.textContent = '';
    }
}

function openSettings() {
    const modal = document.getElementById('settings-modal');
    modal.classList.remove('hidden');
    
    // Populate current values
    document.getElementById('select-provider').value = state.settings.provider;
    onProviderChange();
    document.getElementById('select-model').value = state.settings.model;
    document.getElementById('input-api-key').value = state.settings.apiKey;
    document.getElementById('input-ollama-url').value = state.settings.ollamaUrl || 'http://localhost:11434';
}

function closeSettings() {
    document.getElementById('settings-modal').classList.add('hidden');
}

function saveSettingsFromModal() {
    state.settings.provider = document.getElementById('select-provider').value;
    state.settings.model = document.getElementById('select-model').value;
    state.settings.apiKey = document.getElementById('input-api-key').value;
    state.settings.ollamaUrl = document.getElementById('input-ollama-url').value;
    
    saveSettings();
    closeSettings();
    updateSolveButton();
    showToast('Settings saved!', 'success');
}

function loadSettings() {
    try {
        const saved = localStorage.getItem('ciscolabai_settings');
        if (saved) {
            const parsed = JSON.parse(saved);
            state.settings = { ...state.settings, ...parsed };
        }
        

    } catch (e) { /* ignore */ }
}

function saveSettings() {
    try {
        localStorage.setItem('ciscolabai_settings', JSON.stringify(state.settings));
    } catch (e) { /* ignore */ }
}

function updateSolveButton() {
    const hasProvider = state.settings.provider && state.settings.model;
    const hasKey = !state.providers[state.settings.provider]?.requires_key || state.settings.apiKey;
    const disabled = !state.sessionId || !hasProvider || !hasKey;
    document.getElementById('btn-solve').disabled = disabled;
    const auto = document.getElementById('btn-auto-solve');
    if (auto) auto.disabled = disabled;
}

// ═══════════════════════════════════════════════════════════════
//  HISTORY
// ═══════════════════════════════════════════════════════════════

function openHistory() {
    document.getElementById('history-modal').classList.remove('hidden');
    renderHistory();
}

function closeHistory() {
    document.getElementById('history-modal').classList.add('hidden');
}

function loadHistory() {
    try {
        return JSON.parse(localStorage.getItem('ciscolabai_history') || '[]');
    } catch { return []; }
}

function addToHistory(filename) {
    const history = loadHistory();
    history.unshift({
        filename,
        date: new Date().toISOString(),
        solved: false,
    });
    // Keep last 20
    localStorage.setItem('ciscolabai_history', JSON.stringify(history.slice(0, 20)));
}

function updateHistoryWithSolution(filename) {
    const history = loadHistory();
    const item = history.find(h => h.filename === filename);
    if (item) {
        item.solved = true;
        item.solvedDate = new Date().toISOString();
    }
    localStorage.setItem('ciscolabai_history', JSON.stringify(history));
}

function renderHistory() {
    const list = document.getElementById('history-list');
    const history = loadHistory();
    
    if (history.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No labs solved yet.</p>';
        return;
    }
    
    list.innerHTML = history.map(item => `
        <div class="history-item">
            <div>
                <div class="history-item-name">${item.filename}</div>
                <div class="history-item-date">${new Date(item.date).toLocaleString()}</div>
            </div>
            <span class="file-badge" style="${item.solved ? 'background: rgba(0,206,201,0.08); border-color: rgba(0,206,201,0.15); color: #00cec9;' : ''}">${item.solved ? '✓ Solved' : 'Uploaded'}</span>
        </div>
    `).join('');
}

// ═══════════════════════════════════════════════════════════════
//  TOASTS
// ═══════════════════════════════════════════════════════════════

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icons = {
        success: '✓',
        error: '✗',
        warning: '⚠',
        info: 'ℹ',
    };
    
    toast.innerHTML = `<strong>${icons[type] || 'ℹ'}</strong> ${message}`;
    container.appendChild(toast);
    
    // Auto remove
    setTimeout(() => {
        toast.classList.add('toast-out');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}
