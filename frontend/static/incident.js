document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const id = urlParams.get('id');
    
    if (!id) {
        showError('loadingState', 'No Incident ID provided in URL.');
        return;
    }
    
    fetchIncidentDetail(id);
});

async function fetchIncidentDetail(id) {
    showLoading('loadingState');
    try {
        const incident = await api(`/api/v1/incidents/${id}`);
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('incidentContent').style.display = 'grid';
        
        renderIncident(incident);
    } catch (err) {
        if (err.message === "MOCK_NOT_FOUND") {
            showEmpty('loadingState', `Detailed mock data for ${id} is not available in the demo environment. Try INC-0187.`);
        } else {
            showError('loadingState', `Failed to load incident: ${err.message}`);
        }
    }
}

function renderIncident(inc) {
    // 1. Header
    document.getElementById('incTitle').textContent = inc.title;
    document.getElementById('incId').textContent = inc.id;
    document.getElementById('incRisk').textContent = inc.risk_score;
    document.getElementById('incOpened').textContent = inc.opened_at.replace('T', ' ').replace('Z', '');
    document.getElementById('incLastSeen').textContent = inc.last_seen_at.replace('T', ' ').replace('Z', '');
    
    const priorityPill = document.getElementById('incPriority');
    priorityPill.textContent = inc.priority;
    priorityPill.className = `priority-pill color-${inc.priority}`;
    
    const contrastPill = document.getElementById('contrastIncPriority');
    contrastPill.textContent = inc.priority;
    contrastPill.className = `priority-pill color-${inc.priority}`;

    // 2. Risk Breakdown (Stacked Bar)
    const breakdown = inc.risk_breakdown;
    const segments = ['model_confidence', 'asset_criticality', 'exploitability', 'blast_radius', 'kill_chain_depth', 'recency'];
    const colors = ['#dc2626', '#ea580c', '#ca8a04', '#64748b', '#3b82f6', '#8b5cf6'];
    
    const bar = document.getElementById('riskBar');
    const labels = document.getElementById('riskLabels');
    
    segments.forEach((seg, i) => {
        const data = breakdown[seg];
        const pct = (data.points / inc.risk_score) * 100;
        
        bar.insertAdjacentHTML('beforeend', `<div class="stacked-segment" style="width: ${pct}%; background-color: ${colors[i]}" title="${seg}: ${data.raw} x ${data.weight} = ${data.points}"></div>`);
        labels.insertAdjacentHTML('beforeend', `<div class="risk-label" style="color: ${colors[i]}">${seg.replace(/_/g, ' ')}<br><strong style="color:white">${data.points.toFixed(1)} pts</strong></div>`);
    });

    // 3. Summary
    document.getElementById('incSummary').textContent = inc.summary;

    // 4. Kill Chain
    const kcContainer = document.getElementById('killChain');
    inc.kill_chain.forEach(stage => {
        kcContainer.insertAdjacentHTML('beforeend', `
            <div class="kc-stage">
                <div class="kc-tactic">${stage.tactic}</div>
                <div class="kc-tech">${stage.technique_id} - ${stage.technique}</div>
                <div style="font-size: 11px; margin-top: 10px; color: var(--accent-blue);">${stage.event_count} events</div>
            </div>
        `);
    });

    // 5. Entity Graph
    document.getElementById('entityGraphContainer').innerHTML = inc.entity_graph_svg;

    // 6. Threat Intel
    const tiContainer = document.getElementById('threatIntel');
    inc.threat_intel.forEach(ti => {
        let loudHtml = '';
        if (ti.in_kev) {
            loudHtml = `<div style="background: rgba(239, 68, 68, 0.2); border: 1px solid var(--accent-red); color: var(--accent-red); padding: 10px; border-radius: 4px; margin-bottom: 10px; font-weight: bold;">⚠️ CISA KEV MATCH: Active Exploitation in the Wild</div>`;
        }
        tiContainer.insertAdjacentHTML('beforeend', `
            ${loudHtml}
            <div style="font-size: 13px; line-height: 1.6;">
                <strong>${ti.value}</strong> (${ti.name})<br>
                Source: ${ti.source}<br>
                EPSS: ${ti.epss}<br>
                Triggered by path: <code style="background: #000; padding: 2px 4px;">${ti.triggered_by_path}</code><br>
                Matched Asset: ${ti.matched_asset} (${ti.matched_software})
            </div>
        `);
    });

    // 7. Similar Past Incident
    if (inc.similar_incident) {
        const sim = inc.similar_incident;
        const chips = sim.shared.map(s => `<span style="background:var(--bg-hover); padding:2px 8px; border-radius:12px; font-size:11px; margin:2px; display:inline-block;">${s}</span>`).join('');
        document.getElementById('similarIncident').innerHTML = `
            <div style="display:flex; align-items:center; gap: 15px; margin-bottom: 15px;">
                <div style="font-size: 32px; font-weight: bold; color: var(--accent-blue);">${(sim.similarity * 100).toFixed(0)}%</div>
                <div>Match to <strong>${sim.id}</strong><br><span style="color:var(--text-secondary); font-size:12px;">${sim.days_ago} days ago • Verdict: ${sim.verdict}</span></div>
            </div>
            <div><strong>Shared Entities & Tactics:</strong><br><div style="margin-top: 8px;">${chips}</div></div>
        `;
    } else {
        document.getElementById('similarIncident').innerHTML = `<div style="color:var(--text-secondary)">No highly similar past incidents found.</div>`;
    }

    // 8. Events Table
    const tbody = document.getElementById('eventsTbody');
    inc.events.forEach(ev => {
        // Individual Priority cell
        const prioCell = `<span class="priority-pill color-${ev.individual_priority}">${ev.individual_priority}</span>`;
        
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.onclick = () => {
            const evRow = document.getElementById(`ev-details-${ev.id}`);
            evRow.style.display = evRow.style.display === 'none' ? 'table-row' : 'none';
        };
        
        tr.innerHTML = `
            <td>${ev.ts.split('T')[1].replace('Z','')}</td>
            <td style="font-family:monospace">${ev.src_ip}</td>
            <td style="font-family:monospace">${ev.url_path}</td>
            <td>${ev.http_status}</td>
            <td>${ev.pred_class}</td>
            <td>${ev.pred_confidence.toFixed(2)}</td>
            <td>${prioCell}</td>
        `;
        tbody.appendChild(tr);

        // Evidence expansion row
        const evHtml = ev.evidence.map(e => `
            <tr>
                <td style="padding:4px 0;"><strong>${e.feature}</strong></td>
                <td>Value: ${e.value}</td>
                <td>Baseline: ${e.baseline}</td>
                <td><span style="color:var(--accent-red)">Deviation: ${e.deviation}</span></td>
                <td><em>${e.note}</em></td>
            </tr>
        `).join('');

        const evTr = document.createElement('tr');
        evTr.id = `ev-details-${ev.id}`;
        evTr.style.display = 'none';
        evTr.style.backgroundColor = 'var(--bg-dark)';
        evTr.innerHTML = `<td colspan="7"><div style="padding: 15px; border-left: 3px solid var(--accent-blue);"><table style="width:100%; font-size:12px;">${evHtml}</table></div></td>`;
        tbody.appendChild(evTr);
    });

    // 9. Recommendations
    const recContainer = document.getElementById('recommendations');
    const recs = inc.recommendations;
    ['containment', 'eradication', 'recovery', 'hunt'].forEach(group => {
        if (!recs[group] || recs[group].length === 0) return;
        
        let html = `<div class="rec-group"><h4>${group}</h4>`;
        recs[group].forEach(r => {
            let q = r.query ? `<div class="rec-query">${r.query}</div>` : '';
            html += `
                <div class="rec-item">
                    <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                        <span class="rec-id">${r.id}</span>
                        <span style="font-size:11px; color:var(--text-secondary)">ETA: ${r.eta_min}m • ${r.owner}</span>
                    </div>
                    <div style="font-size:13px; font-weight:bold; margin-bottom:5px;">${r.action}</div>
                    <div style="font-size:12px; color:var(--text-secondary);">Rollback: ${r.rollback}</div>
                    ${q}
                </div>
            `;
        });
        html += `</div>`;
        recContainer.insertAdjacentHTML('beforeend', html);
    });

    // 10. Narrative
    const narContainer = document.getElementById('incNarrative');
    inc.narrative.split('\n\n').forEach(p => {
        narContainer.insertAdjacentHTML('beforeend', `<p style="margin-bottom: 10px;">${p}</p>`);
    });
}

async function submitFeedback(label) {
    const id = new URLSearchParams(window.location.search).get('id');
    try {
        const res = await api(`/api/v1/incidents/${id}/feedback`, {
            method: 'POST',
            body: JSON.stringify({ label, analyst: "demo" })
        });
        if (res.ok) {
            alert(`Incident marked as ${res.new_status}. ${res.labels_pending} labels pending.`);
            window.location.href = 'incidents.html';
        }
    } catch (err) {
        alert("Failed to submit feedback.");
    }
}
