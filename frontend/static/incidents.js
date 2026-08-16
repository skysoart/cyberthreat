document.addEventListener('DOMContentLoaded', () => {
    fetchIncidents();
});

function applyFilters() {
    const prio = document.getElementById('filterPriority').value;
    const stat = document.getElementById('filterStatus').value;
    
    const params = new URLSearchParams();
    if (prio) params.append('priority', prio);
    if (stat) params.append('status', stat);
    
    // In a real app, this re-fetches. With mocks, it fetches the same file, but we demonstrate the API contract
    fetchIncidents(params.toString());
}

async function fetchIncidents(query = '') {
    showLoading('loadingState');
    const tbody = document.getElementById('incidentsTbody');
    tbody.innerHTML = '';
    
    try {
        const path = query ? `/api/v1/incidents?${query}` : '/api/v1/incidents';
        // Note: api.js maps /api/v1/incidents regardless of query params to the mock file
        const data = await api(path);
        
        document.getElementById('loadingState').style.display = 'none';
        
        if (data.incidents.length === 0) {
            showEmpty('loadingState', 'No incidents match these filters.');
            document.getElementById('loadingState').style.display = 'block';
            return;
        }
        
        renderTable(data.incidents);
    } catch (err) {
        showError('loadingState', 'Failed to load incidents queue.');
    }
}

function renderTable(incidents) {
    const tbody = document.getElementById('incidentsTbody');
    const colors = ['#dc2626', '#ea580c', '#ca8a04', '#64748b', '#3b82f6', '#8b5cf6'];
    const segments = ['model_confidence', 'asset_criticality', 'exploitability', 'blast_radius', 'kill_chain_depth', 'recency'];
    
    // Time formatting helper
    const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
    
    incidents.forEach(inc => {
        const tr = document.createElement('tr');
        tr.onclick = () => window.location.href = `incident.html?id=${inc.id}`;
        
        // Priority Pill
        const prioCell = `<span class="priority-pill color-${inc.priority}">${inc.priority}</span>`;
        
        // Risk Score & Inline Bar
        let barHtml = `<div class="inline-risk-bar">`;
        segments.forEach((seg, i) => {
            const pt = inc.risk_breakdown[seg].points;
            const pct = (pt / 100) * 100; // Total bar width represents 100 max points
            barHtml += `<div class="inline-risk-segment" style="width: ${pct}%; background-color: ${colors[i]}" title="${seg}: ${inc.risk_breakdown[seg].raw} x ${inc.risk_breakdown[seg].weight} = ${pt}"></div>`;
        });
        barHtml += `</div>`;
        
        const riskCell = `
            <div style="font-weight: bold; font-size: 14px;">${inc.risk_score}</div>
            ${barHtml}
        `;
        
        // Title & Similar marker
        let simMarker = inc.has_similar ? `<span class="sim-marker" title="Similar past incident found">HAS SIMILAR</span>` : '';
        const titleCell = `
            <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 3px;">${inc.id}</div>
            <div style="font-weight: 500;">${inc.title} ${simMarker}</div>
        `;
        
        // Time diff hack for mock data (assuming mock data is "now")
        // The brief says "relative, '4m ago'", so we'll just mock it directly or parse it.
        // Actually, let's just do a simple fallback for the relative time.
        const diffMinutes = Math.floor((new Date() - new Date(inc.last_seen_at)) / 60000);
        let timeStr = `${diffMinutes}m ago`;
        if (diffMinutes > 60) timeStr = `${Math.floor(diffMinutes/60)}h ago`;
        if (diffMinutes < 0 || isNaN(diffMinutes)) timeStr = 'just now'; // Fallback for fixed mock dates
        
        tr.innerHTML = `
            <td>${prioCell}</td>
            <td>${riskCell}</td>
            <td>${titleCell}</td>
            <td>${inc.event_count}</td>
            <td><span style="font-family:monospace; font-size:12px;">${inc.assets_affected.join(', ')}</span></td>
            <td><span style="color:var(--text-secondary); font-size:13px;">${timeStr}</span></td>
        `;
        
        tbody.appendChild(tr);
    });
}
