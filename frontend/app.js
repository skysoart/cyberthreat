let overviewPoll;

document.addEventListener('DOMContentLoaded', () => {
    fetchOverview();
    // Poll every 2 seconds as per requirements
    overviewPoll = setInterval(fetchOverview, 2000);
});

async function fetchOverview() {
    try {
        const overview = await api('/api/v1/overview');
        
        // Populate KPIs
        const tenantEl = document.querySelector('.tenant-info div');
        if(tenantEl) tenantEl.textContent = overview.tenant;
        
        document.getElementById('kpiEvents').textContent = overview.counters.events_total.toLocaleString();
        document.getElementById('kpiIncidents').textContent = overview.counters.incidents_open;
        document.getElementById('kpiP1').textContent = overview.counters.incidents_p1;
        document.getElementById('kpiNoise').textContent = overview.counters.noise_reduction_pct + '%';
        
        // Update nav badge (which might be injected by layout.js, so handle carefully if it exists)
        // Since we removed it from layout.js, we don't strict-fail if missing

        renderTrendChart(overview.trend);
        renderPriorityChart(overview.priority_split);
        renderSourcesTable(overview.top_sources);
        renderTicker(overview.ticker);

    } catch (err) {
        console.error("Overview poll failed:", err);
        // We do not stop polling on a single error, but we could show a warning toast if we had one
    }
}

let trendChartInst = null;
function renderTrendChart(trendData) {
    const ctx = document.getElementById('trendChart').getContext('2d');
    const labels = trendData.map(d => d.date.split('-').slice(1).join('/'));
    const events = trendData.map(d => d.events);
    const incidents = trendData.map(d => d.incidents);

    if (trendChartInst) {
        trendChartInst.data.labels = labels;
        trendChartInst.data.datasets[0].data = events;
        trendChartInst.data.datasets[1].data = incidents;
        trendChartInst.update();
        return;
    }

    trendChartInst = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Events',
                    data: events,
                    borderColor: '#2d3748',
                    backgroundColor: 'rgba(45, 55, 72, 0.2)',
                    fill: true,
                    tension: 0.4,
                    yAxisID: 'y'
                },
                {
                    label: 'Incidents',
                    data: incidents,
                    borderColor: '#ef4444',
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    tension: 0.4,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#94a3b8' } } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#2d3748' } },
                y: { type: 'linear', display: true, position: 'left', ticks: { color: '#94a3b8' }, grid: { color: '#2d3748' } },
                y1: { type: 'linear', display: true, position: 'right', ticks: { color: '#ef4444', stepSize: 1 }, grid: { drawOnChartArea: false } }
            }
        }
    });
}

let priorityChartInst = null;
function renderPriorityChart(split) {
    const ctx = document.getElementById('priorityChart').getContext('2d');
    const data = [split.P1, split.P2, split.P3, split.P4];
    
    if (priorityChartInst) {
        priorityChartInst.data.datasets[0].data = data;
        priorityChartInst.update();
        return;
    }

    priorityChartInst = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['P1', 'P2', 'P3', 'P4'],
            datasets: [{
                data: data,
                backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#64748b'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 20, usePointStyle: true } }
            }
        }
    });
}

function renderSourcesTable(sources) {
    // The previous index.html had an incidents table, but the brief says Overview has a "top_sources" table
    // Let's repurpose that table id="incidentsTable" -> id="sourcesTable"
    let table = document.getElementById('incidentsTable'); // Will rename in HTML later if needed
    if (!table) return;
    
    // Quick fix: Update headers dynamically since I didn't replace them in HTML
    const thead = table.querySelector('thead tr');
    if(thead.children[0].textContent !== 'ASN') {
        thead.innerHTML = `<th>ASN</th><th>Name</th><th>Country</th><th>Events</th><th>Flags</th>`;
    }

    const tbody = table.querySelector('tbody');
    tbody.innerHTML = '';
    
    sources.forEach(src => {
        const tr = document.createElement('tr');
        if (src.is_hosting || src.reputation_hit) tr.style.backgroundColor = 'rgba(239, 68, 68, 0.05)'; // flag row
        
        const flags = [];
        if (src.is_hosting) flags.push('<span class="badge" style="background:#ea580c">Hosting</span>');
        if (src.reputation_hit) flags.push('<span class="badge" style="background:#dc2626">Reputation</span>');
        
        tr.innerHTML = `
            <td>AS${src.asn}</td>
            <td>${src.asn_name}</td>
            <td>${src.country}</td>
            <td>${src.events.toLocaleString()}</td>
            <td>${flags.join(' ')}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderTicker(events) {
    // Requires a ticker element, we will create one below the tables
    let tickerContainer = document.getElementById('eventTicker');
    if (!tickerContainer) {
        const row = document.querySelector('.data-row');
        row.insertAdjacentHTML('beforeend', `
            <div class="card table-container" style="flex: 1;">
                <h3>Live Event Ticker</h3>
                <div id="eventTicker" class="ticker-list"></div>
            </div>
        `);
        document.querySelector('.data-row').style.display = 'flex';
        document.querySelector('.data-row').style.gap = '20px';
        tickerContainer = document.getElementById('eventTicker');
    }
    
    tickerContainer.innerHTML = '';
    events.forEach(ev => {
        const div = document.createElement('div');
        div.className = 'ticker-item';
        // newest at top, rows with incident link to it
        const link = ev.incident_id ? `<a href="incident.html?id=${ev.incident_id}" style="color:var(--accent-blue)">${ev.incident_id}</a>` : '<span style="color:var(--text-secondary)">No Incident</span>';
        
        div.innerHTML = `
            <div style="font-size:11px; color:var(--text-secondary)">${fmtTime(ev.ts)}</div>
            <div style="font-family:monospace">${ev.src_ip}</div>
            <div style="flex-grow:1; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">${ev.url_path}</div>
            <div style="width:80px;">${ev.pred_class}</div>
            <div style="width:100px; text-align:right;">${link}</div>
        `;
        tickerContainer.appendChild(div);
    });
}
