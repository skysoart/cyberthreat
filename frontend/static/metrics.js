document.addEventListener('DOMContentLoaded', () => {
    fetchMetrics();
});

async function fetchMetrics() {
    showLoading('loadingState');
    try {
        const metrics = await api('/api/v1/metrics');
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('metricsContent').style.display = 'grid';
        
        renderFunnel(metrics.funnel);
        renderTriage(metrics.triage);
        renderCharts(metrics.pr_curve, metrics.top_k_precision);
        renderCorrelation(metrics.correlation);
    } catch (err) {
        showError('loadingState', `Failed to load metrics: ${err.message}`);
    }
}

function renderFunnel(funnel) {
    const container = document.getElementById('funnelVis');
    
    const stages = [
        { key: 'events', label: 'Raw Events', val: funnel.events, w: 100 },
        { key: 'candidate_alerts', label: 'Candidate Alerts', val: funnel.candidate_alerts, w: 85 },
        { key: 'incidents', label: 'Correlated Incidents', val: funnel.incidents, w: 70 },
        { key: 'actionable', label: 'Actionable', val: funnel.actionable, w: 55 }
    ];
    
    stages.forEach((stage, i) => {
        let dropHtml = '';
        if (i > 0) {
            const prev = stages[i-1].val;
            const drop = ((prev - stage.val) / prev * 100).toFixed(1);
            dropHtml = `<div class="funnel-drop">&darr; ${drop}%</div>`;
        }
        
        container.insertAdjacentHTML('beforeend', `
            <div class="funnel-stage" style="width: ${stage.w}%">
                <span class="funnel-label">${stage.label}</span>
                <span class="funnel-val">${stage.val.toLocaleString()}</span>
                ${dropHtml}
            </div>
        `);
    });
}

function renderTriage(triage) {
    document.getElementById('trManual').textContent = triage.manual_estimate_seconds;
    document.getElementById('trAda').textContent = triage.adamantine_seconds;
    document.getElementById('trReduction').textContent = triage.reduction_pct;
}

function renderCharts(prCurve, topK) {
    // PR Curve
    new Chart(document.getElementById('prChart').getContext('2d'), {
        type: 'line',
        data: {
            labels: prCurve.map(d => (d.recall * 100).toFixed(0) + '%'),
            datasets: [{
                label: 'Precision',
                data: prCurve.map(d => d.precision),
                borderColor: '#3b82f6',
                tension: 0.4,
                fill: true,
                backgroundColor: 'rgba(59, 130, 246, 0.1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { title: { display: true, text: 'Recall', color: '#94a3b8' }, ticks: { color: '#94a3b8' }, grid: { color: '#2d3748' } },
                y: { title: { display: true, text: 'Precision', color: '#94a3b8' }, min: 0.5, max: 1.05, ticks: { color: '#94a3b8' }, grid: { color: '#2d3748' } }
            },
            plugins: { legend: { display: false } }
        }
    });
    
    // Top-K
    new Chart(document.getElementById('topkChart').getContext('2d'), {
        type: 'bar',
        data: {
            labels: topK.map(d => `Top ${d.k}`),
            datasets: [{
                label: 'Precision',
                data: topK.map(d => d.precision),
                backgroundColor: '#10b981',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { min: 0, max: 1.05, ticks: { color: '#94a3b8' }, grid: { color: '#2d3748' } },
                x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderCorrelation(corr) {
    document.getElementById('corrEvents').textContent = `${corr.events_per_incident_mean.toFixed(1)} / ${corr.events_per_incident_median}`;
    document.getElementById('corrSources').textContent = corr.incidents_multi_source;
    document.getElementById('corrHistory').textContent = corr.incidents_with_historical_match;
    document.getElementById('corrEscalated').textContent = corr.incidents_escalated_by_correlation;
    document.getElementById('corrNote').textContent = corr.note;
}
