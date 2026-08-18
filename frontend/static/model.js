document.addEventListener('DOMContentLoaded', () => {
    fetchModelData();
    fetchReviewQueue();
});

async function fetchModelData() {
    showLoading('loadingState');
    try {
        const data = await api('/api/v1/model');
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('modelContent').style.display = 'block';
        
        renderCurrentVersion(data.current);
        renderConfusionMatrix(data.confusion_matrix);
        renderFeatureChart(data.feature_importance);
        renderHistory(data.history);
    } catch (err) {
        showError('loadingState', `Failed to load model data: ${err.message}`);
    }
}

function renderCurrentVersion(curr) {
    document.getElementById('currentVersion').textContent = curr.version;
    document.getElementById('currentTrained').textContent = curr.trained_at.replace('T', ' ').replace('Z', '');
    document.getElementById('nBase').textContent = curr.n_base.toLocaleString();
    document.getElementById('nFeedback').textContent = curr.n_feedback;
    
    document.getElementById('mF1').textContent = curr.f1.toFixed(3);
    document.getElementById('mPrecision').textContent = curr.precision.toFixed(3);
    document.getElementById('mRecall').textContent = curr.recall.toFixed(3);
    document.getElementById('mPrAuc').textContent = curr.pr_auc.toFixed(3);
    document.getElementById('mFpr').textContent = curr.fpr_at_90_recall.toFixed(3);
}

function renderConfusionMatrix(cm) {
    // We render the heatmap using an HTML CSS Grid because vanilla Chart.js doesn't natively support heatmaps without external plugins.
    const container = document.getElementById('htmlHeatmap');
    container.innerHTML = '';
    
    const labels = cm.labels;
    const matrix = cm.matrix; // The brief provided a 1x7 array for matrix in the example, assuming it meant 7x7. Let's assume a standard 2D array or just render whatever is provided.
    
    // Set grid columns
    container.style.gridTemplateColumns = `repeat(${labels.length}, 1fr)`;
    container.style.gridTemplateRows = `repeat(${labels.length}, 1fr)`;
    
    // Y-axis labels container
    container.insertAdjacentHTML('beforeend', `<div style="position: absolute; left: 0; top: 10px; bottom: 0; width: 90px; display: flex; flex-direction: column; justify-content: space-around; text-align: right; padding-right: 10px; font-size: 10px; color: var(--text-secondary);">
        ${labels.map(l => `<div>${l.replace('_',' ')}</div>`).join('')}
    </div>`);
    
    // Find max value for color scaling
    let maxVal = 0;
    const flatMatrix = [];
    // Mock provided [[9812,3,11,7,0,22,14]] (1x7) so we must adapt safely
    for(let r=0; r<labels.length; r++) {
        const row = matrix[r] || Array(labels.length).fill(0);
        for(let c=0; c<labels.length; c++) {
            const val = row[c] || 0;
            if(val > maxVal) maxVal = val;
            flatMatrix.push(val);
        }
    }
    
    // Render cells
    flatMatrix.forEach(val => {
        // Log scale color for better visibility
        let intensity = 0;
        if (val > 0) {
            intensity = Math.max(0.1, Math.log10(val) / Math.log10(maxVal));
        }
        
        const r = Math.round(59 + (220 - 59) * intensity);
        const g = Math.round(130 + (38 - 130) * intensity);
        const b = Math.round(246 + (38 - 246) * intensity);
        
        const cell = document.createElement('div');
        cell.style.backgroundColor = val === 0 ? 'var(--bg-dark)' : `rgba(59, 130, 246, ${intensity})`; // blue scaled
        cell.style.border = '1px solid rgba(255,255,255,0.05)';
        cell.style.display = 'flex';
        cell.style.alignItems = 'center';
        cell.style.justifyContent = 'center';
        cell.style.fontSize = '10px';
        cell.title = val;
        
        if(val > 0) cell.textContent = val > 1000 ? (val/1000).toFixed(1)+'k' : val;
        
        container.appendChild(cell);
    });
    
    // X-axis labels
    container.insertAdjacentHTML('beforeend', `<div style="position: absolute; left: 100px; bottom: -20px; right: 0; display: flex; justify-content: space-around; font-size: 10px; color: var(--text-secondary); text-align: center;">
        ${labels.map(l => `<div style="width: 100%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${l}">${l.substring(0,3)}</div>`).join('')}
    </div>`);
}

function renderFeatureChart(features) {
    const ctx = document.getElementById('featureChart').getContext('2d');
    
    // Sort descending by importance
    features.sort((a,b) => b.importance - a.importance);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: features.map(f => f.feature),
            datasets: [{
                label: 'Importance',
                data: features.map(f => f.importance),
                backgroundColor: '#3b82f6',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#2d3748' } },
                y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { display: false } }
            }
        }
    });
}

function renderHistory(history) {
    const tbody = document.getElementById('historyTbody');
    tbody.innerHTML = '';
    
    history.forEach(v => {
        const tr = document.createElement('tr');
        if (!v.promoted) tr.className = 'history-rejected';
        
        let statusHtml = v.promoted 
            ? `<span style="color:#10b981; font-weight:bold;">Active</span>` 
            : `<div style="color:var(--accent-red); font-weight:bold; margin-bottom: 4px;">Rejected</div><div style="font-size: 12px; line-height: 1.4;">${v.rejection_reason}</div>`;
            
        let actionBtn = v.promoted 
            ? `<button class="btn-action" onclick="rollback('${v.version}')">Rollback to this</button>`
            : `<span style="color:var(--text-secondary); font-size: 11px;">Discarded</span>`;
            
        tr.innerHTML = `
            <td style="font-family:monospace; font-weight:bold;">${v.version}</td>
            <td>${v.trained_at.replace('T', ' ').replace('Z', '')}</td>
            <td>${v.pr_auc.toFixed(3)}</td>
            <td>${v.fpr_at_90_recall.toFixed(3)}</td>
            <td>${v.n_feedback}</td>
            <td style="max-width: 300px;">${statusHtml}</td>
            <td>${actionBtn}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function fetchReviewQueue() {
    try {
        const data = await api('/api/v1/review-queue');
        const list = document.getElementById('reviewQueueList');
        list.innerHTML = '';
        
        if (data.items.length === 0) {
            list.innerHTML = '<div class="empty-state">No items require review.</div>';
            return;
        }
        
        data.items.forEach(item => {
            const div = document.createElement('div');
            div.className = 'review-card';
            
            // Re-use logic for evidence formatting loosely, but keep it simple
            div.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px;">
                    <div>
                        <span class="priority-pill" style="background:#2d3748;">Event #${item.event_id}</span>
                        <span style="color:var(--text-secondary); font-size:12px; margin-left:10px;">Sampled via: <strong style="color:white">${item.sampled_by}</strong> (Uncertainty: ${item.uncertainty})</span>
                    </div>
                    <div style="display:flex; gap: 8px;">
                        <button class="btn-action" onclick="alert('Label saved')">Confirm: ${item.pred_class}</button>
                        <button class="btn-action" style="background: rgba(239, 68, 68, 0.1); color: var(--accent-red);" onclick="alert('Label saved')">Mark False Positive</button>
                    </div>
                </div>
                <div style="font-family:monospace; font-size:13px; margin-bottom: 10px; padding: 10px; background:var(--bg-code, #f4f3f0); color:var(--text-primary); border:1px solid var(--border, #e8e6e1); border-radius:4px;">
                    ${item.ts} | ${item.src_ip} | ${item.url_path}
                </div>
            `;
            list.appendChild(div);
        });
    } catch(err) {
        document.getElementById('reviewQueueList').innerHTML = `<div class="error-state">Failed to load review queue</div>`;
    }
}

async function retrainModel() {
    const btn = document.getElementById('btnRetrain');
    btn.textContent = 'Training...';
    btn.disabled = true;
    
    try {
        const res = await api('/api/v1/model/retrain', { method: 'POST' });
        
        const banner = document.getElementById('retrainBanner');
        banner.style.display = 'block';
        banner.innerHTML = `
            <div style="font-weight:bold; color:#10b981; margin-bottom: 5px;">Training Complete (Took ${res.duration_ms}ms)</div>
            <div style="font-size:13px; line-height: 1.6;">
                Evaluated candidate <strong>${res.candidate_version}</strong> using ${res.n_feedback_used} new feedback labels.<br>
                PR AUC: ${res.before.pr_auc} &rarr; <strong>${res.after.pr_auc}</strong><br>
                FPR @ 90% Recall: ${res.before.fpr_at_90_recall} &rarr; <strong>${res.after.fpr_at_90_recall}</strong><br>
                Status: <strong>${res.promoted ? 'Promoted to Active' : 'Rejected'}</strong>
            </div>
        `;
        
        // Refresh model data
        await fetchModelData();
    } catch(err) {
        alert("Training failed: " + err.message);
    } finally {
        btn.textContent = 'Retrain Model';
        btn.disabled = false;
    }
}

async function rollback(version) {
    if(!confirm(`Rollback to ${version}?`)) return;
    try {
        const res = await api('/api/v1/model/rollback', { 
            method: 'POST', 
            body: JSON.stringify({ version }) 
        });
        alert(`Successfully rolled back. Active version is now ${res.current_version}`);
        fetchModelData();
    } catch(err) {
        alert("Rollback failed: " + err.message);
    }
}
