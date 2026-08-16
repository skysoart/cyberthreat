let currentWeights = {};

const order = [
    'model_confidence',
    'asset_criticality',
    'exploitability',
    'blast_radius',
    'kill_chain_depth',
    'recency'
];

document.addEventListener('DOMContentLoaded', () => {
    fetchSettings();
});

async function fetchSettings() {
    showLoading('loadingState');
    try {
        const weights = await api('/api/v1/settings/weights');
        currentWeights = weights;
        
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('settingsContent').style.display = 'block';
        
        renderSliders();
        updateSum();
    } catch (err) {
        showError('loadingState', `Failed to load settings: ${err.message}`);
    }
}

function renderSliders() {
    const container = document.getElementById('slidersContainer');
    container.innerHTML = '';
    
    order.forEach(key => {
        const val = currentWeights[key];
        const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        
        container.insertAdjacentHTML('beforeend', `
            <div class="weight-row">
                <div class="weight-label">${label}</div>
                <input type="range" class="weight-slider" id="slider_${key}" min="0" max="1" step="0.05" value="${val}" oninput="handleSliderChange('${key}', this.value)">
                <div class="weight-val" id="val_${key}">${val.toFixed(2)}</div>
            </div>
        `);
    });
}

function handleSliderChange(key, value) {
    const num = parseFloat(value);
    currentWeights[key] = num;
    document.getElementById(`val_${key}`).textContent = num.toFixed(2);
    updateSum();
}

function updateSum() {
    const sum = Object.values(currentWeights).reduce((a, b) => a + b, 0);
    const sumEl = document.getElementById('totalSum');
    const btn = document.getElementById('btnSave');
    
    sumEl.textContent = sum.toFixed(2);
    
    // Check if sum is 1.0 (±0.001)
    if (Math.abs(sum - 1.0) < 0.001) {
        sumEl.className = 'sum-val sum-valid';
        btn.disabled = false;
        btn.textContent = 'Save & Rescore';
    } else {
        sumEl.className = 'sum-val sum-invalid';
        btn.disabled = true;
        btn.textContent = 'Sum must be 1.00';
    }
}

async function saveWeights() {
    const btn = document.getElementById('btnSave');
    btn.disabled = true;
    btn.textContent = 'Saving...';
    document.getElementById('successBanner').style.display = 'none';
    
    try {
        const res = await api('/api/v1/settings/weights', {
            method: 'PUT',
            body: JSON.stringify(currentWeights)
        });
        
        if (res.ok) {
            document.getElementById('successBanner').style.display = 'block';
            document.getElementById('rescoredCount').textContent = res.incidents_rescored;
        }
    } catch(err) {
        alert("Failed to save weights: " + err.message);
    } finally {
        updateSum(); // Reset button state safely
    }
}
