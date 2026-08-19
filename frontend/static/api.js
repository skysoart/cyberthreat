const USE_MOCKS = false; // flip to false when the backend is running

const MOCK_MAP = {
    '/api/v1/overview': 'overview.json',
    '/api/v1/incidents': 'incidents.json',
    '/api/v1/model': 'model.json',
    '/api/v1/metrics': 'metrics.json',
    '/api/v1/review-queue': 'review-queue.json',
    '/api/v1/settings/weights': 'settings-weights.json'
};

async function api(path, options = {}) {
    if (USE_MOCKS) {
        // Handle mocked POST/PUT requests
        if (options.method && options.method !== 'GET') {
            await new Promise(r => setTimeout(r, 300)); // mock network delay
            
            if (path.includes('/feedback')) {
                const id = path.split('/')[4];
                return { ok: true, incident_id: id, new_status: "false_positive", labels_pending: 12 };
            }
            if (path === '/api/v1/model/retrain') {
                return {
                    candidate_version: "v1.0.4", promoted: true, rejection_reason: null,
                    before: { pr_auc: 0.981, fpr_at_90_recall: 0.012 },
                    after:  { pr_auc: 0.986, fpr_at_90_recall: 0.011 },
                    n_feedback_used: 48, duration_ms: 2840
                };
            }
            if (path === '/api/v1/model/rollback') {
                // Parse body to get version
                const body = JSON.parse(options.body);
                return { ok: true, current_version: body.version };
            }
            if (path === '/api/v1/settings/weights') {
                return { ok: true, incidents_rescored: 41 };
            }
            return { ok: true };
        }

        // Handle GET requests
        let file = MOCK_MAP[path];
        
        // Special routing for dynamic incident detail
        if (path.startsWith('/api/v1/incidents/') && path.split('/').length === 5) {
            const id = path.split('/')[4];
            if (id === 'INC-0187') {
                file = 'incident-INC-0187.json';
            } else {
                throw new Error("MOCK_NOT_FOUND"); // Special error for graceful degradation
            }
        }
        
        if (!file) throw new Error(`No mock mapped for ${path}`);
        
        const res = await fetch(`mocks/${file}`);
        if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
        return await res.json();
    }
    
    // Live API.
    //
    // Relative URL, not a hardcoded http://localhost:8000 — the dashboard is
    // served from the same origin, and hardcoding the host made every request
    // cross-origin when the page was opened on 127.0.0.1 instead of localhost.
    //
    // A JSON string body needs an explicit Content-Type. Without it fetch sends
    // text/plain, FastAPI's Body(...) cannot parse it, and every POST came back
    // 422 — which is why "Failed to submit feedback" appeared on every click.
    const opts = { ...options };
    if (opts.body && typeof opts.body === 'string') {
        opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    }
    const res = await fetch(path, opts);
    if (!res.ok) {
        let detail = '';
        try { detail = (await res.json()).detail || ''; } catch (_) {}
        throw new Error(`HTTP ${res.status}${detail ? ': ' + detail : ''}`);
    }
    return await res.json();
}
