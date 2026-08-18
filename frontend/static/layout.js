
// ---------------------------------------------------------------------------
// Timestamps.
//
// The API returns ISO-8601 UTC ("2026-08-18T07:54:03Z"). Stripping the T and
// the Z shows the raw UTC clock, so an analyst in IST saw their own activity
// timestamped 5.5 hours in the past and reasonably concluded the dashboard
// was not updating. Always parse and render in the viewer's local zone.
// ---------------------------------------------------------------------------
function fmtTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleTimeString([], { hour12: false });
}

function fmtDateTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString([], { hour12: false });
}

document.addEventListener("DOMContentLoaded", () => {
    const sidebarHtml = `
        <aside class="sidebar">
            <div class="logo">
                <div class="logo-icon"></div>
                <h2>Adamantine</h2>
            </div>
            <nav>
                <a href="index.html" id="nav-overview">Overview</a>
                <a href="incidents.html" id="nav-incidents">Incidents</a>
                <a href="model.html" id="nav-model">Model</a>
                <a href="metrics.html" id="nav-metrics">Metrics</a>
                <a href="settings.html" id="nav-settings">Settings</a>
            </nav>
            <div class="tenant-info">
                <small>Tenant</small>
                <div>Sample Store</div>
            </div>
        </aside>
    `;

    // Inject sidebar into the .app-container
    const container = document.querySelector('.app-container');
    if (container) {
        container.insertAdjacentHTML('afterbegin', sidebarHtml);
    }

    // Set active class based on current path
    const path = window.location.pathname;
    let activeId = 'nav-overview';
    if (path.includes('incidents.html') || path.includes('incident.html')) activeId = 'nav-incidents';
    else if (path.includes('model.html')) activeId = 'nav-model';
    else if (path.includes('metrics.html')) activeId = 'nav-metrics';
    else if (path.includes('settings.html')) activeId = 'nav-settings';

    const activeEl = document.getElementById(activeId);
    if (activeEl) activeEl.classList.add('active');
});

// UI Utilities shared across pages
function showLoading(containerId) {
    const el = document.getElementById(containerId);
    if (el) el.innerHTML = `<div class="loading-state">Loading data...</div>`;
}

function showError(containerId, message = "Failed to load data") {
    const el = document.getElementById(containerId);
    if (el) el.innerHTML = `<div class="error-state">⚠️ ${message}</div>`;
}

function showEmpty(containerId, message = "No data available") {
    const el = document.getElementById(containerId);
    if (el) el.innerHTML = `<div class="empty-state">${message}</div>`;
}
