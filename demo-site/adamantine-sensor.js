(function() {
    // Collect browser telemetry to simulate Adamantine sensor
    
    // Attempt to extract the API key from the script tag's data-key attribute
    const currentScript = document.currentScript || document.querySelector('script[src*="adamantine-sensor.js"]');
    const apiKey = currentScript ? currentScript.getAttribute('data-key') : 'adm_live_demo';

    let telemetry = {
        mouse_move_count: 0,
        mouse_path_entropy: 0.0,
        keystroke_count: 0,
        keystroke_intervals: [],
        form_fill_start: null,
        form_fill_ms: 0,
        paste_events: 0,
        click_count: 0,
        time_to_first_click_ms: 0,
        scroll_events: 0,
        focus_blur_count: 0,
        page_load_time: Date.now()
    };

    let lastKeyTime = 0;
    
    document.addEventListener('mousemove', () => { telemetry.mouse_move_count++; });
    
    document.addEventListener('click', () => {
        if (telemetry.click_count === 0) {
            telemetry.time_to_first_click_ms = Date.now() - telemetry.page_load_time;
        }
        telemetry.click_count++;
    });

    document.addEventListener('keydown', (e) => {
        telemetry.keystroke_count++;
        const now = Date.now();
        if (lastKeyTime > 0) {
            telemetry.keystroke_intervals.push(now - lastKeyTime);
        }
        lastKeyTime = now;
        
        if (!telemetry.form_fill_start && e.target.tagName === 'INPUT') {
            telemetry.form_fill_start = now;
        }
    });

    document.addEventListener('paste', () => { telemetry.paste_events++; });
    document.addEventListener('scroll', () => { telemetry.scroll_events++; });
    window.addEventListener('blur', () => { telemetry.focus_blur_count++; });
    window.addEventListener('focus', () => { telemetry.focus_blur_count++; });

    function getSessionId() {
        // Read simple cookie for demo or create one
        let match = document.cookie.match(new RegExp('(^| )session_id=([^;]+)'));
        if (match) return match[2];
        return "s_anon_" + Math.random().toString(36).substring(2, 10);
    }

    function calculateStats(arr) {
        if (arr.length === 0) return { mean: 0, std: 0 };
        const sum = arr.reduce((a, b) => a + b, 0);
        const mean = sum / arr.length;
        const sqDiffs = arr.map(val => Math.pow(val - mean, 2));
        const std = Math.sqrt(sqDiffs.reduce((a, b) => a + b, 0) / arr.length);
        return { mean, std };
    }

    function sendTelemetry() {
        const keyStats = calculateStats(telemetry.keystroke_intervals);
        
        if (telemetry.form_fill_start) {
            telemetry.form_fill_ms = Date.now() - telemetry.form_fill_start;
        }

        const payload = {
            session_id: getSessionId(),
            page: window.location.pathname,
            browser: {
                mouse_move_count: telemetry.mouse_move_count,
                mouse_path_entropy: 4.82, // Hardcoded for demo simplicity
                keystroke_count: telemetry.keystroke_count,
                keystroke_interval_mean: keyStats.mean,
                keystroke_interval_std: keyStats.std,
                form_fill_ms: telemetry.form_fill_ms,
                paste_events: telemetry.paste_events,
                click_count: telemetry.click_count,
                time_to_first_click_ms: telemetry.time_to_first_click_ms,
                scroll_events: telemetry.scroll_events,
                page_dwell_ms: Date.now() - telemetry.page_load_time,
                focus_blur_count: telemetry.focus_blur_count,
                screen_w: window.screen.width,
                screen_h: window.screen.height,
                tz_offset: new Date().getTimezoneOffset(),
                hardware_concurrency: navigator.hardwareConcurrency || 4
            }
        };

        // Fire and forget beacon
        if (navigator.sendBeacon) {
            const headers = { type: 'application/json' };
            const blob = new Blob([JSON.stringify(payload)], headers);
            // sendBeacon doesn't easily set custom headers like X-Adamantine-Key. 
            // So we'll use fetch with keepalive.
        }
        
        fetch('/api/v1/telemetry', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Adamantine-Key': apiKey
            },
            body: JSON.stringify(payload),
            keepalive: true
        }).catch(err => console.error("Telemetry error", err));
    }

    // Send telemetry periodically and on unload
    setInterval(sendTelemetry, 15000); // every 15s for demo
    window.addEventListener('beforeunload', sendTelemetry);
})();
