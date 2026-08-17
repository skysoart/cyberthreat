/*
 * adamantine-sensor.js — the browser half of the split sensor.
 *
 *   <script src="/adamantine-sensor.js" data-key="adm_live_demo" defer></script>
 *
 * Collects the 16 BROWSER_FEATURES from backend/ml/features.py and POSTs them
 * to /api/v1/telemetry, where they are fused onto the server-side events for
 * the same session.
 *
 * WHY THIS EXISTS SEPARATELY FROM THE SERVER SENSOR
 * JavaScript cannot see the client's own IP address, its ASN, packet sizes or
 * TLS handshake — those are network-layer facts only the server observes. The
 * server, in turn, cannot see mouse movement or typing rhythm. Neither half is
 * sufficient, and the split is what produces the single most discriminating
 * feature in the model: a scripted attacker hitting the API directly never
 * runs this file, so `browser_telemetry_present` comes back 0.
 *
 * PRIVACY
 * Timings and counts only. Key IDENTITIES are never read, never stored and
 * never transmitted — we record *when* a key was pressed, never *which*. Form
 * values are never touched. That is the honest answer when someone asks what
 * this script does to their users.
 *
 * It must also never break the host page: everything is wrapped, failures are
 * swallowed, and the page works identically if this file 404s.
 */
(function () {
  "use strict";

  var script = document.currentScript ||
    (function () {
      var s = document.getElementsByTagName("script");
      return s[s.length - 1];
    })();

  var API_KEY = (script && script.getAttribute("data-key")) || "adm_live_demo";
  var ENDPOINT = (script && script.getAttribute("data-endpoint")) || "/api/v1/telemetry";
  var FLUSH_MS = 10000;

  // ---------------------------------------------------------------- state

  var t0 = Date.now();
  var s = {
    mouse_move_count: 0,
    mouse_path_len: 0,
    mouse_dirs: [],
    keystroke_count: 0,
    key_gaps: [],
    last_key_at: 0,
    paste_events: 0,
    click_count: 0,
    time_to_first_click_ms: null,
    scroll_events: 0,
    focus_blur_count: 0,
    form_first_touch_at: 0,
    form_fill_ms: null,
    sent: false
  };

  function on(target, type, fn) {
    try {
      target.addEventListener(type, function (e) {
        try { fn(e); } catch (_) { /* never break the host page */ }
      }, { passive: true });
    } catch (_) {}
  }

  // ------------------------------------------------------------- listeners

  var lastX = null, lastY = null;
  on(document, "mousemove", function (e) {
    s.mouse_move_count++;
    if (lastX !== null) {
      var dx = e.clientX - lastX, dy = e.clientY - lastY;
      s.mouse_path_len += Math.sqrt(dx * dx + dy * dy);
      // Direction of travel, quantised to 16 buckets. Human movement wanders
      // across many buckets; a script that "moves the mouse" usually does not.
      if (dx || dy) {
        var bucket = Math.floor((Math.atan2(dy, dx) + Math.PI) / (Math.PI / 8));
        if (s.mouse_dirs.length < 4000) s.mouse_dirs.push(bucket);
      }
    }
    lastX = e.clientX;
    lastY = e.clientY;
  });

  on(document, "keydown", function () {
    // Timing only. e.key is deliberately never read.
    var now = Date.now();
    if (s.last_key_at) {
      var gap = now - s.last_key_at;
      if (gap < 5000 && s.key_gaps.length < 2000) s.key_gaps.push(gap);
    }
    s.last_key_at = now;
    s.keystroke_count++;
    if (!s.form_first_touch_at) s.form_first_touch_at = now;
  });

  on(document, "paste", function () {
    s.paste_events++;
    if (!s.form_first_touch_at) s.form_first_touch_at = Date.now();
  });

  on(document, "click", function () {
    s.click_count++;
    if (s.time_to_first_click_ms === null) s.time_to_first_click_ms = Date.now() - t0;
  });

  on(document, "scroll", function () { s.scroll_events++; });
  on(window, "focus", function () { s.focus_blur_count++; });
  on(window, "blur", function () { s.focus_blur_count++; });

  on(document, "submit", function () {
    if (s.form_first_touch_at) s.form_fill_ms = Date.now() - s.form_first_touch_at;
    flush(true);
  });

  // ------------------------------------------------------------ derived

  function shannon(values) {
    if (!values.length) return 0;
    var counts = {}, i;
    for (i = 0; i < values.length; i++) counts[values[i]] = (counts[values[i]] || 0) + 1;
    var n = values.length, h = 0;
    for (var k in counts) {
      if (Object.prototype.hasOwnProperty.call(counts, k)) {
        var p = counts[k] / n;
        h -= p * Math.log(p) / Math.LN2;
      }
    }
    return Math.round(h * 100) / 100;
  }

  function stats(a) {
    if (!a.length) return { mean: null, std: null };
    var sum = 0, i;
    for (i = 0; i < a.length; i++) sum += a[i];
    var mean = sum / a.length, v = 0;
    for (i = 0; i < a.length; i++) v += (a[i] - mean) * (a[i] - mean);
    return {
      mean: Math.round(mean * 10) / 10,
      std: Math.round(Math.sqrt(v / a.length) * 10) / 10
    };
  }

  function snapshot() {
    var k = stats(s.key_gaps);
    return {
      mouse_move_count: s.mouse_move_count,
      mouse_path_entropy: shannon(s.mouse_dirs),
      keystroke_count: s.keystroke_count,
      // A human's typing rhythm is irregular. A script's is not — which is why
      // the standard deviation matters more than the mean.
      keystroke_interval_mean: k.mean,
      keystroke_interval_std: k.std,
      form_fill_ms: s.form_fill_ms,
      paste_events: s.paste_events,
      click_count: s.click_count,
      time_to_first_click_ms: s.time_to_first_click_ms,
      scroll_events: s.scroll_events,
      page_dwell_ms: Date.now() - t0,
      focus_blur_count: s.focus_blur_count,
      screen_w: (window.screen && window.screen.width) || null,
      screen_h: (window.screen && window.screen.height) || null,
      tz_offset: new Date().getTimezoneOffset(),
      hardware_concurrency: navigator.hardwareConcurrency || null
    };
  }

  // -------------------------------------------------------------- session

  function sessionId() {
    try {
      var m = document.cookie.match(/(?:^|;\s*)session_id=([^;]+)/);
      if (m) return decodeURIComponent(m[1]);
      var k = "adamantine_sid", v = sessionStorage.getItem(k);
      if (!v) {
        v = "s_";
        for (var i = 0; i < 8; i++) v += "0123456789abcdef"[Math.floor(Math.random() * 16)];
        sessionStorage.setItem(k, v);
      }
      return v;
    } catch (_) {
      return null;
    }
  }

  // ---------------------------------------------------------------- flush

  function flush(useBeacon) {
    var body;
    try {
      body = JSON.stringify({
        session_id: sessionId(),
        page: location.pathname,
        browser: snapshot()
      });
    } catch (_) {
      return;
    }

    // sendBeacon survives page unload but cannot set the API key header, so we
    // fall back to fetch with keepalive wherever headers matter.
    if (useBeacon && navigator.sendBeacon) {
      try {
        var blob = new Blob([body], { type: "application/json" });
        if (navigator.sendBeacon(ENDPOINT + "?key=" + encodeURIComponent(API_KEY), blob)) {
          return;
        }
      } catch (_) {}
    }

    try {
      fetch(ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Adamantine-Key": API_KEY },
        body: body,
        keepalive: true,
        credentials: "same-origin"
      }).catch(function () { /* telemetry must never surface an error */ });
    } catch (_) {}
  }

  // Send an early sample so short visits are not invisible, then on a timer,
  // then once more on the way out.
  setTimeout(function () { flush(false); }, 2500);
  setInterval(function () { flush(false); }, FLUSH_MS);
  on(document, "visibilitychange", function () {
    if (document.visibilityState === "hidden") flush(true);
  });
  on(window, "pagehide", function () { flush(true); });

  window.__adamantine = { snapshot: snapshot, flush: flush };
})();
