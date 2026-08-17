"""
backend/app/services/detect.py — Team 2.

Live classification for traffic arriving right now, plus the two things the
middleware cannot work out on its own: which asset a path belongs to, and
whether a browser session was involved.

Three responsibilities:

  1. SESSION FUSION. The sensor POSTs browser telemetry to /api/v1/telemetry as
     its own row, so a server-side event has no idea whether a real browser was
     driving it. Without fusion every request looks like a bot, including a
     human typing their password. We keep a short-lived in-memory map of
     session_id -> browser features and merge it into server events.

  2. CLASSIFICATION. A rule layer over the same 47 features, used when no
     trained model artifact is present. This is deliberate, not a stopgap:
     the demo must work before the model exists, the rules are inspectable, and
     a judge asking "what fired?" gets a threshold rather than a shrug. When
     ml/artifacts/current.joblib appears, the model takes over and the rules
     become the fallback.

  3. EVIDENCE. Per-prediction reasons in plain English, as feature deviation
     from a benign baseline. Exact, deterministic, and impossible to crash
     mid-demo — which a SHAP call is not.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from backend.ml.features import BROWSER_FEATURES

# ---------------------------------------------------------------- fusion

_TTL_SECONDS = 900          # a session's telemetry stays fresh for 15 minutes
_lock = threading.Lock()
_sessions: dict[str, tuple[float, dict]] = {}


def remember_browser(session_id: Optional[str], browser: dict[str, Any]) -> None:
    """Called by /api/v1/telemetry. Stores the newest telemetry for a session."""
    if not session_id:
        return
    with _lock:
        _sessions[session_id] = (time.time(), dict(browser))
        if len(_sessions) > 5000:                       # bound the map
            cutoff = time.time() - _TTL_SECONDS
            for k in [k for k, (t, _) in _sessions.items() if t < cutoff]:
                _sessions.pop(k, None)


def browser_for(session_id: Optional[str]) -> Optional[dict]:
    """Newest browser telemetry for a session, or None if the sensor never ran."""
    if not session_id:
        return None
    with _lock:
        hit = _sessions.get(session_id)
    if hit is None:
        return None
    ts, feats = hit
    if time.time() - ts > _TTL_SECONDS:
        return None
    return feats


def fuse(server_features: dict, session_id: Optional[str]) -> dict:
    """
    Merge browser telemetry into a server-observed feature dict.

    Absent telemetry leaves all 16 browser features as None — never 0. Writing
    0 would claim the visitor moved the mouse zero times, when in fact no
    browser ran at all, and those are very different statements.
    """
    browser = browser_for(session_id)
    out = dict(server_features)
    if browser:
        for k in BROWSER_FEATURES:
            out[k] = browser.get(k)
        out["browser_telemetry_present"] = 1
    else:
        for k in BROWSER_FEATURES:
            out.setdefault(k, None)
        out["browser_telemetry_present"] = 0
    return out


# ------------------------------------------------------------ asset routing

# Longest prefix wins. Mirrors the Sample Store route table; an event with no
# asset gets asset_criticality 0.1, which understates every real incident.
_ASSET_ROUTES: list[tuple[str, str]] = [
    ("/api/v1/auth", "auth-service"),
    ("/login", "auth-service"),
    ("/register", "auth-service"),
    ("/account", "auth-service"),
    ("/admin", "admin-portal"),
    ("/api/v1/store/checkout", "payments-api"),
    ("/checkout", "checkout-web"),
    ("/cart", "checkout-web"),
    ("/api/v1/store/products", "catalogue-api"),
    ("/products", "catalogue-api"),
    ("/search", "search-service"),
    ("/actuator", "metrics-agent"),
    ("/wp-admin", "blog-cms"),
    ("/wp-content", "blog-cms"),
    ("/blog", "blog-cms"),
]


def asset_for(url_path: str) -> str:
    base = (url_path or "/").split("?")[0]
    best, best_len = "cdn-edge", -1
    for prefix, asset in _ASSET_ROUTES:
        if base.startswith(prefix) and len(prefix) > best_len:
            best, best_len = asset, len(prefix)
    return best


# ---------------------------------------------------------------- baselines
#
# (low, high) range seen in ordinary traffic. Used only to phrase evidence —
# "47, normal range 0-2" is far more persuasive to a non-ML judge than a
# signed Shapley value, and it cannot throw an exception on stage.

BASELINE: dict[str, tuple[float, float]] = {
    "req_rate_10s": (0, 3), "req_rate_60s": (3, 12), "req_rate_300s": (8, 40),
    "auth_fail_ip_60s": (0, 2), "auth_fail_user_60s": (0, 2),
    "distinct_users_tried_60s": (1, 1), "auth_success_after_fails": (0, 0),
    "unique_paths_60s": (2, 6), "p404_ratio_60s": (0.0, 0.04),
    "path_entropy": (1.2, 2.1), "sensitive_path_hit": (0, 0),
    "interarrival_std_ms": (800, 4000), "payload_bytes": (0, 900),
    "header_count": (9, 14), "ua_known_tool": (0, 0), "ua_missing": (0, 0),
    "asn_is_hosting": (0, 0), "ip_reputation_hit": (0, 0), "is_tor_exit": (0, 0),
    "browser_telemetry_present": (1, 1),
    "mouse_path_entropy": (3.8, 5.4), "keystroke_interval_std": (60, 180),
    "form_fill_ms": (6000, 24000), "paste_events": (0, 1),
}

NOTE: dict[str, str] = {
    "browser_telemetry_present": "no JavaScript executed — not a browser",
    "auth_fail_ip_60s": "failed logins from this address in 60s",
    "auth_fail_user_60s": "failed logins against this account in 60s",
    "distinct_users_tried_60s": "distinct accounts attempted from one address",
    "auth_success_after_fails": "successful login immediately after failures",
    "req_rate_10s": "requests in the last 10 seconds",
    "req_rate_60s": "requests in the last 60 seconds",
    "p404_ratio_60s": "share of requests returning 404",
    "unique_paths_60s": "distinct paths requested in 60s",
    "sensitive_path_hit": "requested a sensitive or configuration path",
    "path_entropy": "paths do not follow site navigation structure",
    "interarrival_std_ms": "machine-uniform request timing",
    "asn_is_hosting": "datacentre origin, not residential",
    "ua_known_tool": "user agent matches a known automation tool",
    "ua_missing": "no user agent supplied",
    "ip_reputation_hit": "source address on a threat-intel blocklist",
    "is_tor_exit": "source is a Tor exit node",
    "mouse_path_entropy": "very little mouse movement for the session length",
    "keystroke_interval_std": "typing rhythm too regular for a human",
    "form_fill_ms": "form completed unusually fast",
    "paste_events": "credentials pasted rather than typed",
}


def _f(features: dict, key: str, default: float = 0.0) -> float:
    v = features.get(key)
    if v is None:
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def evidence_for(features: dict, keys: list[str]) -> list[dict]:
    """Plain-English reasons, strongest deviation first."""
    out = []
    for k in keys:
        v = features.get(k)
        lo, hi = BASELINE.get(k, (0.0, 1.0))
        if v is None:
            dev = "absent"
        else:
            fv = _f(features, k)
            if fv > hi and hi > 0:
                dev = f"{fv / max(hi, 1e-9):.0f}x above baseline"
            elif fv > hi:
                dev = "present"
            elif fv < lo and fv > 0:
                dev = f"{lo / max(fv, 1e-9):.0f}x below baseline"
            elif fv < lo:
                dev = "absent"
            else:
                dev = "within baseline"
        rng = f"{lo:g}" if lo == hi else f"{lo:g}-{hi:g}"
        out.append({"feature": k, "value": v, "baseline": rng,
                    "deviation": dev, "note": NOTE.get(k, "")})
    return out


# --------------------------------------------------------------- rule layer

def _rules(f: dict, url_path: str, http_status: int) -> list[tuple[str, float, list[str]]]:
    """(class, confidence, evidence keys) for every rule that fires."""
    hits: list[tuple[str, float, list[str]]] = []
    no_js = _f(f, "browser_telemetry_present", 1.0) == 0
    path = (url_path or "").split("?")[0]

    r10, r60 = _f(f, "req_rate_10s"), _f(f, "req_rate_60s")
    fails_ip = _f(f, "auth_fail_ip_60s")
    fails_user = _f(f, "auth_fail_user_60s")
    users_tried = _f(f, "distinct_users_tried_60s", 1.0)
    p404 = _f(f, "p404_ratio_60s")
    paths = _f(f, "unique_paths_60s")
    sensitive = _f(f, "sensitive_path_hit")
    hosting = _f(f, "asn_is_hosting")
    tool = _f(f, "ua_known_tool") or _f(f, "ua_missing")

    # Volumetric flood — many requests, one endpoint.
    if r10 >= 40 or r60 >= 250:
        conf = min(0.99, 0.75 + r10 / 400)
        hits.append(("flood", conf,
                     ["req_rate_10s", "req_rate_60s", "payload_bytes",
                      "browser_telemetry_present"]))

    # Credential stuffing — many ACCOUNTS from one source.
    if users_tried >= 3 and fails_ip >= 3:
        conf = min(0.96, 0.62 + users_tried * 0.05 + (0.12 if no_js else 0))
        hits.append(("credential_stuffing", conf,
                     ["distinct_users_tried_60s", "auth_fail_ip_60s",
                      "browser_telemetry_present", "asn_is_hosting"]))

    # Brute force — many attempts against ONE account.
    if fails_user >= 4 and users_tried <= 2:
        conf = min(0.97, 0.60 + fails_user * 0.05 + (0.10 if no_js else 0))
        hits.append(("brute_force", conf,
                     ["auth_fail_user_60s", "auth_fail_ip_60s",
                      "browser_telemetry_present", "interarrival_std_ms"]))

    # Directory scanning — enumeration, mostly 404s.
    if p404 >= 0.5 and paths >= 6:
        conf = min(0.97, 0.65 + p404 * 0.25)
        hits.append(("dir_scan", conf,
                     ["p404_ratio_60s", "unique_paths_60s", "path_entropy",
                      "sensitive_path_hit"]))

    # Low and slow — sensitive paths, deliberately under the rate limits.
    if sensitive and r60 <= 12 and no_js:
        conf = 0.70 + (0.12 if hosting else 0) + (0.06 if tool else 0)
        if http_status == 200:
            conf += 0.08                      # the probe actually landed
        hits.append(("slow_recon", min(0.95, conf),
                     ["sensitive_path_hit", "browser_telemetry_present",
                      "req_rate_60s", "asn_is_hosting"]))

    # Systematic scraping — high volume, resolving fine, no browser.
    if no_js and r60 >= 15 and paths >= 8 and p404 < 0.3:
        hits.append(("scraper", min(0.88, 0.50 + r60 / 120),
                     ["req_rate_60s", "unique_paths_60s",
                      "browser_telemetry_present", "interarrival_std_ms"]))

    # Automated account creation.
    if path.startswith("/register") and no_js and r60 >= 5:
        hits.append(("credential_stuffing", min(0.90, 0.60 + r60 / 60),
                     ["req_rate_60s", "browser_telemetry_present",
                      "asn_is_hosting", "interarrival_std_ms"]))

    return hits


# Path-aware technique assignment. Overrides the class-based map in
# attack_map.yaml when the path says something more specific.
def technique_for(pred_class: str, url_path: str, features: dict,
                  http_status: int) -> Optional[str]:
    path = (url_path or "").split("?")[0]
    if _f(features, "auth_success_after_fails") == 1:
        return "T1078"                                  # Valid Accounts
    if path.startswith("/register"):
        return "T1136"                                  # Create Account
    if _f(features, "sensitive_path_hit") == 1 and http_status == 200:
        return "T1190"                                  # Exploit Public-Facing App
    return {
        "dir_scan": "T1595.002", "slow_recon": "T1595.002", "scraper": "T1592",
        "brute_force": "T1110.001", "credential_stuffing": "T1110.004",
        "flood": "T1498",
    }.get(pred_class)


_model = None
_model_loaded = False


def _load_model():
    global _model, _model_loaded
    if _model_loaded:
        return _model
    _model_loaded = True
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "ml" / "artifacts" / "current.joblib"
    if path.exists():
        try:
            import joblib
            _model = joblib.load(path).get("model")
        except Exception:
            _model = None
    return _model


def classify(features: dict, url_path: str, http_status: int
             ) -> tuple[str, float, list[dict], Optional[str]]:
    """
    -> (pred_class, confidence, evidence, attack_technique)

    Uses the trained model when one exists, the rule layer otherwise. Either
    way the evidence is produced the same way, so the UI is identical and the
    explanation never depends on the model being present.
    """
    model = _load_model()
    if model is not None:
        try:
            import numpy as np
            from backend.ml.features import to_vector
            proba = model.predict_proba(to_vector(features).reshape(1, -1))[0]
            classes = list(model.classes_)
            idx = int(np.argmax(proba))
            cls, conf = classes[idx], float(proba[idx])
            keys = [k for k in ("browser_telemetry_present", "auth_fail_ip_60s",
                                "req_rate_60s", "asn_is_hosting") if k in features]
            return cls, conf, evidence_for(features, keys), \
                technique_for(cls, url_path, features, http_status)
        except Exception:
            pass                                        # fall through to rules

    hits = _rules(features, url_path, http_status)
    if not hits:
        return "normal", 0.95, evidence_for(
            features, ["browser_telemetry_present", "req_rate_60s"]), None

    cls, conf, keys = max(hits, key=lambda h: h[1])
    return cls, round(conf, 2), evidence_for(features, keys), \
        technique_for(cls, url_path, features, http_status)
