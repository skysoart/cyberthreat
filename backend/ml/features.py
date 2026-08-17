"""
backend/ml/features.py  — Team 2 owns the list; Team 1 imports it.
FEATURE_NAMES is the single source of truth for the 47-feature vector.
DO NOT rename or reorder without both teams agreeing.
"""

# 30 server-side features — populated by backend/app/middleware.py
SERVER_FEATURES = [
    "req_rate_10s",
    "req_rate_60s",
    "req_rate_300s",
    "auth_fail_ip_60s",
    "auth_fail_user_60s",
    "distinct_users_tried_60s",
    "auth_success_after_fails",
    "unique_paths_60s",
    "p404_ratio_60s",
    "path_entropy",
    "sensitive_path_hit",
    "interarrival_mean_ms",
    "interarrival_std_ms",
    "payload_bytes",
    "payload_bytes_std",
    "resp_bytes_60s",
    "header_count",
    "ua_missing",
    "ua_known_tool",
    "ua_entropy",
    "accept_lang_missing",
    "header_order_hash_known",
    "asn_is_hosting",
    "country_risk",
    "ip_reputation_hit",
    "is_tor_exit",
    "session_age_s",
    "requests_this_session",
    "hour_of_day",
    "is_off_hours",
]

# 16 browser features — populated by widget/adamantine-sensor.js via POST /api/v1/telemetry
# Absent (no sensor ran) → all 16 are None, NOT zero.
BROWSER_FEATURES = [
    "mouse_move_count",
    "mouse_path_entropy",
    "keystroke_count",
    "keystroke_interval_mean",
    "keystroke_interval_std",
    "form_fill_ms",
    "paste_events",
    "click_count",
    "time_to_first_click_ms",
    "scroll_events",
    "page_dwell_ms",
    "focus_blur_count",
    "screen_w",
    "screen_h",
    "tz_offset",
    "hardware_concurrency",
]

# 1 fusion feature — set by Team 1 at the point of fusing browser telemetry
FUSION_FEATURES = [
    "browser_telemetry_present",
]

# Single ordered list used by Team 2's model training and inference
FEATURE_NAMES = SERVER_FEATURES + BROWSER_FEATURES + FUSION_FEATURES  # 47 total

assert len(FEATURE_NAMES) == 47, f"Expected 47 features, got {len(FEATURE_NAMES)}"
assert len(set(FEATURE_NAMES)) == 47, "Duplicate feature name detected"

N_FEATURES = len(FEATURE_NAMES)
FEATURE_INDEX = {name: i for i, name in enumerate(FEATURE_NAMES)}

# Only browser features may legitimately be NaN. If the server did not observe
# something, that is a bug in the middleware, not missing data.
NAN_ALLOWED = set(BROWSER_FEATURES)


# ---------------------------------------------------------------------------
# Helpers — used by ml/train.py and app/services/engine.py
# ---------------------------------------------------------------------------

import math
from typing import Any, Optional


def shannon_entropy(s: str) -> float:
    """Character-level Shannon entropy — hostnames, URL paths, user agents."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def to_vector(features: dict[str, Any]):
    """
    Dict -> ordered float vector, in FEATURE_NAMES order.

    Missing browser features become NaN, which HistGradientBoostingClassifier
    handles natively. Missing server features become 0.0 — the server always
    observes something, so absence there means the value genuinely was zero.

    Writing 0 for absent browser telemetry would be a lie: it would claim the
    visitor moved the mouse zero times, when in fact no browser ran at all.
    """
    import numpy as np

    out = np.empty(N_FEATURES, dtype=np.float64)
    for i, name in enumerate(FEATURE_NAMES):
        v = features.get(name)
        if v is None:
            out[i] = np.nan if name in NAN_ALLOWED else 0.0
        elif isinstance(v, bool):
            out[i] = 1.0 if v else 0.0
        else:
            try:
                out[i] = float(v)
            except (TypeError, ValueError):
                out[i] = np.nan if name in NAN_ALLOWED else 0.0
    return out


def matrix_from_events(events):
    """Stack features_json from a list of Event rows into an (n, 47) matrix."""
    import json
    import numpy as np
    return np.vstack([to_vector(json.loads(e.features_json or "{}")) for e in events])


def empty_browser() -> dict[str, Optional[float]]:
    """No sensor ran. Unknown is not zero."""
    return {k: None for k in BROWSER_FEATURES}


def validate(features: dict[str, Any]) -> list[str]:
    """
    Self-check for Team 1's middleware and sensor. Returns a list of problems;
    empty means the feature dict is contract-compliant.
    """
    problems = []
    unknown = set(features) - set(FEATURE_NAMES)
    if unknown:
        problems.append(f"unknown feature keys: {sorted(unknown)}")
    missing_server = [f for f in SERVER_FEATURES if f not in features]
    if missing_server:
        problems.append(f"missing server features: {missing_server}")
    if "browser_telemetry_present" not in features:
        problems.append("missing browser_telemetry_present")
    zeroed = [f for f in BROWSER_FEATURES
              if features.get(f) == 0 and features.get("browser_telemetry_present") == 0]
    if zeroed:
        problems.append(
            f"browser features zeroed instead of None while telemetry absent: {zeroed}")
    return problems
