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
