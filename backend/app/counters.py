"""
backend/app/counters.py  — Team 1
In-memory rolling rate counters keyed by IP.
Uses collections.deque — DO NOT query the database for rate math.
Designed to be replaceable by Redis later without changing the interface.
"""
import time
import math
from collections import defaultdict, deque
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Tuneable windows (seconds)
# ---------------------------------------------------------------------------
_WINDOW_10 = 10
_WINDOW_60 = 60
_WINDOW_300 = 300


class _RollingDeque:
    """Thread-unsafe, single-process rolling window of timestamps."""

    def __init__(self, window_s: int):
        self._window = window_s
        self._ts: deque = deque()

    def push(self, t: Optional[float] = None) -> None:
        t = t or time.monotonic()
        self._ts.append(t)
        self._evict(t)

    def _evict(self, now: float) -> None:
        cutoff = now - self._window
        while self._ts and self._ts[0] < cutoff:
            self._ts.popleft()

    def count(self) -> int:
        self._evict(time.monotonic())
        return len(self._ts)

    def timestamps(self) -> list:
        self._evict(time.monotonic())
        return list(self._ts)


class IPRateState:
    """Per-IP mutable state. Created lazily."""

    __slots__ = (
        "req_10", "req_60", "req_300",
        "auth_fail_60", "auth_success_after_fail",
        "paths_60", "statuses_60", "resp_bytes_60",
        "payload_bytes_history",
        "session_start", "session_req_count",
        "_users_tried",
        "_last_auth_failed", "_last_email_tried"
    )

    def __init__(self):
        self.req_10 = _RollingDeque(_WINDOW_10)
        self.req_60 = _RollingDeque(_WINDOW_60)
        self.req_300 = _RollingDeque(_WINDOW_300)
        self.auth_fail_60: _RollingDeque = _RollingDeque(_WINDOW_60)
        self.auth_success_after_fail: bool = False
        self.paths_60: deque = deque()           # (ts, path) tuples
        self.statuses_60: deque = deque()        # (ts, status_code)
        self.resp_bytes_60: deque = deque()      # (ts, bytes)
        self.payload_bytes_history: deque = deque(maxlen=100)
        self.session_start: Optional[float] = None
        self.session_req_count: int = 0
        self._users_tried: deque = deque()
        self._last_auth_failed: bool = False
        self._last_email_tried: str = ""


class RateCounter:
    """Global in-memory rate counter. One instance created at import time."""

    def __init__(self):
        self._state: Dict[str, IPRateState] = defaultdict(IPRateState)
        self._user_fails: Dict[str, _RollingDeque] = defaultdict(lambda: _RollingDeque(_WINDOW_60))

    def _s(self, ip: str) -> IPRateState:
        return self._state[ip]

    # ------------------------------------------------------------------
    # Called by middleware on every request BEFORE response
    # ------------------------------------------------------------------
    def record_request(self, ip: str, path: str, payload_bytes: int,
                       session_id: Optional[str] = None) -> None:
        st = self._s(ip)
        now = time.monotonic()
        st.req_10.push(now)
        st.req_60.push(now)
        st.req_300.push(now)

        # Session tracking
        if st.session_start is None:
            st.session_start = now
        st.session_req_count += 1

        # Path + payload tracking for entropy / 404 ratio
        cutoff = now - _WINDOW_60
        st.paths_60.append((now, path))
        while st.paths_60 and st.paths_60[0][0] < cutoff:
            st.paths_60.popleft()

        st.payload_bytes_history.append(payload_bytes)

    def record_response(self, ip: str, status_code: int, resp_bytes: int) -> None:
        now = time.monotonic()
        st = self._s(ip)
        cutoff = now - _WINDOW_60

        st.statuses_60.append((now, status_code))
        while st.statuses_60 and st.statuses_60[0][0] < cutoff:
            st.statuses_60.popleft()

        st.resp_bytes_60.append((now, resp_bytes))
        while st.resp_bytes_60 and st.resp_bytes_60[0][0] < cutoff:
            st.resp_bytes_60.popleft()

    def record_auth_fail(self, ip: str, email: str = "") -> None:
        now = time.monotonic()
        st = self._s(ip)
        st.auth_fail_60.push(now)
        st._last_auth_failed = True
        st._last_email_tried = email
        if email:
            cutoff = now - _WINDOW_60
            st._users_tried.append((now, email))
            while st._users_tried and st._users_tried[0][0] < cutoff:
                st._users_tried.popleft()
            self._user_fails[email].push(now)

    def record_auth_success(self, ip: str) -> None:
        st = self._s(ip)
        if st._last_auth_failed:
            st.auth_success_after_fail = True
        st._last_auth_failed = False

    # ------------------------------------------------------------------
    # Feature extraction — returns a dict keyed by SERVER_FEATURES names
    # ------------------------------------------------------------------
    def get_features(self, ip: str, path: str, payload_bytes: int,
                     user_agent: Optional[str],
                     accept_lang: Optional[str],
                     header_count: int,
                     session_id: Optional[str],
                     ip_reputation_hit: bool = False,
                     is_tor_exit: bool = False,
                     asn_is_hosting: bool = False,
                     country_risk: float = 0.0) -> dict:
        st = self._s(ip)
        now = time.monotonic()

        # Rate features
        req_10 = st.req_10.count()
        req_60 = st.req_60.count()
        req_300 = st.req_300.count()

        # Auth fail features
        auth_fail_ip_60 = st.auth_fail_60.count()
        
        cutoff = now - _WINDOW_60
        while st._users_tried and st._users_tried[0][0] < cutoff:
            st._users_tried.popleft()
        distinct_users_tried = len(set(e for _, e in st._users_tried))
        
        auth_fail_user_60 = self._user_fails[st._last_email_tried].count() if st._last_email_tried else 0
        auth_success_after_fails = 1 if st.auth_success_after_fail else 0

        # Path features
        paths = [p for _, p in st.paths_60]
        unique_paths = len(set(paths)) if paths else 0
        statuses = [s for _, s in st.statuses_60]
        p404 = sum(1 for s in statuses if s == 404)
        p404_ratio = (p404 / len(statuses)) if statuses else 0.0
        path_entropy = _shannon_entropy(paths)

        sensitive_path_hit = 1 if _is_sensitive(path) else 0

        # Timing features — interarrival from req_60 deque
        ts_list = st.req_60.timestamps()
        if len(ts_list) >= 2:
            gaps = [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]
            gaps_ms = [g * 1000 for g in gaps]
            interarrival_mean = sum(gaps_ms) / len(gaps_ms)
            variance = sum((g - interarrival_mean) ** 2 for g in gaps_ms) / len(gaps_ms)
            interarrival_std = math.sqrt(variance)
        else:
            interarrival_mean = 0.0
            interarrival_std = 0.0

        # Payload features
        payload_history = list(st.payload_bytes_history)
        payload_bytes_std = _std(payload_history) if len(payload_history) > 1 else 0.0
        resp_bytes_sum = sum(b for _, b in st.resp_bytes_60)

        # Header features
        ua_missing = 1 if not user_agent else 0
        ua_known_tool = 1 if _is_known_tool_ua(user_agent) else 0
        ua_entropy_val = _shannon_entropy(list(user_agent or ""))
        accept_lang_missing = 1 if not accept_lang else 0
        header_order_hash_known = 1  # simplified — no JA3 available in uvicorn

        # Session features
        session_age = (now - st.session_start) if st.session_start else 0.0
        requests_this_session = st.session_req_count

        # Time features
        import datetime as _dt
        hour = _dt.datetime.now(_dt.timezone.utc).hour
        is_off_hours = 1 if (hour < 6 or hour >= 22) else 0

        return {
            "req_rate_10s": req_10,
            "req_rate_60s": req_60,
            "req_rate_300s": req_300,
            "auth_fail_ip_60s": auth_fail_ip_60,
            "auth_fail_user_60s": auth_fail_user_60,
            "distinct_users_tried_60s": distinct_users_tried,
            "auth_success_after_fails": auth_success_after_fails,
            "unique_paths_60s": unique_paths,
            "p404_ratio_60s": round(p404_ratio, 4),
            "path_entropy": round(path_entropy, 4),
            "sensitive_path_hit": sensitive_path_hit,
            "interarrival_mean_ms": round(interarrival_mean, 2),
            "interarrival_std_ms": round(interarrival_std, 2),
            "payload_bytes": payload_bytes,
            "payload_bytes_std": round(payload_bytes_std, 2),
            "resp_bytes_60s": resp_bytes_sum,
            "header_count": header_count,
            "ua_missing": ua_missing,
            "ua_known_tool": ua_known_tool,
            "ua_entropy": round(ua_entropy_val, 4),
            "accept_lang_missing": accept_lang_missing,
            "header_order_hash_known": header_order_hash_known,
            "asn_is_hosting": 1 if asn_is_hosting else 0,
            "country_risk": round(country_risk, 4),
            "ip_reputation_hit": 1 if ip_reputation_hit else 0,
            "is_tor_exit": 1 if is_tor_exit else 0,
            "session_age_s": round(session_age, 2),
            "requests_this_session": requests_this_session,
            "hour_of_day": hour,
            "is_off_hours": is_off_hours,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = frozenset([
    "/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/",
    "/admin", "/actuator/env", "/login", "/register", "/checkout",
])

_KNOWN_TOOL_UAS = ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "curl/", "python-requests", "go-http-client")


def _is_sensitive(path: str) -> bool:
    p = path.split("?")[0].rstrip("/") or "/"
    return p in _SENSITIVE_PATHS or any(path.startswith(s) for s in ("/wp-", "/phpmyadmin"))


def _is_known_tool_ua(ua: Optional[str]) -> bool:
    if not ua:
        return False
    ua_lower = ua.lower()
    return any(t in ua_lower for t in _KNOWN_TOOL_UAS)


def _shannon_entropy(items) -> float:
    if not items:
        return 0.0
    from collections import Counter
    counts = Counter(items)
    total = len(items)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _std(values) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))


# Global singleton — imported by middleware and auth routes
ip_counter = RateCounter()
