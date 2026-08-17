"""
backend/app/middleware.py  — Team 1
Intercepts every HTTP request to the FastAPI app and writes an Event row.
Team 1 fills all fields up to and including features_json.
Team 2 fills pred_*, evidence_json, attack_technique, individual_priority.
"""
import json
import time
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from backend.app.counters import ip_counter
from backend.app.database import SessionLocal
from backend.app.models.tables import Event

# Paths that generate noise without security signal — skip logging
_SKIP_PREFIXES = ("/static/", "/mocks/", "/dashboard-static/", "/favicon")

# Paths that must return exactly 404 — explicit probe honeypots
_PROBE_404_PATHS = frozenset([
    "/.env", "/.git/config", "/wp-admin/", "/wp-admin",
    "/phpmyadmin/", "/phpmyadmin",
])


class TelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        path = request.url.path
        src_ip = (request.client.host if request.client else "127.0.0.1")
        payload_bytes = int(request.headers.get("content-length", 0))
        user_agent = request.headers.get("user-agent")
        accept_lang = request.headers.get("accept-language")
        header_count = len(request.headers)
        session_id: str | None = request.cookies.get("session_id")

        # Record request in counters BEFORE the response
        ip_counter.record_request(
            ip=src_ip,
            path=path,
            payload_bytes=payload_bytes,
            session_id=session_id,
        )

        response = await call_next(request)

        duration_ms = int((time.monotonic() - start) * 1000)
        resp_bytes = int(response.headers.get("content-length", 0))

        # Record response counters
        ip_counter.record_response(src_ip, response.status_code, resp_bytes)

        # Skip noisy static asset paths
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return response

        # Build the 30-feature server vector (from deques — no DB query)
        server_feats = ip_counter.get_features(
            ip=src_ip,
            path=path,
            payload_bytes=payload_bytes,
            user_agent=user_agent,
            accept_lang=accept_lang,
            header_count=header_count,
            session_id=session_id,
        )

        # Browser features — absent for server-generated events → all None
        browser_feats = {k: None for k in [
            "mouse_move_count", "mouse_path_entropy",
            "keystroke_count", "keystroke_interval_mean", "keystroke_interval_std",
            "form_fill_ms", "paste_events",
            "click_count", "time_to_first_click_ms",
            "scroll_events", "page_dwell_ms", "focus_blur_count",
            "screen_w", "screen_h", "tz_offset", "hardware_concurrency",
        ]}

        features = {**server_feats, **browser_feats, "browser_telemetry_present": 0}

        # Raw request snapshot (safe — no credentials stored)
        raw = {
            "method": request.method,
            "path": path,
            "query": str(request.url.query),
            "user_agent": user_agent,
            "referrer": request.headers.get("referer"),
            "duration_ms": duration_ms,
            "status_code": response.status_code,
        }

        db = SessionLocal()
        try:
            event = Event(
                tenant_id="sample-store",
                ts=datetime.now(timezone.utc),
                session_id=session_id,
                source="server",
                src_ip=src_ip,
                asn=None,        # enriched later by Team 2
                country=None,    # enriched later by Team 2
                user_id=None,    # set by auth routes when user is known
                asset_id=None,   # set by auth routes / telemetry when known
                url_path=path,
                http_status=response.status_code,
                raw_json=json.dumps(raw),
                features_json=json.dumps(features),
                # Team 2 fields — explicitly None on insert
                pred_class=None,
                pred_confidence=None,
                evidence_json=None,
                attack_technique=None,
                individual_priority=None,
            )
            db.add(event)
            db.commit()
        except Exception as exc:
            db.rollback()
            if True:  # always log in dev
                print(f"[middleware] Event insert failed: {exc}")
        finally:
            db.close()

        return response
