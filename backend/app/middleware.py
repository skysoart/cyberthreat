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
from backend.app.services import detect, enrich as enr, prioritize as prio

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

        # Fuse browser telemetry by session_id. Without this every request
        # looks like a bot — including a human typing their own password —
        # because the sensor reports separately from the server.
        features = detect.fuse(server_feats, session_id)

        # Which asset answered this path. Left None, asset_criticality falls to
        # its floor and every incident is under-scored.
        asset_id = detect.asset_for(path)

        # Classify now, not later: correlation only considers non-normal
        # events, so an unclassified row is invisible to the whole pipeline.
        pred_class, pred_conf, evidence, technique = detect.classify(
            features, path, response.status_code)

        enrichment = enr.enrich(path, response.status_code, asset_id,
                                src_ip, None, None)
        scored = prio.score_event(pred_conf, enrichment,
                                  datetime.now(timezone.utc))

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
                user_id=ip_counter.last_user_for(src_ip),
                asset_id=asset_id,
                url_path=path,
                http_status=response.status_code,
                raw_json=json.dumps(raw),
                features_json=json.dumps(features),
                pred_class=pred_class,
                pred_confidence=pred_conf,
                evidence_json=json.dumps(evidence),
                attack_technique=technique,
                individual_priority=scored["priority"],
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
