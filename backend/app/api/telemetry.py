"""
backend/app/api/telemetry.py  — Team 1
POST /api/v1/telemetry — receives browser telemetry from widget/adamantine-sensor.js.
Validates X-Adamantine-Key, fuses browser features into an Event row.
"""
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.database import get_db
from backend.app.models.tables import Event
from backend.app.counters import ip_counter
from backend.app.schemas import TelemetryPayload
from backend.ml.features import SERVER_FEATURES, BROWSER_FEATURES

router = APIRouter()


@router.post("/api/v1/telemetry")
def ingest_telemetry(
    payload: TelemetryPayload,
    request: Request,
    x_adamantine_key: str = Header(None),
    db: Session = Depends(get_db),
):
    if x_adamantine_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    src_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")

    # Build server features snapshot for this telemetry event
    server_feats = ip_counter.get_features(
        ip=src_ip,
        path=payload.page,
        payload_bytes=int(request.headers.get("content-length", 0)),
        user_agent=user_agent,
        accept_lang=request.headers.get("accept-language"),
        header_count=len(request.headers),
        session_id=payload.session_id,
    )

    # Browser features — None means "absent"; contract says absent → None NOT 0
    b = payload.browser
    browser_feats: dict = {}
    if b is not None:
        browser_feats = {
            "mouse_move_count": b.mouse_move_count,
            "mouse_path_entropy": b.mouse_path_entropy,
            "keystroke_count": b.keystroke_count,
            "keystroke_interval_mean": b.keystroke_interval_mean,
            "keystroke_interval_std": b.keystroke_interval_std,
            "form_fill_ms": b.form_fill_ms,
            "paste_events": b.paste_events,
            "click_count": b.click_count,
            "time_to_first_click_ms": b.time_to_first_click_ms,
            "scroll_events": b.scroll_events,
            "page_dwell_ms": b.page_dwell_ms,
            "focus_blur_count": b.focus_blur_count,
            "screen_w": b.screen_w,
            "screen_h": b.screen_h,
            "tz_offset": b.tz_offset,
            "hardware_concurrency": b.hardware_concurrency,
        }
        browser_telemetry_present = 1
    else:
        browser_feats = {k: None for k in BROWSER_FEATURES}
        browser_telemetry_present = 0

    features = {**server_feats, **browser_feats, "browser_telemetry_present": browser_telemetry_present}

    raw = {
        "session_id": payload.session_id,
        "page": payload.page,
        "source": "widget",
    }

    event = Event(
        tenant_id="sample-store",
        ts=datetime.now(timezone.utc),
        session_id=payload.session_id,
        source="widget",
        src_ip=src_ip,
        asn=None,
        country=None,
        user_id=None,
        asset_id=None,
        url_path=payload.page,
        http_status=None,
        raw_json=json.dumps(raw),
        features_json=json.dumps(features),
        # Team 2 fills these
        pred_class=None,
        pred_confidence=None,
        evidence_json=None,
        attack_technique=None,
        individual_priority=None,
    )
    db.add(event)
    db.commit()

    return {"ok": True}
