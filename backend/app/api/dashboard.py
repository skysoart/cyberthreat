"""
backend/app/api/dashboard.py  — Team 1
All /api/v1/* dashboard endpoints.
Response shapes are contract-frozen — match docs/api-contract.md and frontend/mocks/*.json.
Until ThreatEngine exists, falls back to reading mocks from disk.
When engine.py lands, swap each method body to call engine.<method>().
"""
import json
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.tables import Incident, Event, SettingsWeight
from backend.app.schemas import IncidentFeedback, ModelRollback, WeightsSettings

router = APIRouter()

_MOCKS_DIR = "frontend/mocks"


def _load_mock(filename: str) -> dict:
    path = os.path.join(_MOCKS_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _inc_to_dict(inc: Incident) -> dict:
    def _j(v):
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return v
        return v

    return {
        "id": inc.id,
        "title": inc.title,
        "status": inc.status,
        "priority": inc.priority,
        "risk_score": inc.risk_score,
        "opened_at": inc.opened_at.strftime("%Y-%m-%dT%H:%M:%SZ") if inc.opened_at else None,
        "last_seen_at": inc.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ") if inc.last_seen_at else None,
        "event_count": inc.event_count,
        "primary_class": inc.primary_class,
        "kill_chain_depth": inc.kill_chain_depth,
        "assets_affected": _j(inc.assets_affected) or [],
        "users_affected": inc.users_affected,
        "top_asn": inc.top_asn,
        "has_similar": inc.has_similar,
        "risk_breakdown": _j(inc.risk_breakdown) or {},
    }


def _event_to_dict(ev: Event) -> dict:
    return {
        "id": ev.id,
        "ts": ev.ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ev.ts else None,
        "src_ip": ev.src_ip,
        "url_path": ev.url_path,
        "http_status": ev.http_status,
        "user_id": ev.user_id,
        "asset_id": ev.asset_id,
        "pred_class": ev.pred_class,
        "pred_confidence": ev.pred_confidence,
        "individual_priority": ev.individual_priority,
        "attack_technique": ev.attack_technique,
        "evidence": json.loads(ev.evidence_json) if ev.evidence_json else [],
    }


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

@router.get("/api/v1/overview")
def get_overview(db: Session = Depends(get_db)):
    # Use DB for live counters; fall back to mock shape for static sections
    mock = _load_mock("overview.json")

    events_total = db.query(Event).count()
    incidents_open = db.query(Incident).filter(Incident.status == "open").count()
    incidents_p1 = db.query(Incident).filter(Incident.priority == "P1").count()

    # Live ticker — last 25 events that have predictions
    ticker_rows = (
        db.query(Event)
        .filter(Event.pred_class.isnot(None))
        .order_by(Event.ts.desc())
        .limit(25)
        .all()
    )
    ticker = []
    for ev in ticker_rows:
        ticker.append({
            "ts": ev.ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": ev.src_ip,
            "url_path": ev.url_path,
            "pred_class": ev.pred_class,
            "pred_confidence": ev.pred_confidence,
            "incident_id": ev.incident_id,
        })
    if not ticker:
        ticker = mock.get("ticker", [])

    return {
        "tenant": "Sample Store",
        "window_days": 30,
        "counters": {
            "events_total": events_total or mock["counters"]["events_total"],
            "events_last_24h": mock["counters"]["events_last_24h"],
            "incidents_open": incidents_open or mock["counters"]["incidents_open"],
            "incidents_p1": incidents_p1 or mock["counters"]["incidents_p1"],
            "noise_reduction_pct": mock["counters"]["noise_reduction_pct"],
            "median_triage_seconds": mock["counters"]["median_triage_seconds"],
        },
        "trend": mock["trend"],
        "priority_split": mock["priority_split"],
        "class_split": mock["class_split"],
        "top_sources": mock["top_sources"],
        "ticker": ticker,
    }


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.get("/api/v1/incidents")
def get_incidents(
    priority: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50),
    offset: int = Query(0),
    db: Session = Depends(get_db),
):
    q = db.query(Incident)
    if priority:
        q = q.filter(Incident.priority == priority)
    if status:
        q = q.filter(Incident.status == status)

    total = q.count()
    incidents = q.order_by(Incident.risk_score.desc()).offset(offset).limit(limit).all()

    if not incidents:
        # Fall back to mock while ThreatEngine not yet running
        return _load_mock("incidents.json")

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "incidents": [_inc_to_dict(i) for i in incidents],
    }


@router.get("/api/v1/incidents/{id}")
def get_incident(id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == id).first()
    if not inc:
        # Try mock as graceful fallback for INC-0187 used in demo
        if id == "INC-0187":
            return _load_mock("incident-INC-0187.json")
        raise HTTPException(status_code=404, detail="Incident not found")

    events = db.query(Event).filter(Event.incident_id == id).all()

    def _j(v):
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return v
        return v

    return {
        "id": inc.id,
        "title": inc.title,
        "status": inc.status,
        "priority": inc.priority,
        "risk_score": inc.risk_score,
        "opened_at": inc.opened_at.strftime("%Y-%m-%dT%H:%M:%SZ") if inc.opened_at else None,
        "last_seen_at": inc.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ") if inc.last_seen_at else None,
        "risk_breakdown": _j(inc.risk_breakdown) or {},
        "summary": inc.summary,
        "kill_chain": _j(inc.kill_chain) or [],
        "entities": _j(inc.entities) or [],
        "entity_graph_svg": inc.entity_graph_svg,
        "threat_intel": _j(inc.threat_intel) or [],
        "similar_incident": _j(inc.similar_incident),
        "recommendations": _j(inc.recommendations) or {},
        "narrative": inc.narrative,
        "events": [_event_to_dict(e) for e in events],
    }


@router.post("/api/v1/incidents/{id}/feedback")
def submit_feedback(id: str, feedback: IncidentFeedback, db: Session = Depends(get_db)):
    valid_labels = {"confirmed_threat", "false_positive", "reclassify"}
    if feedback.label not in valid_labels:
        raise HTTPException(status_code=400, detail=f"label must be one of {valid_labels}")
    if feedback.label == "reclassify" and not feedback.new_class:
        raise HTTPException(status_code=400, detail="reclassify requires new_class")

    label_to_status = {
        "confirmed_threat": "confirmed",
        "false_positive": "false_positive",
        "reclassify": "open",
    }
    new_status = label_to_status[feedback.label]

    # Update incident status if it exists in DB
    inc = db.query(Incident).filter(Incident.id == id).first()
    if inc:
        inc.status = new_status
        db.commit()

    return {
        "ok": True,
        "incident_id": id,
        "new_status": new_status,
        "labels_pending": 12,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@router.get("/api/v1/model")
def get_model():
    return _load_mock("model.json")


@router.post("/api/v1/model/retrain")
def retrain_model():
    """Stub — Team 2 replaces with real retrain when engine.py lands."""
    return {
        "candidate_version": "v1.0.4",
        "promoted": True,
        "rejection_reason": None,
        "before": {"pr_auc": 0.981, "fpr_at_90_recall": 0.012},
        "after": {"pr_auc": 0.986, "fpr_at_90_recall": 0.011},
        "n_feedback_used": 48,
        "duration_ms": 2840,
    }


@router.post("/api/v1/model/rollback")
def rollback_model(body: ModelRollback):
    return {"ok": True, "current_version": body.version}


# ---------------------------------------------------------------------------
# Review queue
# ---------------------------------------------------------------------------

@router.get("/api/v1/review-queue")
def get_review_queue():
    return _load_mock("review-queue.json")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@router.get("/api/v1/metrics")
def get_metrics():
    return _load_mock("metrics.json")


# ---------------------------------------------------------------------------
# Settings / weights
# ---------------------------------------------------------------------------

@router.get("/api/v1/settings/weights")
def get_weights(db: Session = Depends(get_db)):
    w = db.query(SettingsWeight).first()
    if not w:
        w = SettingsWeight()
        db.add(w)
        db.commit()
    return {
        "model_confidence": w.model_confidence,
        "asset_criticality": w.asset_criticality,
        "exploitability": w.exploitability,
        "blast_radius": w.blast_radius,
        "kill_chain_depth": w.kill_chain_depth,
        "recency": w.recency,
    }


@router.put("/api/v1/settings/weights")
def update_weights(weights_in: WeightsSettings, db: Session = Depends(get_db)):
    total = sum(weights_in.model_dump().values())
    if abs(total - 1.0) > 0.001:
        raise HTTPException(status_code=400, detail="Weights must sum to 1.0 (±0.001)")

    w = db.query(SettingsWeight).first()
    if not w:
        w = SettingsWeight()
        db.add(w)

    for k, v in weights_in.model_dump().items():
        setattr(w, k, v)
    db.commit()

    open_count = db.query(Incident).filter(Incident.status == "open").count()
    return {"ok": True, "incidents_rescored": open_count}
