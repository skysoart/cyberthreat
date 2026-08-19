"""
backend/app/api/dashboard.py — all /api/v1/* dashboard endpoints.

Every handler is one line: call ThreatEngine, return the dict. Response shapes
are contract-frozen in docs/api-contract.md, and the engine already returns
them verbatim — so nothing is reshaped here. If a shape is wrong it is wrong in
services/engine.py, and there is exactly one place to fix it.

The mock fallback that used to live here is gone. It existed so the frontend
could be built before the engine did; keeping it now would mean the dashboard
could silently show fixture data instead of computed results, which is the one
thing that must never happen in front of a judge. A failing endpoint should
fail loudly.
"""

from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Query

from backend.app.services.engine import get_engine

router = APIRouter()


@router.get("/api/v1/overview")
def overview():
    return get_engine().get_overview()


@router.get("/api/v1/incidents")
def incidents(
    priority: Optional[str] = Query(None, pattern="^P[1-4]$"),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    return get_engine().get_incidents(
        priority=priority, status=status, limit=limit, offset=offset)


@router.get("/api/v1/incidents/{incident_id}")
def incident_detail(incident_id: str):
    try:
        return get_engine().get_incident(incident_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No such incident: {incident_id}")


@router.post("/api/v1/incidents/{incident_id}/feedback")
def incident_feedback(incident_id: str, body: dict = Body(...)):
    label = body.get("label")
    if label not in ("confirmed_threat", "false_positive", "reclassify"):
        raise HTTPException(status_code=400, detail=f"Invalid label: {label}")
    try:
        return get_engine().submit_feedback(
            incident_id=incident_id,
            label=label,
            analyst=body.get("analyst", "demo"),
            note=body.get("note"),
            new_class=body.get("new_class"),
        )
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No such incident: {incident_id}")


@router.post("/api/v1/correlate")
def run_correlation():
    """
    Rebuild incidents from the current Event table.

    Exposed because the demo runs an attack live: the sequence is generate
    traffic, hit this, watch the queue repopulate. Also called on a timer by
    main.py so the dashboard keeps up on its own.
    """
    n = get_engine().correlate()
    return {"ok": True, "incidents": n}


@router.get("/api/v1/model")
def model_info():
    return get_engine().get_model()


@router.post("/api/v1/model/retrain")
def model_retrain():
    return get_engine().retrain()


@router.post("/api/v1/model/rollback")
def model_rollback(body: dict = Body(...)):
    version = body.get("version")
    if not version:
        raise HTTPException(status_code=400, detail="version is required")
    try:
        return get_engine().rollback(version)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No such version: {version}")


@router.get("/api/v1/review-queue")
def review_queue(limit: int = Query(25, ge=1, le=200)):
    return get_engine().get_review_queue(limit=limit)


@router.post("/api/v1/review-queue/label")
def label_review_group(body: dict = Body(...)):
    """
    Label a whole group of near-identical events at once.

    The queue groups by (class, path, source), so one click can retire
    thousands of rows from a single flood instead of asking for thousands
    of clicks.
    """
    ids = body.get("event_ids") or ([body["event_id"]] if body.get("event_id") else [])
    if not ids:
        raise HTTPException(status_code=400, detail="event_ids is required")
    try:
        return get_engine().submit_event_feedback(
            event_ids=[int(i) for i in ids],
            label=body.get("label"),
            analyst=body.get("analyst", "demo"),
            new_class=body.get("new_class"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/api/v1/metrics")
def metrics():
    return get_engine().get_metrics()


@router.get("/api/v1/settings/weights")
def get_weights():
    return get_engine().get_weights()


@router.put("/api/v1/settings/weights")
def put_weights(body: dict = Body(...)):
    try:
        return get_engine().set_weights(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
