"""
backend/app/models/security_tables.py — Team 2.

Tables the intelligence layer needs that are not in tables.py. Declared against
Team 1's Base so they are created by the same `Base.metadata.create_all()` and
appear in the same SQLite file — no second engine, no migration step, and no
edit to Team 1's schema file.

  Feedback           analyst labels; the ONLY source of training labels
  ModelVersion       model registry, including rejected candidates
  IncidentFingerprint  campaign signatures for past-to-current matching
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, Float, Integer, String, Text, DateTime

from backend.app.models.tables import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Feedback(Base):
    """
    Human labels only.

    Model predictions never enter this table. Training on your own confident
    outputs is confirmation bias and is trivially poisoned — an attacker who can
    generate traffic could teach the model that their traffic is normal.
    """
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, index=True, nullable=True)     # INC-XXXX
    event_id = Column(Integer, index=True, nullable=True)
    label = Column(String, nullable=False)                      # see FEEDBACK_LABELS
    new_class = Column(String, nullable=True)                   # when label == reclassify
    analyst = Column(String, nullable=False, default="demo")
    note = Column(Text, nullable=True)
    ts = Column(DateTime(timezone=True), default=_utcnow)
    original_prediction = Column(String, nullable=True)
    # Set once a promoted model has trained on this label, so retraining is
    # idempotent and the "labels pending" counter is honest.
    consumed_by_version = Column(String, nullable=True)


class ModelVersion(Base):
    """
    Model registry. Rejected candidates are recorded, not discarded — a system
    that refuses a bad update is more convincing evidence of a working
    promotion gate than one that only ever succeeds.
    """
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True)
    version = Column(String, index=True, nullable=False)        # v1.0.3
    trained_at = Column(DateTime(timezone=True), default=_utcnow)
    n_base = Column(Integer, default=0)
    n_feedback = Column(Integer, default=0)

    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1 = Column(Float, nullable=True)
    pr_auc = Column(Float, nullable=True)
    fpr_at_90_recall = Column(Float, nullable=True)

    promoted = Column(Boolean, default=False)
    rejection_reason = Column(Text, nullable=True)
    artifact_path = Column(String, nullable=True)
    meta_json = Column(Text, nullable=True)     # confusion matrix, importances, PR curve


class IncidentFingerprint(Base):
    """
    A compact signature of HOW a campaign behaved — technique set, timing
    profile, hour histogram — not who it was.

    Kept separate from `incidents` so campaign matching survives a correlation
    rebuild: incidents are dropped and recreated on every correlate() run, but
    the record of what past campaigns looked like has to outlive that.
    """
    __tablename__ = "incident_fingerprints"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, index=True, nullable=False)
    fingerprint_json = Column(Text, nullable=False)
    status = Column(String, default="open")
    opened_at = Column(DateTime(timezone=True), default=_utcnow)
