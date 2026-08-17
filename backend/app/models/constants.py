"""
backend/app/models/constants.py — Team 2.

Shared enumerations and the risk-band mapping. These lived in tables.py in the
original schema; they are here so that neither team has to edit the other's
file to add one. Import from here, never retype a literal.

Contract: docs/backend-contract.md §5.
"""

from __future__ import annotations

# Model output classes. Exactly 7, exactly these strings.
CLASSES = [
    "normal",
    "brute_force",
    "credential_stuffing",
    "dir_scan",
    "flood",
    "scraper",
    "slow_recon",
]

# Event.source
SOURCES = ["widget", "server", "firewall", "email_gw", "edr"]

# Entity.kind — used by the correlation graph
ENTITY_KINDS = ["ip", "subnet", "asn", "user", "ua_hash", "asset", "session", "cve"]

# Feedback.label
FEEDBACK_LABELS = ["confirmed_threat", "false_positive", "reclassify"]

# Incident.status
INCIDENT_STATUSES = ["open", "confirmed", "false_positive", "closed"]

# Risk score -> priority band. Applied identically to events and incidents;
# the comparison between them is only meaningful on one scale.
PRIORITY_BANDS = [(80.0, "P1"), (60.0, "P2"), (35.0, "P3"), (0.0, "P4")]

# The six risk terms, in the order the dashboard renders the stacked bar.
# DO NOT REORDER — frontend/static/incident.js relies on this sequence.
RISK_TERMS = [
    "model_confidence",
    "asset_criticality",
    "exploitability",
    "blast_radius",
    "kill_chain_depth",
    "recency",
]

DEFAULT_WEIGHTS = {
    "model_confidence": 0.20,
    "asset_criticality": 0.20,
    "exploitability": 0.20,
    "blast_radius": 0.15,
    "kill_chain_depth": 0.15,
    "recency": 0.10,
}


def priority_for(risk_score: float) -> str:
    """Single source of truth for the risk -> priority mapping."""
    for threshold, band in PRIORITY_BANDS:
        if risk_score >= threshold:
            return band
    return "P4"
