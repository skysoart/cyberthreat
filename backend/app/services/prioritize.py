"""
Adamantine — prioritisation.

A transparent, six-term weighted formula. Not a model.

That is a deliberate choice, not a shortcut. A security team will not act on a
number it cannot interrogate, and "the model said 87" is not an answer when
someone asks why they should wake up. Every term here is separately computed,
separately stored, and rendered as a labelled segment of a stacked bar in the
UI, so the answer to "why is this a P1" is to point at the screen.

Three of the six terms — blast_radius, kill_chain_depth, and the asset spread
inside asset_criticality — CANNOT be computed for a single event. That is the
whole thesis of the product: the same nine events score P4 individually and
P1 correlated, not because anything was reclassified, but because half the
inputs to the score only exist once you look at events together.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Optional

from ..models.constants import DEFAULT_WEIGHTS, RISK_TERMS, priority_for

# Blast radius saturates here — beyond ~20 distinct assets+users the incident is
# already "widespread" and further growth should not keep inflating the score.
BLAST_SATURATION = 20.0

# Recency half-life. An incident last seen 24h ago contributes ~37% of the term.
RECENCY_TAU_HOURS = 24.0

# Kill-chain depth is NOT linear in tactic count. The meaningful jump is from
# "one stage" (could be anything) to "multi-stage" (someone is working through
# a plan), and again at three (reconnaissance that led somewhere). A web-app
# intrusion realistically tops out around five tactics, so dividing by the nine
# in attack_map.yaml would permanently understate every real campaign.
KILL_CHAIN_SCALE = {0: 0.0, 1: 0.05, 2: 0.45, 3: 0.80, 4: 0.92}
KILL_CHAIN_MAX = 1.0


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def compute_terms(
    *,
    model_confidence: float,
    asset_criticality: float,
    exploitability: float,
    distinct_assets: int,
    distinct_users: int,
    kill_chain_depth: int,
    last_seen_at: datetime,
    now: Optional[datetime] = None,
) -> dict[str, float]:
    """The six raw term values, each normalised to 0..1."""
    now = now or datetime.now(timezone.utc)
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)

    blast = math.log1p(distinct_assets + distinct_users) / math.log1p(BLAST_SATURATION)
    age_h = max(0.0, (now - last_seen_at).total_seconds() / 3600.0)

    return {
        "model_confidence": _clamp(model_confidence),
        "asset_criticality": _clamp(asset_criticality),
        "exploitability": _clamp(exploitability),
        "blast_radius": _clamp(blast),
        "kill_chain_depth": KILL_CHAIN_SCALE.get(kill_chain_depth, KILL_CHAIN_MAX),
        "recency": _clamp(math.exp(-age_h / RECENCY_TAU_HOURS)),
    }


def score(terms: dict[str, float],
          weights: Optional[dict[str, float]] = None) -> tuple[float, dict[str, dict]]:
    """
    Returns (risk_score, breakdown).

    `breakdown` keys are RISK_TERMS in fixed order — the dashboard renders the
    stacked bar straight from this, so the order must not change. `points`
    always sums to `risk_score` within rounding.
    """
    w = weights or DEFAULT_WEIGHTS
    breakdown: dict[str, dict] = {}
    total = 0.0
    for term in RISK_TERMS:
        raw = float(terms.get(term, 0.0))
        weight = float(w.get(term, 0.0))
        pts = 100.0 * raw * weight
        total += pts
        breakdown[term] = {
            "raw": round(raw, 3),
            "weight": round(weight, 3),
            "points": round(pts, 1),
        }
    return round(total, 1), breakdown


def score_incident(cluster, enrichments: dict[int, Any],
                   weights: Optional[dict[str, float]] = None,
                   now: Optional[datetime] = None) -> dict:
    """
    Score a correlated cluster. This is where the P4 -> P1 inversion happens.

    A cluster's exploitability is the MAXIMUM across its events, not the mean:
    one confirmed hit on a KEV-listed vulnerability makes the whole incident
    exploitable, and averaging it away with nine harmless 404s would be wrong.
    Same reasoning for asset criticality — an incident that touched the payments
    API is a payments incident even if most of its events hit the blog.
    """
    depth = len(set(cluster.tactics))

    max_expl, max_crit, conf_sum = 0.0, 0.0, 0.0
    for ev in cluster.events:
        en = enrichments.get(ev.id)
        if en is not None:
            max_expl = max(max_expl, getattr(en, "exploitability", 0.0))
            max_crit = max(max_crit, getattr(en, "asset_criticality", 0.0))
        conf_sum += (ev.pred_confidence or 0.0)

    n = max(1, len(cluster.events))
    # Mean confidence understates a cluster whose strongest signal is decisive,
    # so blend mean with max. A cluster is at least as suspicious as its worst event.
    mean_conf = conf_sum / n
    max_conf = max((ev.pred_confidence or 0.0) for ev in cluster.events)
    confidence = 0.6 * max_conf + 0.4 * mean_conf

    terms = compute_terms(
        model_confidence=confidence,
        asset_criticality=max_crit,
        exploitability=max_expl,
        distinct_assets=len(cluster.assets),
        distinct_users=len(cluster.users),
        kill_chain_depth=depth,
        last_seen_at=cluster.last_seen_at,
        now=now,
    )
    risk, breakdown = score(terms, weights)

    # No score flooring. An earlier version clamped three-tactic incidents up to
    # 80, which made `points` stop summing to `risk_score` and quietly broke the
    # stacked bar in the UI — a score you cannot decompose is exactly the black
    # box this formula exists to avoid. The kill-chain curve above carries that
    # weight honestly instead.
    escalated = depth >= 3

    return {
        "risk_score": risk,
        "risk_breakdown": breakdown,
        "priority": priority_for(risk),
        "kill_chain_depth": depth,
        "escalated_by_kill_chain": escalated,
        "terms": terms,
    }


def score_event(pred_confidence: float, enrichment, last_seen_at: datetime,
                weights: Optional[dict[str, float]] = None,
                now: Optional[datetime] = None) -> dict:
    """
    Score a single event on the identical formula — the comparison only means
    something if both sides use the same scale.

    A single event has one asset and one tactic, so blast_radius and
    kill_chain_depth are structurally near their floor. That is not a penalty
    we apply; it is what those terms actually measure.
    """
    terms = compute_terms(
        model_confidence=pred_confidence,
        asset_criticality=getattr(enrichment, "asset_criticality", 0.1),
        exploitability=getattr(enrichment, "exploitability", 0.0),
        distinct_assets=1,
        distinct_users=0,
        kill_chain_depth=1,
        last_seen_at=last_seen_at,
        now=now,
    )
    risk, breakdown = score(terms, weights)
    return {"risk_score": risk, "risk_breakdown": breakdown, "priority": priority_for(risk)}


def validate_weights(weights: dict[str, float]) -> Optional[str]:
    missing = [t for t in RISK_TERMS if t not in weights]
    if missing:
        return f"missing terms: {missing}"
    extra = [k for k in weights if k not in RISK_TERMS]
    if extra:
        return f"unknown terms: {extra}"
    if any(not (0.0 <= float(v) <= 1.0) for v in weights.values()):
        return "each weight must be between 0 and 1"
    total = sum(float(v) for v in weights.values())
    if abs(total - 1.0) > 0.001:
        return f"weights must sum to 1.0, got {total:.3f}"
    return None
