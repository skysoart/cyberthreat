"""
Adamantine — correlation engine.

This is the product. Everything else supports it.

A single web request is almost never alarming. A directory scan that 404s, one
failed login, a request from a datacentre IP — each is noise, and any system
that pages a human for them is worse than useless. The events that matter only
become visible when you look at them *together*.

So we never alert on events. We build a weighted graph of them, cut it into
clusters, and alert on the clusters.

Design notes worth knowing before changing anything here:

  * Links are weighted by ENTITY SPECIFICITY. Two events sharing a session are
    almost certainly the same actor (1.0). Two events sharing an ASN might both
    just be on AWS (0.4). Weight reflects how much evidence the link actually is.

  * Links DECAY with time gap rather than being hard-cut at a window boundary.
    A fixed window is arbitrary — an attacker who waits 61 minutes defeats a
    60-minute window. Decay means a stale link contributes a little instead of
    nothing, so it can still tip a cluster over threshold when combined with
    other evidence, but can never merge things on its own.

  * High-fanout entities are SKIPPED. An entity shared by 500 events carries no
    information (this is just inverse document frequency). Without this, every
    event from a popular ASN links to every other and you get one giant useless
    incident instead of forty real ones.

  * Only non-normal events seed clusters. We do not build incidents out of
    ordinary traffic.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

DATA = Path(__file__).resolve().parents[1] / "data"

# ---------------------------------------------------------------- tuning
#
#   base   how much evidence this shared entity is, at zero time gap
#   tau    decay constant in hours — weight halves roughly every 0.7*tau
#   window hard ceiling in hours; beyond this we do not link at all
#   cap    skip the entity entirely if it appears in more events than this
#
ENTITY_LINKS: dict[str, dict[str, float]] = {
    "session": {"base": 1.00, "tau": 24.0, "window": 48.0, "cap": 400},
    "ip":      {"base": 1.00, "tau": 1.5,  "window": 6.0,  "cap": 400},
    "user":    {"base": 0.80, "tau": 3.0,  "window": 12.0, "cap": 120},
    "subnet":  {"base": 0.70, "tau": 3.0,  "window": 12.0, "cap": 300},
    "cve":     {"base": 0.50, "tau": 12.0, "window": 24.0, "cap": 200},
    "ua_hash": {"base": 0.55, "tau": 8.0,  "window": 24.0, "cap": 200},
    "asn":     {"base": 0.40, "tau": 8.0,  "window": 24.0, "cap": 250},
    "asset":   {"base": 0.25, "tau": 4.0,  "window": 12.0, "cap": 150},
}

EDGE_CUT = 0.9          # summed weight below this is not a link

# Campaign-match threshold. 0.75 was far too loose: the hour-of-day histogram
# dominates the fingerprint vector, so any two clusters active at similar times
# scored above it and 72 of 76 incidents claimed a historical match. A match
# that fires on almost everything tells an analyst nothing, and "87% similar to
# a confirmed attack" only carries weight if it is rare.
SIMILARITY_THRESHOLD = 0.88
MAX_COMPONENT = 250     # above this, split with community detection
ESCALATE_TACTICS = 3    # distinct tactics that force escalation


@dataclass
class Cluster:
    """A correlated group of events — an incident before it has been scored."""
    event_ids: list[int] = field(default_factory=list)
    events: list[Any] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    kill_chain: list[dict] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    top_asn: Optional[int] = None
    primary_class: Optional[str] = None
    opened_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    fingerprint: dict = field(default_factory=dict)
    max_individual_priority: str = "P4"


# ---------------------------------------------------------------- ATT&CK

def load_attack_map() -> dict:
    p = DATA / "attack_map.yaml"
    if not p.exists():
        return {"classes": {}, "overrides": [], "tactic_order": []}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def technique_for(pred_class: Optional[str], features: dict,
                  http_status: int, amap: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """(technique_id, technique, tactic). Feature overrides beat class mapping."""
    for ov in amap.get("overrides", []) or []:
        cond = ov.get("when", {})
        feat = cond.get("feature")
        if feat is None:
            continue
        val = features.get(feat)
        if val is None:
            continue
        if "equals" in cond and val != cond["equals"]:
            continue
        if "greater_than" in cond and not (val > cond["greater_than"]):
            continue
        if "http_status" in cond and http_status != cond["http_status"]:
            continue
        return ov.get("technique_id"), ov.get("technique"), ov.get("tactic")

    entry = (amap.get("classes") or {}).get(pred_class or "normal") or {}
    return entry.get("technique_id"), entry.get("technique"), entry.get("tactic")


# ---------------------------------------------------------------- union-find

class _DSU:
    def __init__(self, n: int):
        self.p = list(range(n))
        self.r = [0] * n

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.r[ra] < self.r[rb]:
            ra, rb = rb, ra
        self.p[rb] = ra
        if self.r[ra] == self.r[rb]:
            self.r[ra] += 1


# ---------------------------------------------------------------- core

def _entities_of(ev, enrichment: Optional[dict] = None) -> list[tuple[str, str]]:
    import ipaddress
    out: list[tuple[str, str]] = [("ip", ev.src_ip)]
    try:
        out.append(("subnet", str(ipaddress.ip_network(f"{ev.src_ip}/24", strict=False))))
    except ValueError:
        pass
    if ev.asn:
        out.append(("asn", str(ev.asn)))
    if ev.user_id:
        out.append(("user", ev.user_id))
    if ev.asset_id:
        out.append(("asset", ev.asset_id))
    if ev.session_id:
        out.append(("session", ev.session_id))
    if enrichment and enrichment.get("cve"):
        out.append(("cve", enrichment["cve"]))
    return out


def build_clusters(events: list, enrichments: Optional[dict[int, dict]] = None,
                   edge_cut: float = EDGE_CUT) -> list[Cluster]:
    """
    events: Event rows with pred_class already set, ordered by ts.
    Returns clusters of size >= 2, plus singletons that are individually severe.
    """
    if not events:
        return []
    enrichments = enrichments or {}
    amap = load_attack_map()
    n = len(events)

    # index: entity -> [positions]
    buckets: dict[tuple[str, str], list[int]] = defaultdict(list)
    ent_of: list[list[tuple[str, str]]] = []
    for i, ev in enumerate(events):
        ents = _entities_of(ev, enrichments.get(ev.id))
        ent_of.append(ents)
        for e in ents:
            buckets[e].append(i)

    # accumulate weighted edges, entity by entity
    edges: dict[tuple[int, int], float] = defaultdict(float)
    for (kind, _value), idxs in buckets.items():
        cfg = ENTITY_LINKS.get(kind)
        if cfg is None or len(idxs) < 2:
            continue
        base, tau, window = cfg["base"], cfg["tau"], cfg["window"]

        if len(idxs) > cfg["cap"]:
            # Too many events share this entity to compare them all — and an
            # all-pairs pass here would be quadratic on the largest buckets.
            #
            # But skipping outright was wrong: a 3,000-request flood comes from
            # ONE ip, so every strong entity exceeds its cap and the flood
            # produced no incident at all. The loudest attack in the dataset was
            # invisible.
            #
            # Chain adjacent-in-time events instead. That is linear, still
            # yields one connected component, and reflects what a flood
            # actually is — a continuous burst rather than a web of relations.
            chain = sorted(idxs, key=lambda i: events[i].ts)
            for a, b in zip(chain, chain[1:]):
                gap = abs((events[b].ts - events[a].ts).total_seconds()) / 3600.0
                if gap > window:
                    continue
                w = base * math.exp(-gap / tau)
                if w >= 0.02:
                    edges[(a, b) if a < b else (b, a)] += w
            continue

        for a in range(len(idxs)):
            ia = idxs[a]
            ta = events[ia].ts
            for b in range(a + 1, len(idxs)):
                ib = idxs[b]
                gap = abs((events[ib].ts - ta).total_seconds()) / 3600.0
                if gap > window:
                    continue
                w = base * math.exp(-gap / tau)
                if w < 0.02:
                    continue
                edges[(ia, ib) if ia < ib else (ib, ia)] += w

    dsu = _DSU(n)
    for (a, b), w in edges.items():
        if w >= edge_cut:
            dsu.union(a, b)

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[dsu.find(i)].append(i)

    clusters: list[Cluster] = []
    for members in groups.values():
        # Community detection exists to break up SPURIOUS merges — many
        # unrelated actors joined by an over-general link like a shared ASN.
        # It must not be used on a single actor's burst: a 3,000-request flood
        # from one IP is one incident, and running Louvain over its time-chain
        # shatters it into dozens of meaningless fragments.
        distinct_sources = len({events[i].src_ip for i in members})
        if len(members) > MAX_COMPONENT and distinct_sources > 3:
            for sub in _split_large(members, edges):
                clusters.append(_make_cluster(sub, events, enrichments, amap))
        else:
            clusters.append(_make_cluster(members, events, enrichments, amap))

    # a lone event is only an incident if it was severe by itself
    return [c for c in clusters
            if len(c.event_ids) >= 2 or c.max_individual_priority in ("P1", "P2")]


def _split_large(members: list[int], edges: dict) -> Iterable[list[int]]:
    """
    A component this big means an over-general link slipped through. Re-cut it
    with community detection on the weighted subgraph rather than shipping one
    incident containing everything.
    """
    try:
        import networkx as nx
        from networkx.algorithms.community import louvain_communities
    except ImportError:
        return [members]

    ms = set(members)
    g = nx.Graph()
    g.add_nodes_from(members)
    for (a, b), w in edges.items():
        if a in ms and b in ms:
            g.add_edge(a, b, weight=w)
    try:
        return [sorted(c) for c in louvain_communities(g, weight="weight", seed=42)]
    except Exception:
        return [members]


def _make_cluster(members: list[int], events: list,
                  enrichments: dict, amap: dict) -> Cluster:
    c = Cluster()
    order = {t: i for i, t in enumerate(amap.get("tactic_order", []))}
    rows = sorted((events[i] for i in members), key=lambda e: e.ts)

    c.events = rows
    c.event_ids = [e.id for e in rows]
    c.opened_at = rows[0].ts
    c.last_seen_at = rows[-1].ts

    seen_tactic: dict[str, dict] = {}
    cls_counts: dict[str, int] = defaultdict(int)
    asn_counts: dict[int, int] = defaultdict(int)
    ent_counts: dict[tuple[str, str], int] = defaultdict(int)
    prio_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    best_prio = "P4"

    for ev in rows:
        feats = json.loads(ev.features_json or "{}")
        tid, tname, tactic = technique_for(ev.pred_class, feats, ev.http_status, amap)

        # A technique stored on the event WINS. detect.py assigned it while
        # holding the actual request — it knows the URL path, which this
        # reconstruction does not. Recomputing from features alone mislabelled
        # bulk traffic as T1190 Initial Access purely because one sensitive
        # path in the same window had returned 200.
        if ev.attack_technique and ev.attack_technique != tid:
            tid = ev.attack_technique
            named = (amap.get("technique_names") or {}).get(tid)
            if named:
                tname, tactic = named.get("technique"), named.get("tactic")
        if tid and tid not in c.techniques:
            c.techniques.append(tid)
        if tactic:
            s = seen_tactic.setdefault(tactic, {
                "tactic": tactic, "technique_id": tid, "technique": tname,
                "first_seen": ev.ts, "event_count": 0,
            })
            s["event_count"] += 1
        if ev.pred_class and ev.pred_class != "normal":
            cls_counts[ev.pred_class] += 1
        if ev.asn:
            asn_counts[ev.asn] += 1
        if ev.user_id:
            c.users.add(ev.user_id)
        if ev.asset_id and ev.asset_id not in c.assets:
            c.assets.append(ev.asset_id)
        if ev.individual_priority and prio_rank.get(ev.individual_priority, 3) < prio_rank[best_prio]:
            best_prio = ev.individual_priority
        for e in _entities_of(ev, enrichments.get(ev.id)):
            ent_counts[e] += 1

    c.max_individual_priority = best_prio
    c.kill_chain = sorted(seen_tactic.values(),
                          key=lambda s: (order.get(s["tactic"], 99), s["first_seen"]))
    c.tactics = [s["tactic"] for s in c.kill_chain]
    c.primary_class = max(cls_counts, key=cls_counts.get) if cls_counts else "normal"
    c.top_asn = max(asn_counts, key=asn_counts.get) if asn_counts else None
    c.entities = [
        {"kind": k, "value": v, "event_count": n}
        for (k, v), n in sorted(ent_counts.items(), key=lambda kv: -kv[1])
    ]
    c.fingerprint = fingerprint(c)
    return c


# ---------------------------------------------------- campaign matching

TIMING_BUCKETS = ["burst", "steady", "low_and_slow"]


def _timing_bucket(rows: list) -> str:
    if len(rows) < 2:
        return "burst"
    span = (rows[-1].ts - rows[0].ts).total_seconds()
    per_event = span / max(1, len(rows) - 1)
    if per_event < 10:
        return "burst"
    if per_event < 180:
        return "steady"
    return "low_and_slow"


def fingerprint(c: Cluster) -> dict:
    """
    A compact, comparable signature of *how* a campaign behaved — not who it
    was. Two attacks from different IPs using the same tooling, timing and
    technique set should look alike here.
    """
    from .enrich import load_assets
    assets = load_assets()

    hours = [0.0] * 24
    for ev in c.events:
        hours[ev.ts.hour] += 1
    total = sum(hours) or 1

    tiers = [assets[a].criticality for a in c.assets if a in assets]

    return {
        "techniques": sorted(set(c.techniques)),
        "tactics": sorted(set(c.tactics)),
        "asns": sorted({str(ev.asn) for ev in c.events if ev.asn}),
        "timing_bucket": _timing_bucket(c.events),
        "asset_tier": round(max(tiers), 2) if tiers else 0.0,
        "hour_profile": [round(h / total, 3) for h in hours],
        "event_count_log": round(math.log1p(len(c.events)), 2),
    }


def _vec(fp: dict, technique_vocab: list[str]) -> list[float]:
    v = [1.0 if t in set(fp.get("techniques", [])) else 0.0 for t in technique_vocab]
    v += [1.0 if fp.get("timing_bucket") == b else 0.0 for b in TIMING_BUCKETS]
    v += list(fp.get("hour_profile", [0.0] * 24))
    v.append(min(1.0, fp.get("event_count_log", 0.0) / 10.0))
    return v


def _cosine(a: list[float], b: list[float]) -> float:
    num = sum(x * y for x, y in zip(a, b))
    da = math.sqrt(sum(x * x for x in a))
    db = math.sqrt(sum(y * y for y in b))
    return 0.0 if da == 0 or db == 0 else num / (da * db)


def match_campaign(fp: dict, history: list[dict],
                   threshold: float = SIMILARITY_THRESHOLD) -> Optional[dict]:
    """
    Compare a new cluster against past incidents.

    history: [{"incident_id", "fingerprint", "status", "opened_at"}, ...]

    This is what answers "correlate past to current". Shared ASN alone is not
    enough — the technique set and timing profile have to line up too, which is
    why we compare vectors rather than doing an entity lookup.
    """
    if not history:
        return None
    vocab = sorted({t for h in history for t in h["fingerprint"].get("techniques", [])}
                   | set(fp.get("techniques", [])))
    if not vocab:
        return None
    target = _vec(fp, vocab)

    target_tech = set(fp.get("techniques", []))
    best, best_score = None, 0.0
    for h in history:
        h_tech = set(h["fingerprint"].get("techniques", []))
        # Two campaigns that share no technique are not the same campaign,
        # however similar their timing looks. Requiring overlap here is what
        # stops every burst of scraper traffic matching every other one.
        if not (target_tech & h_tech):
            continue
        s = _cosine(target, _vec(h["fingerprint"], vocab))
        # a shared ASN is corroborating evidence, not proof — small nudge only
        if set(fp.get("asns", [])) & set(h["fingerprint"].get("asns", [])):
            s = min(1.0, s + 0.05)
        if s > best_score:
            best, best_score = h, s

    if best is None or best_score < threshold:
        return None

    shared = sorted(set(fp.get("techniques", [])) &
                    set(best["fingerprint"].get("techniques", [])))
    shared += [f"ASN {a}" for a in sorted(set(fp.get("asns", [])) &
                                          set(best["fingerprint"].get("asns", [])))]
    if fp.get("timing_bucket") == best["fingerprint"].get("timing_bucket"):
        shared.append(f"{fp['timing_bucket']} timing")

    days = None
    if best.get("opened_at"):
        days = max(0, (datetime.now(timezone.utc) - best["opened_at"]).days)

    return {
        "id": best["incident_id"],
        "similarity": round(best_score, 2),
        "opened_at": best.get("opened_at"),
        "days_ago": days,
        "verdict": "confirmed_malicious" if best.get("status") == "confirmed" else best.get("status"),
        "shared": shared,
    }


def kill_chain_depth(cluster: Cluster) -> int:
    return len(set(cluster.tactics))


def should_escalate(cluster: Cluster) -> bool:
    """Three distinct tactics is an intrusion in progress, whatever the scores say."""
    return kill_chain_depth(cluster) >= ESCALATE_TACTICS


def title_for(cluster: Cluster) -> str:
    depth = kill_chain_depth(cluster)
    names = {
        "slow_recon": "Low-and-slow reconnaissance",
        "dir_scan": "Vulnerability scanning",
        "credential_stuffing": "Credential stuffing",
        "brute_force": "Brute force",
        "scraper": "Systematic content scraping",
        "flood": "Request flood",
    }
    base = names.get(cluster.primary_class or "", "Suspicious activity")
    if depth >= 3:
        return "Multi-stage reconnaissance and credential attack"
    if cluster.assets:
        return f"{base} against {cluster.assets[0]}"
    return base
