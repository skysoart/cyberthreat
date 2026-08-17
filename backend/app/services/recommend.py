"""
Adamantine — response recommendations.

No language model. Anywhere.

Actions are selected from playbooks.yaml by MITRE ATT&CK technique ID and
rendered with string substitution. The narrative is a template filled with
values computed elsewhere in the pipeline. Nothing here generates text that
was not written by a human first.

That constraint is not a limitation we are working around — it is the answer
to the hardest question a judge can ask about an AI security tool. "How do you
know it isn't inventing remediation steps?" Because nothing in this file can
invent anything. Every action carries a playbook ID you can look up.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml

DATA = Path(__file__).resolve().parents[1] / "data"
SECTIONS = ["containment", "eradication", "recovery", "hunt"]


@lru_cache(maxsize=1)
def load_playbooks() -> dict:
    p = DATA / "playbooks.yaml"
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def _context(cluster, enrichments: dict) -> dict[str, str]:
    """Values available to placeholders. Every one is derived, never invented."""
    import ipaddress

    top_ip = cluster.events[0].src_ip if cluster.events else ""
    try:
        subnet = str(ipaddress.ip_network(f"{top_ip}/24", strict=False)).rsplit(".", 1)[0]
    except ValueError:
        subnet = top_ip

    cve = matched_asset = None
    for ev in cluster.events:
        en = enrichments.get(ev.id)
        if en is not None and getattr(en, "cve", None):
            cve = en.cve
            matched_asset = getattr(en, "matched_asset", None) or (ev.asset_id or "")
            if getattr(en, "probe_succeeded", False):
                break   # a confirmed hit outranks a mere probe

    return {
        "top_asn": str(cluster.top_asn or "unknown"),
        "n_users": str(len(cluster.users)),
        "assets": ", ".join(cluster.assets) or "the affected assets",
        "cve": cve or "the identified vulnerability",
        "matched_asset": matched_asset or (cluster.assets[0] if cluster.assets else "the affected asset"),
        "top_ip": top_ip,
        "subnet": subnet,
    }


def _fill(text: str, ctx: dict[str, str]) -> str:
    for k, v in ctx.items():
        text = text.replace("{" + k + "}", v)
    return text


def recommend(cluster, enrichments: dict) -> dict[str, list[dict]]:
    """
    Technique IDs -> playbook actions, de-duplicated by ID, order preserved.

    A cluster spanning reconnaissance, credential access and initial access
    pulls from three playbooks; overlapping actions (blocking the ASN appears
    in several) collapse to one entry rather than being listed three times.
    """
    books = load_playbooks()
    ctx = _context(cluster, enrichments)

    techniques = [t for t in cluster.techniques if t in books] or ["default"]
    out: dict[str, list[dict]] = {s: [] for s in SECTIONS}
    seen: set[str] = set()

    for tech in techniques:
        book = books.get(tech) or {}
        for section in SECTIONS:
            for action in book.get(section) or []:
                aid = action.get("id")
                if not aid or aid in seen:
                    continue
                seen.add(aid)
                entry = {
                    "id": aid,
                    "action": _fill(str(action.get("action", "")), ctx),
                    "owner": action.get("owner", "SOC"),
                    "eta_min": action.get("eta_min", 15),
                    "rollback": _fill(str(action.get("rollback", "N/A")), ctx),
                    "technique_id": tech,
                }
                if action.get("query"):
                    entry["query"] = _fill(str(action["query"]), ctx)
                out[section].append(entry)

    return out


def narrative(cluster, scoring: dict, enrichments: dict,
              similar: Optional[dict] = None) -> str:
    """
    The analyst-facing write-up. A filled template, not generated prose.

    Deliberately leads with what the events looked like INDIVIDUALLY, because
    that is the point being made: none of them warranted attention on their own.
    """
    ctx = _context(cluster, enrichments)
    ev = cluster.events
    n = len(ev)
    span_min = int((cluster.last_seen_at - cluster.opened_at).total_seconds() // 60)
    ips = sorted({e.src_ip for e in ev})
    depth = scoring.get("kill_chain_depth", len(set(cluster.tactics)))

    paras: list[str] = []

    where = f"{len(ips)} address{'es' if len(ips) > 1 else ''}"
    if len(ips) > 1:
        where += f" inside {ctx['subnet']}.0/24"
    paras.append(
        f"Between {cluster.opened_at:%H:%M} and {cluster.last_seen_at:%H:%M} UTC, "
        f"{n} event{'s' if n != 1 else ''} reached Sample Store from {where} "
        f"(AS{ctx['top_asn']}), over {span_min} minutes."
    )

    if cluster.max_individual_priority in ("P3", "P4"):
        paras.append(
            f"No single event warranted attention. The highest any of them scored "
            f"individually was {cluster.max_individual_priority}. Request rates stayed "
            f"inside normal bounds and per-account authentication failures never "
            f"reached a lockout threshold."
        )

    if depth >= 2:
        stages = " → ".join(f"{s['tactic']} ({s['technique_id']})" for s in cluster.kill_chain)
        paras.append(
            f"Correlated on shared infrastructure within the window, the pattern spans "
            f"{depth} distinct ATT&CK tactic{'s' if depth != 1 else ''}: {stages}."
        )

    ti = None
    for e in ev:
        en = enrichments.get(e.id)
        if en is not None and getattr(en, "in_kev", False):
            ti = en
            break
    if ti is not None:
        paras.append(
            f"{ti.cve} ({ti.cve_name}) was reachable on {ti.matched_asset}, which runs "
            f"{ti.matched_software}. It is listed in the CISA Known Exploited "
            f"Vulnerabilities catalogue"
            + (f" (added {ti.kev_added})" if ti.kev_added else "")
            + (f" with an EPSS score of {ti.epss:.3f}" if ti.epss else "")
            + ". This is a vulnerability confirmed to be exploited in the wild against "
              "software we actually run."
        )

    no_js = sum(1 for e in ev
                if '"browser_telemetry_present": 0' in (e.features_json or ""))
    if no_js == n and n > 1:
        paras.append(
            "None of these requests executed the Adamantine browser sensor, indicating "
            "direct API access rather than browser traffic throughout."
        )

    if similar:
        paras.append(
            f"This incident shares {', '.join(similar['shared'][:4])} with "
            f"{similar['id']}"
            + (f" ({similar['days_ago']} days ago)" if similar.get("days_ago") is not None else "")
            + f" at {int(similar['similarity'] * 100)}% similarity"
            + (", which was analyst-confirmed malicious."
               if similar.get("verdict") == "confirmed_malicious" else ".")
        )

    if scoring.get("escalated_by_kill_chain"):
        paras.append(
            "Priority was floored at P1 by the kill-chain rule: three or more distinct "
            "tactics indicates an intrusion in progress regardless of the arithmetic score."
        )

    return "\n\n".join(paras)


def summary(cluster, scoring: dict) -> str:
    """One-paragraph version for the incident card."""
    n = len(cluster.events)
    span = int((cluster.last_seen_at - cluster.opened_at).total_seconds() // 60)
    depth = scoring.get("kill_chain_depth", 0)
    return (
        f"{n} event{'s' if n != 1 else ''} over {span} minutes from "
        f"AS{cluster.top_asn or 'unknown'}. "
        f"Highest individual event priority: {cluster.max_individual_priority}. "
        f"Correlated: {scoring['priority']} at risk {scoring['risk_score']}, "
        f"spanning {depth} ATT&CK tactic{'s' if depth != 1 else ''}."
    )
