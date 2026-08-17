"""
backend/scripts/verify_intelligence.py — Team 2 acceptance test.

Run after seed.py. Asserts the thesis of the whole project:

    the same events that score P4 individually must score P1 correlated

If that inversion does not hold, correlation is doing nothing and the product
is a classifier with extra steps. Every other check here is secondary.

    python backend/scripts/verify_intelligence.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.database import SessionLocal, engine          # noqa: E402
from backend.app.models.tables import Base, Event, Incident    # noqa: E402
import backend.app.models.security_tables                      # noqa: E402,F401
from backend.app.services import enrich as enr                 # noqa: E402
from backend.app.services.engine import ThreatEngine           # noqa: E402

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
passed = failed = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  {GREEN}PASS{OFF}  {label}  {DIM}{detail}{OFF}")
    else:
        failed += 1
        print(f"  {RED}FAIL{OFF}  {label}  {detail}")


def main() -> None:
    Base.metadata.create_all(bind=engine)
    print(f"\n{BOLD}Adamantine — Intelligence layer verification{OFF}\n")

    st = enr.feeds_status()
    print(f"{BOLD}threat intelligence{OFF}")
    print(f"  KEV {st['kev_entries']:,} · EPSS {st['epss_entries']} · "
          f"Feodo {st['feodo_ips']:,} · Tor {st['tor_exits']:,}")
    if not st["kev_entries"]:
        print(f"  {DIM}no feed cache — run scripts/fetch_feeds.py for real KEV data{OFF}")

    # ---- enrichment
    print(f"\n{BOLD}enrichment{OFF}")
    hit = enr.enrich("/actuator/env", 200, "metrics-agent", "185.220.101.34", 14061, "NL")
    check("/actuator/env 200 maps to a CVE", hit.cve == "CVE-2022-22965", hit.cve or "none")
    check("confirmed exposure raises exploitability", hit.exploitability >= 0.5,
          f"exploitability={hit.exploitability}")
    check("asset inventory matched", hit.matched_asset == "metrics-agent",
          hit.matched_asset or "no match — check cpe_product in assets.csv")
    check("hosting ASN detected", hit.asn_is_hosting)
    miss = enr.enrich("/actuator/env", 404, "metrics-agent", "185.220.101.34", 14061, "NL")
    check("404 on the same path scores lower than 200",
          miss.exploitability < hit.exploitability,
          f"{miss.exploitability} < {hit.exploitability}")
    benign = enr.enrich("/products", 200, "catalogue-api", "49.36.182.14", 55836, "IN")
    check("benign request has zero exploitability", benign.exploitability == 0.0)

    # ---- correlation
    print(f"\n{BOLD}correlation{OFF}")
    db = SessionLocal()
    try:
        total = db.query(Event).count()
        noisy = db.query(Event).filter(Event.pred_class != "normal").count()
        prios = {p for (p,) in db.query(Event.individual_priority).distinct()}
    finally:
        db.close()

    check("seeded database present", total > 1000, f"{total:,} events")
    check("no event is individually P1 or P2", not (prios & {"P1", "P2"}),
          f"event priorities present: {sorted(x for x in prios if x)}")

    eng = ThreatEngine()
    n = eng.correlate()
    check("correlation produced incidents", n > 0,
          f"{n} incidents from {noisy:,} non-normal events")

    db = SessionLocal()
    try:
        incs = db.query(Incident).order_by(Incident.risk_score.desc()).all()
        p1 = [i for i in incs if i.priority == "P1"]
        p2 = [i for i in incs if i.priority == "P2"]
        multi = [i for i in incs if i.kill_chain_depth >= 2]
        deep = [i for i in incs if i.kill_chain_depth >= 3]
        matched = [i for i in incs if i.has_similar]
        top_id = incs[0].id if incs else None
    finally:
        db.close()

    # ---- THE ACCEPTANCE TEST ----
    print(f"\n{BOLD}the inversion (this is the project){OFF}")
    check("correlation created P1 incidents from a table with none",
          len(p1) > 0, f"{len(p1)} P1, {len(p2)} P2")
    check("multi-stage kill chains reconstructed", len(multi) > 0,
          f"{len(multi)} incidents span 2+ ATT&CK tactics")
    check("a 3-tactic campaign was found", len(deep) > 0,
          f"{len(deep)} incidents reach 3 tactics")
    check("historical campaign matching fired", len(matched) > 0,
          f"{len(matched)} incidents matched a prior campaign")
    reduction = 100.0 * (1 - len(incs) / max(1, total))
    check("noise reduction above 99%", reduction > 99.0, f"{reduction:.2f}%")

    # ---- detail payload matches the frontend contract
    print(f"\n{BOLD}incident detail payload{OFF}")
    d = eng.get_incident(top_id)
    for key in ("risk_breakdown", "kill_chain", "entity_graph_svg",
                "recommendations", "narrative", "events", "summary"):
        check(f"detail contains {key}", bool(d.get(key)))
    pts = sum(v["points"] for v in d["risk_breakdown"].values())
    check("risk breakdown sums to risk score",
          abs(pts - d["risk_score"]) < 0.2, f"{pts:.1f} vs {d['risk_score']}")
    ev_prios = {e["individual_priority"] for e in d["events"]}
    check("its own events are all low priority individually",
          ev_prios <= {"P3", "P4"}, f"event priorities: {sorted(ev_prios)}")
    n_actions = sum(len(v) for v in d["recommendations"].values())
    check("recommendations returned with playbook IDs", n_actions > 0,
          f"{n_actions} actions")

    # ---- the other API surfaces the dashboard calls
    print(f"\n{BOLD}dashboard endpoints{OFF}")
    ov = eng.get_overview()
    check("overview has counters and trend",
          bool(ov["counters"]["events_total"]) and len(ov["trend"]) > 1,
          f"{len(ov['trend'])} days of trend")
    q = eng.get_incidents(limit=5)
    check("incident queue sorted by risk descending",
          all(q["incidents"][i]["risk_score"] >= q["incidents"][i + 1]["risk_score"]
              for i in range(len(q["incidents"]) - 1)))
    m = eng.get_metrics()
    check("metrics funnel populated", m["funnel"]["events"] > 0,
          f"{m['funnel']['events']:,} -> {m['funnel']['incidents']} -> "
          f"{m['funnel']['actionable']}")
    check("weights load and sum to 1.0",
          abs(sum(eng.get_weights().values()) - 1.0) < 0.001)
    rq = eng.get_review_queue()
    check("review queue returns uncertainty-sampled items", rq["total"] > 0,
          f"{rq['total']} items")

    # ---- feedback loop
    print(f"\n{BOLD}feedback loop{OFF}")
    fb = eng.submit_feedback(top_id, "false_positive", "verify")
    check("feedback recorded and status changed",
          fb["ok"] and fb["new_status"] == "false_positive",
          f"{fb['labels_pending']} labels pending")
    eng.submit_feedback(top_id, "confirmed_threat", "verify")
    mdl = eng.get_model()
    check("model endpoint responds without an artifact",
          "current" in mdl and "feeds" in mdl,
          f"version={mdl['current']['version']}")

    # ---- headline
    print(f"\n{BOLD}headline{OFF}")
    print(f"  {total:,} events  ->  {len(incs)} incidents  ->  "
          f"{len(p1) + len(p2)} that matter   ({reduction:.2f}% reduction)")
    print(f"\n  {BOLD}{d['id']}{OFF}  {d['title']}")
    print(f"  risk {d['risk_score']} · {d['priority']} · {len(d['events'])} events · "
          f"{len(d['kill_chain'])} tactics")
    for term, v in d["risk_breakdown"].items():
        bar = "█" * int(v["points"] / 1.5)
        print(f"    {term:<20} {v['raw']:>5.2f} x {v['weight']:.2f} = "
              f"{v['points']:>5.1f}  {bar}")

    print(f"\n{BOLD}{passed} passed, {failed} failed{OFF}\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
