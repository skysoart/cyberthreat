"""
backend/scripts/generate_events.py — SHARED.

Generates the historical Event table that correlation runs against: ~56,000
events over 30 days of benign traffic, with five attack campaigns planted in it.

It writes EVENTS ONLY. No incidents, ever. correlate() has to rediscover all
five campaigns from the events alone — which is the point. If the incidents
were seeded, the dashboard would be showing results the engine never computed,
and "did your system derive this or did you type it in?" would have a bad
answer.

Every event is scored P3 or P4 individually, by construction rather than by
tuning: a single event touches one asset and reaches one ATT&CK tactic, so
blast_radius and kill_chain_depth sit at their floor and three of the six risk
terms cannot contribute. The P1s only exist after correlation.

Called from seed.py. Can also be run standalone against an existing database:
    python -m backend.scripts.generate_events
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

from backend.app.models.constants import priority_for

SEED = 42

# Residential ASNs carry benign traffic; hosting ASNs carry the attacks.
# `asn_is_hosting` is a real discriminator — people do not browse from AWS.
RESI_ASNS = [(55836, "IN"), (9829, "IN"), (24560, "IN"), (7922, "US"), (5607, "GB")]
HOST_ASNS = [(14061, "NL"), (16509, "US"), (9009, "RO"), (24940, "DE"), (63949, "SG")]

BENIGN_PATHS = [
    ("/", "cdn-edge"), ("/products", "catalogue-api"), ("/cart", "checkout-web"),
    ("/checkout", "checkout-web"), ("/login", "auth-service"),
    ("/account", "auth-service"), ("/search", "search-service"),
]

# The last entry is the one that RETURNS 200 — an exposed Spring Boot Actuator
# endpoint mapping to CVE-2022-22965, which is in CISA KEV. Everything else
# 404s. That single 200 is what takes the demo incident from noise to P1.
PROBE_PATHS = [
    ("/.env", "cdn-edge", 404), ("/.git/config", "cdn-edge", 404),
    ("/wp-admin/", "blog-cms", 404), ("/phpmyadmin/", "cdn-edge", 404),
    ("/admin.php", "cdn-edge", 404), ("/api/v1/config", "catalogue-api", 404),
    ("/actuator/env", "metrics-agent", 200),
]

BROWSER_FEATURES = [
    "mouse_move_count", "mouse_path_entropy", "keystroke_count",
    "keystroke_interval_mean", "keystroke_interval_std", "form_fill_ms",
    "paste_events", "click_count", "time_to_first_click_ms", "scroll_events",
    "page_dwell_ms", "focus_blur_count", "screen_w", "screen_h",
    "tz_offset", "hardware_concurrency",
]

UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
UA_TOOL = "python-requests/2.31.0"


def _sid(rnd: random.Random) -> str:
    return "s_%08x" % rnd.getrandbits(32)


def _uid(rnd: random.Random) -> str:
    return "u_%06x" % rnd.getrandbits(24)


def _ip(rnd: random.Random, prefix: str) -> str:
    return f"{prefix}.{rnd.randint(2, 254)}"


def human_browser(rnd: random.Random) -> dict:
    """A real person: irregular typing, mouse movement, unhurried forms."""
    return {
        "mouse_move_count": rnd.randint(40, 400),
        "mouse_path_entropy": round(rnd.uniform(3.8, 5.4), 2),
        "keystroke_count": rnd.randint(0, 60),
        "keystroke_interval_mean": round(rnd.uniform(120, 260), 1),
        "keystroke_interval_std": round(rnd.uniform(60, 180), 1),
        "form_fill_ms": rnd.randint(6000, 24000),
        "paste_events": rnd.choice([0, 0, 0, 1]),
        "click_count": rnd.randint(1, 14),
        "time_to_first_click_ms": rnd.randint(900, 6000),
        "scroll_events": rnd.randint(3, 40),
        "page_dwell_ms": rnd.randint(8000, 60000),
        "focus_blur_count": rnd.randint(0, 3),
        "screen_w": rnd.choice([1366, 1440, 1920, 2560]),
        "screen_h": rnd.choice([768, 900, 1080, 1440]),
        "tz_offset": rnd.choice([-330, 0, 300, 480]),
        "hardware_concurrency": rnd.choice([4, 8, 12, 16]),
    }


def absent_browser() -> dict:
    """No sensor ran. None, never 0 — unknown is not zero."""
    return {k: None for k in BROWSER_FEATURES}


def headless_browser(rnd: random.Random) -> dict:
    """
    A scraper driving a real headless browser (Playwright/Puppeteer). The
    sensor DOES run, so telemetry exists — but the behaviour underneath it is
    machine-like: almost no mouse movement, no typing, uniform dwell.

    This exists so `browser_telemetry_present` is a strong feature rather than
    a perfect one. Without a case like this, every attack in the dataset has
    the flag at 0 and every benign request has it at 1, the classifier learns
    that single column, and PR-AUC comes out at exactly 1.0 — a number that
    means the dataset was separable, not that the model is good.
    """
    return {
        "mouse_move_count": rnd.randint(0, 6),
        "mouse_path_entropy": round(rnd.uniform(0.0, 1.4), 2),
        "keystroke_count": 0,
        "keystroke_interval_mean": None,
        "keystroke_interval_std": None,
        "form_fill_ms": None,
        "paste_events": 0,
        "click_count": rnd.randint(0, 2),
        "time_to_first_click_ms": rnd.randint(20, 180),
        "scroll_events": rnd.randint(0, 3),
        "page_dwell_ms": rnd.randint(400, 1600),
        "focus_blur_count": 0,
        "screen_w": 1280, "screen_h": 720,          # default headless viewport
        "tz_offset": 0,
        "hardware_concurrency": rnd.choice([1, 2, 4]),
    }


def server_features(rnd: random.Random, **kw) -> dict:
    f = {
        "req_rate_10s": 1, "req_rate_60s": rnd.randint(3, 12),
        "req_rate_300s": rnd.randint(8, 40),
        "auth_fail_ip_60s": 0, "auth_fail_user_60s": 0,
        "distinct_users_tried_60s": 1, "auth_success_after_fails": 0,
        "unique_paths_60s": rnd.randint(2, 6), "p404_ratio_60s": 0.0,
        "path_entropy": round(rnd.uniform(1.2, 2.1), 2), "sensitive_path_hit": 0,
        "interarrival_mean_ms": rnd.randint(1500, 12000),
        "interarrival_std_ms": round(rnd.uniform(800, 4000), 1),
        "payload_bytes": rnd.randint(0, 900),
        "payload_bytes_std": round(rnd.uniform(0, 200), 1),
        "resp_bytes_60s": rnd.randint(4000, 90000),
        "header_count": rnd.randint(9, 14), "ua_missing": 0, "ua_known_tool": 0,
        "ua_entropy": round(rnd.uniform(4.1, 5.2), 2), "accept_lang_missing": 0,
        "header_order_hash_known": 0,
        "asn_is_hosting": 0, "country_risk": 0.1,
        "ip_reputation_hit": 0, "is_tor_exit": 0,
        "session_age_s": rnd.randint(5, 1800),
        "requests_this_session": rnd.randint(1, 25),
        "hour_of_day": 12, "is_off_hours": 0,
    }
    f.update(kw)
    return f


def _row(EventCls, ts, src_ip, asn, country, url_path, status, asset_id,
         pred_class, confidence, features, session_id=None, user_id=None,
         technique=None, source="server"):
    features = dict(features)
    features["hour_of_day"] = ts.hour
    features["is_off_hours"] = 1 if (ts.hour < 7 or ts.hour > 21) else 0
    features["browser_telemetry_present"] = (
        0 if features.get("mouse_move_count") is None else 1)

    # Individual events score low BY CONSTRUCTION, not by tuning: one asset,
    # one tactic, so blast_radius and kill_chain_depth are at their floor.
    risk = round(min(100.0, confidence * 34
                     + (12 if features["sensitive_path_hit"] else 0)), 1)

    # Historical events carry the same evidence a live one would. Without it
    # the detail page shows blank "why?" panels for anything older than the
    # current session, which is most of what a judge will click on.
    from backend.app.services.detect import evidence_for
    keys = ["browser_telemetry_present", "req_rate_60s"]
    if features.get("auth_fail_ip_60s"):
        keys = ["auth_fail_ip_60s", "distinct_users_tried_60s",
                "browser_telemetry_present", "asn_is_hosting"]
    elif features.get("sensitive_path_hit"):
        keys = ["sensitive_path_hit", "browser_telemetry_present",
                "asn_is_hosting", "interarrival_std_ms"]
    elif pred_class in ("flood", "scraper"):
        keys = ["req_rate_60s", "unique_paths_60s",
                "browser_telemetry_present", "interarrival_std_ms"]

    return EventCls(
        ts=ts.replace(tzinfo=None), session_id=session_id, source=source,
        src_ip=src_ip, asn=asn, country=country, user_id=user_id,
        asset_id=asset_id, url_path=url_path, http_status=status,
        raw_json=json.dumps({
            "ua": UA_BROWSER if features["browser_telemetry_present"] else UA_TOOL}),
        features_json=json.dumps(features),
        pred_class=pred_class, pred_confidence=round(confidence, 2),
        evidence_json=json.dumps(evidence_for(features, keys)),
        attack_technique=technique,
        individual_priority=priority_for(risk),
    )


# --------------------------------------------------------------- generators

def benign_day(EventCls, rnd, day_start, n):
    """Benign traffic with a realistic daily rhythm — quiet overnight, busy midday."""
    out = []
    for _ in range(n):
        hour = rnd.choices(range(24), weights=[
            2, 1, 1, 1, 1, 2, 4, 8, 14, 20, 26, 30,
            32, 30, 28, 26, 24, 22, 20, 16, 12, 8, 5, 3])[0]
        ts = day_start + timedelta(hours=hour, minutes=rnd.randint(0, 59),
                                   seconds=rnd.randint(0, 59))
        asn, country = rnd.choice(RESI_ASNS)
        path, asset = rnd.choice(BENIGN_PATHS)
        feats = server_features(rnd)

        # ~9% of legitimate traffic never runs JavaScript: mobile app clients,
        # RSS readers, uptime monitors, link previewers, someone with curl.
        # Real sites see this constantly. Omitting it would make the absence of
        # telemetry a perfect attack signal, which it is not.
        roll = rnd.random()
        if roll < 0.09:
            feats.update(absent_browser())
            feats["ua_known_tool"] = 1
            feats["accept_lang_missing"] = 1
        else:
            feats.update(human_browser(rnd))

        # ~4% of benign traffic looks superficially like an attack: search
        # engine crawlers walking the catalogue, a monitoring probe polling
        # fast, a shopper hammering refresh on a sale page.
        #
        # Without this the parameter ranges of each class are disjoint and the
        # dataset is perfectly separable — every metric comes out at 1.000,
        # which measures the generator rather than the model. Real traffic has
        # no such clean boundary, and a classifier that has never seen an
        # ambiguous request will not survive contact with one.
        if roll > 0.96:
            feats["req_rate_60s"] = rnd.randint(18, 60)
            feats["req_rate_10s"] = rnd.randint(4, 14)
            feats["unique_paths_60s"] = rnd.randint(10, 40)
            feats["interarrival_std_ms"] = round(rnd.uniform(20, 400), 1)
            if rnd.random() < 0.5:
                feats["p404_ratio_60s"] = round(rnd.uniform(0.3, 0.7), 2)
                feats["path_entropy"] = round(rnd.uniform(2.6, 3.8), 2)
            if rnd.random() < 0.4:
                feats["asn_is_hosting"] = 1        # corporate VPN / cloud NAT
        octet = f"{rnd.randint(49,203)}.{rnd.randint(0,255)}.{rnd.randint(0,255)}"
        out.append(_row(
            EventCls, ts, _ip(rnd, octet), asn, country, path, 200, asset,
            "normal", rnd.uniform(0.93, 0.99), feats,
            session_id=_sid(rnd),
            user_id=_uid(rnd) if path in ("/account", "/checkout") else None,
        ))
    return out


def campaign(EventCls, rnd, start, subnet, asn, country, targets,
             include_success=True):
    """
    Slow reconnaissance, then credential stuffing, then one successful login.

    Every event is individually unremarkable — rates stay inside normal bounds
    and per-account failures never reach a lockout threshold. Only the cluster
    is alarming, and only because it spans three ATT&CK tactics.

    The two source IPs deliberately never repeat: they link through the shared
    /24 and ASN, so IP-based alerting would miss the connection entirely.
    """
    out = []
    ip_a, ip_b = _ip(rnd, subnet), _ip(rnd, subnet)
    t = start

    # Stage 1 — reconnaissance
    probes = rnd.sample(PROBE_PATHS[:-1], 4) + [PROBE_PATHS[-1]]
    for path, asset, status in probes:
        feats = server_features(
            rnd, req_rate_60s=1, req_rate_10s=1, unique_paths_60s=1,
            p404_ratio_60s=1.0 if status == 404 else 0.0,
            path_entropy=round(rnd.uniform(3.4, 4.2), 2),
            sensitive_path_hit=1,
            interarrival_std_ms=round(rnd.uniform(2.0, 6.0), 1),
            asn_is_hosting=1, country_risk=0.6,
            ua_known_tool=1, accept_lang_missing=1, header_count=5,
        )
        feats.update(absent_browser())
        out.append(_row(EventCls, t, ip_a, asn, country, path, status, asset,
                        "slow_recon", rnd.uniform(0.66, 0.87), feats,
                        technique="T1595.002"))
        t += timedelta(minutes=rnd.randint(5, 12))

    # Stage 2 — credential stuffing, one attempt per account
    for u in targets:
        feats = server_features(
            rnd, auth_fail_ip_60s=len(targets), auth_fail_user_60s=1,
            distinct_users_tried_60s=len(targets),
            asn_is_hosting=1, country_risk=0.6, ua_known_tool=1,
            interarrival_std_ms=round(rnd.uniform(2.0, 8.0), 1),
            payload_bytes=rnd.randint(90, 140),
        )
        feats.update(absent_browser())
        out.append(_row(EventCls, t, ip_b, asn, country, "/login", 401,
                        "auth-service", "credential_stuffing",
                        rnd.uniform(0.81, 0.90), feats, user_id=u,
                        technique="T1110.004"))
        t += timedelta(minutes=rnd.randint(3, 6))

    # Stage 3 — one success. This is the third tactic (T1078 Valid Accounts),
    # and it is what takes kill_chain_depth to 3 and the cluster to P1.
    if include_success:
        feats = server_features(
            rnd, auth_fail_ip_60s=len(targets), auth_success_after_fails=1,
            distinct_users_tried_60s=len(targets),
            asn_is_hosting=1, country_risk=0.6, ua_known_tool=1,
        )
        feats.update(absent_browser())
        out.append(_row(EventCls, t, ip_b, asn, country, "/login", 200,
                        "auth-service", "credential_stuffing",
                        rnd.uniform(0.88, 0.93), feats, user_id=targets[-1],
                        technique="T1078"))
    return out


def noisy_campaign(EventCls, rnd, start, kind, subnet, asn, country):
    """High-volume attacks — loud, trivially detected, and NOT the interesting case."""
    out, t, ip = [], start, _ip(rnd, subnet)

    if kind == "dir_scan":
        for i in range(rnd.randint(120, 240)):
            path, asset, status = rnd.choice(PROBE_PATHS[:-1])
            feats = server_features(
                rnd, req_rate_60s=rnd.randint(40, 90), p404_ratio_60s=0.97,
                unique_paths_60s=rnd.randint(30, 70), sensitive_path_hit=1,
                path_entropy=4.1, asn_is_hosting=1, ua_known_tool=1,
                interarrival_std_ms=round(rnd.uniform(1.0, 5.0), 1),
            )
            feats.update(absent_browser())
            out.append(_row(EventCls, t, ip, asn, country,
                            f"{path}{i % 7 or ''}", status, asset, "dir_scan",
                            rnd.uniform(0.90, 0.97), feats, technique="T1595.002"))
            t += timedelta(seconds=rnd.randint(1, 4))

    elif kind == "scraper":
        for page in range(1, rnd.randint(180, 400)):
            feats = server_features(
                rnd, req_rate_60s=rnd.randint(20, 45),
                unique_paths_60s=rnd.randint(20, 45), asn_is_hosting=1,
                interarrival_std_ms=round(rnd.uniform(5, 40), 1),
            )
            # This scraper drives a headless browser, so it DOES report
            # telemetry — it just behaves like a machine underneath.
            feats.update(headless_browser(rnd))
            out.append(_row(EventCls, t, ip, asn, country,
                            f"/products?page={page}", 200, "catalogue-api",
                            "scraper", rnd.uniform(0.50, 0.72), feats,
                            technique="T1592"))
            t += timedelta(seconds=rnd.randint(2, 6))

    elif kind == "brute_force":
        # Many attempts against ONE account, which is what separates this from
        # credential stuffing. The class has to exist in the training data or
        # the model can never predict it, however well the rules would have.
        user = "u_%06x" % rnd.getrandbits(24)
        for i in range(rnd.randint(60, 140)):
            feats = server_features(
                rnd, auth_fail_ip_60s=min(60, i + 1),
                auth_fail_user_60s=min(60, i + 1),
                distinct_users_tried_60s=1,
                req_rate_60s=rnd.randint(20, 60),
                asn_is_hosting=1, ua_known_tool=1,
                interarrival_std_ms=round(rnd.uniform(1.0, 20.0), 1),
                payload_bytes=rnd.randint(80, 130),
            )
            feats.update(absent_browser())
            out.append(_row(EventCls, t, ip, asn, country, "/login", 401,
                            "auth-service", "brute_force",
                            rnd.uniform(0.88, 0.97), feats, user_id=user,
                            technique="T1110.001"))
            t += timedelta(seconds=rnd.randint(1, 5))

    elif kind == "flood":
        for _ in range(rnd.randint(2000, 5000)):
            feats = server_features(
                rnd, req_rate_10s=rnd.randint(80, 200),
                req_rate_60s=rnd.randint(400, 900),
                payload_bytes=rnd.randint(20, 60), payload_bytes_std=2.0,
                unique_paths_60s=1, asn_is_hosting=1,
                interarrival_std_ms=round(rnd.uniform(0.5, 3.0), 1),
            )
            feats.update(absent_browser())
            out.append(_row(EventCls, t, ip, asn, country, "/checkout", 503,
                            "checkout-web", "flood", rnd.uniform(0.96, 0.99),
                            feats, technique="T1498"))
            t += timedelta(milliseconds=rnd.randint(150, 600))

    return out


# --------------------------------------------------------------------- main

def build(EventCls, days: int = 30, per_day: int = 1700) -> list:
    """Return the full list of Event rows. Deterministic for a given seed."""
    rnd = random.Random(SEED)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = (now - timedelta(days=days - 1)).replace(hour=0)

    events: list = []
    for d in range(days):
        events += benign_day(EventCls, rnd, start + timedelta(days=d),
                             per_day + rnd.randint(-250, 250))

    # Four historical campaigns. Two share ASN 14061 with today's, so campaign
    # fingerprint matching has a genuine near-neighbour rather than a contrived one.
    events += campaign(EventCls, rnd, start + timedelta(days=5, hours=2, minutes=11),
                       "185.220.101", 14061, "NL", [_uid(rnd), _uid(rnd), _uid(rnd)])
    events += campaign(EventCls, rnd, start + timedelta(days=12, hours=19),
                       "45.155.205", 9009, "RO", [_uid(rnd), _uid(rnd)],
                       include_success=False)
    events += noisy_campaign(EventCls, rnd, start + timedelta(days=19, hours=8, minutes=41),
                             "dir_scan", "45.155.205", 9009, "RO")
    events += noisy_campaign(EventCls, rnd, start + timedelta(days=23, hours=3, minutes=12),
                             "brute_force", "45.155.205", 9009, "RO")
    events += noisy_campaign(EventCls, rnd, start + timedelta(days=28, hours=23, minutes=41),
                             "flood", "185.220.101", 14061, "NL")

    # Today: the demo campaign. Nine events, every one P4 on its own.
    # Targets are the three seeded demo accounts.
    events += campaign(EventCls, rnd, now.replace(hour=9, minute=14),
                       "185.220.101", 14061, "NL",
                       ["u_3b71ef", "u_c04d92", "u_8f2a1c"])
    events += noisy_campaign(EventCls, rnd, now.replace(hour=9, minute=2),
                             "scraper", "138.201.44", 24940, "DE")

    events.sort(key=lambda e: e.ts)
    return events


def seed_events(db, EventCls, days: int = 30, per_day: int = 1700) -> dict:
    """Insert generated events into an open session. Returns a stats dict."""
    events = build(EventCls, days=days, per_day=per_day)
    bands: dict[str, int] = {}
    for e in events:
        bands[e.individual_priority] = bands.get(e.individual_priority, 0) + 1
    stats = {
        "total": len(events),
        "priorities": dict(sorted(bands.items())),
        "first": events[0].ts,
        "last": events[-1].ts,
    }
    for i in range(0, len(events), 2000):
        db.add_all(events[i:i + 2000])
        db.flush()
    return stats


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from backend.app.database import SessionLocal, engine
    from backend.app.models.tables import Base, Event
    import backend.app.models.security_tables  # noqa: F401  (registers tables)

    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        session.query(Event).delete()
        st = seed_events(session, Event)
        session.commit()
        print(f"seeded {st['total']:,} events   priorities {st['priorities']}")
    finally:
        session.close()
