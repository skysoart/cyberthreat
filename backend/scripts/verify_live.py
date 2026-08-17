"""
backend/scripts/verify_live.py — end-to-end test against a RUNNING server.

Exercises the real HTTP path, not the library: account creation, login,
and four attack patterns driven exactly the way a person would drive them
by hand. Then it asks the dashboard whether it noticed.

    uvicorn backend.app.main:app --port 8000     # terminal 1
    python backend/scripts/verify_live.py        # terminal 2

This is the check that matters for the demo. verify_intelligence.py proves the
engine works on seeded history; this proves the system reacts to traffic
arriving right now.
"""

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

BASE = "http://127.0.0.1:8000"
GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
passed = failed = 0


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  {GREEN}PASS{OFF}  {label}  {DIM}{detail}{OFF}")
    else:
        failed += 1
        print(f"  {RED}FAIL{OFF}  {label}  {detail}")


def main():
    global failed
    try:
        httpx.get(f"{BASE}/api/v1/overview", timeout=5)
    except Exception:
        print(f"\n{RED}Server not reachable at {BASE}{OFF}")
        print("Start it first:  uvicorn backend.app.main:app --port 8000\n")
        sys.exit(2)

    c = httpx.Client(base_url=BASE, timeout=20, follow_redirects=True)
    stamp = int(time.time())
    new_email = f"tester{stamp}@samplestore.test"

    # ---------------------------------------------------------------- store
    print(f"\n{BOLD}Adamantine — live verification{OFF}\n")
    print(f"{BOLD}sample store{OFF}")
    r = c.get("/")
    check("home page serves", r.status_code == 200, f"{len(r.text)} bytes")
    r = c.get("/actuator/env")
    check("/actuator/env returns 200 (the planted exposure)",
          r.status_code == 200, f"status {r.status_code}")
    r = c.get("/.env")
    check("/.env returns 404", r.status_code == 404, f"status {r.status_code}")

    # ------------------------------------------------------------ accounts
    print(f"\n{BOLD}accounts{OFF}")
    r = c.post("/register", json={"email": new_email, "password": "MyPassw0rd!",
                                  "full_name": "Live Tester"})
    check("can create a new account", r.status_code in (200, 201),
          f"status {r.status_code} {r.text[:120]}")

    r = c.post("/register", json={"email": new_email, "password": "MyPassw0rd!",
                                  "full_name": "Live Tester"})
    check("duplicate registration rejected", r.status_code == 409,
          f"status {r.status_code}")

    r = c.post("/login", json={"email": new_email, "password": "MyPassw0rd!"})
    check("can log in with the new account", r.status_code == 200,
          f"status {r.status_code} {r.text[:120]}")

    r = c.post("/login", json={"email": new_email, "password": "wrong-password"})
    check("wrong password rejected", r.status_code == 401, f"status {r.status_code}")

    r = c.post("/login", json={"email": "alice@samplestore.test",
                               "password": "demo1234"})
    check("seeded demo account still works", r.status_code == 200,
          f"status {r.status_code}")

    # ------------------------------------------------------------- attacks
    print(f"\n{BOLD}driving attacks by hand{OFF}")
    atk = httpx.Client(base_url=BASE, timeout=20)

    for _ in range(12):
        atk.post("/login", json={"email": "alice@samplestore.test",
                                 "password": "guess-me"})
    print(f"  {DIM}12 failed logins for one account (brute force){OFF}")

    for i in range(10):
        atk.post("/login", json={"email": f"victim{i}@samplestore.test",
                                 "password": "Password123"})
    print(f"  {DIM}10 accounts tried from one address (credential stuffing){OFF}")

    for p in ["/wp-admin/", "/phpmyadmin/", "/.git/config", "/admin.php",
              "/backup.sql", "/config.json", "/server-status", "/.aws/credentials",
              "/debug/pprof/", "/.DS_Store"]:
        atk.get(p)
    print(f"  {DIM}10 sensitive paths probed (directory scan){OFF}")

    for _ in range(80):
        atk.get("/products")
    print(f"  {DIM}80 rapid requests (flood){OFF}")

    # ------------------------------------------------------------ detection
    print(f"\n{BOLD}did the platform notice?{OFF}")
    r = c.post("/api/v1/correlate")
    check("correlation endpoint responds", r.status_code == 200,
          f"{r.json().get('incidents')} incidents")

    ov = c.get("/api/v1/overview").json()
    classes = ov["class_split"]
    live = {k: v for k, v in classes.items() if k != "normal"}
    print(f"  {DIM}classes seen: {live}{OFF}")

    for want in ("brute_force", "credential_stuffing", "dir_scan"):
        check(f"detected {want}", classes.get(want, 0) > 0,
              f"{classes.get(want, 0)} events")
    check("detected flood or scraper",
          classes.get("flood", 0) + classes.get("scraper", 0) > 0,
          f"flood={classes.get('flood', 0)} scraper={classes.get('scraper', 0)}")

    incs = c.get("/api/v1/incidents").json()
    check("incident queue populated", incs["total"] > 0, f"{incs['total']} incidents")

    if incs["incidents"]:
        top = incs["incidents"][0]
        det = c.get(f"/api/v1/incidents/{top['id']}").json()
        pts = sum(v["points"] for v in det["risk_breakdown"].values())
        check("top incident breakdown sums to its score",
              abs(pts - det["risk_score"]) < 0.2,
              f"{pts:.1f} vs {det['risk_score']}")
        check("recommendations carry playbook IDs",
              any(a.get("id") for grp in det["recommendations"].values() for a in grp))
        check("every event carries evidence",
              all(e["evidence"] for e in det["events"]),
              f"{len(det['events'])} events")

        print(f"\n  {BOLD}{top['id']}{OFF}  {top['title']}")
        print(f"  {top['priority']} · risk {top['risk_score']} · "
              f"{top['event_count']} events · {top['kill_chain_depth']} tactics")
        for t in det["kill_chain"]:
            print(f"    {t['tactic']:<20} {t['technique_id']:<12} "
                  f"x{t['event_count']}")

    # ---------------------------------------------------------- other APIs
    print(f"\n{BOLD}remaining endpoints{OFF}")
    for path in ("/api/v1/metrics", "/api/v1/model",
                 "/api/v1/review-queue", "/api/v1/settings/weights"):
        r = c.get(path)
        check(f"GET {path}", r.status_code == 200, f"status {r.status_code}")

    print(f"\n{BOLD}{passed} passed, {failed} failed{OFF}\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
