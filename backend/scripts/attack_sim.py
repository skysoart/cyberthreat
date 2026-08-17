"""
backend/scripts/attack_sim.py  — Team 1
Simulates HTTP attack traffic against http://localhost:8000.
ONLY targets the local demo application — never external hosts.

Usage:
    python backend/scripts/attack_sim.py --scenario brute_force
    python backend/scripts/attack_sim.py --scenario dir_scan
    python backend/scripts/attack_sim.py --scenario slow_recon
    python backend/scripts/attack_sim.py --scenario all
"""
import argparse
import time
import random
import sys
import requests

BASE_URL = "http://localhost:8000"

ATTACK_CLASSES = [
    "normal", "brute_force", "credential_stuffing",
    "dir_scan", "flood", "scraper", "slow_recon",
]

_COMMON_PATHS = ["/products", "/", "/cart", "/checkout", "/account"]
_SCAN_PATHS = [
    "/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/", "/admin",
    "/actuator/env", "/config.php", "/backup.zip", "/server-status",
    "/api/v1/", "/.htaccess", "/etc/passwd",
]
_CREDENTIALS = [
    ("alice@samplestore.test", "wrongpassword"),
    ("bob@samplestore.test",   "password123"),
    ("admin@store.com",        "admin"),
    ("root@localhost",         "root"),
]


def _get(path: str, headers: dict | None = None) -> int:
    try:
        r = requests.get(f"{BASE_URL}{path}", headers=headers, timeout=5)
        return r.status_code
    except Exception:
        return 0


def _post(path: str, data: dict, headers: dict | None = None) -> int:
    try:
        r = requests.post(f"{BASE_URL}{path}", json=data, headers=headers, timeout=5)
        return r.status_code
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scenario_normal(n: int = 20):
    """Regular browsing traffic."""
    print(f"[normal] Sending {n} normal requests...")
    for _ in range(n):
        path = random.choice(_COMMON_PATHS)
        status = _get(path)
        print(f"  GET {path} → {status}")
        time.sleep(random.uniform(0.5, 2.0))


def scenario_brute_force(n: int = 30):
    """Rapid credential guessing against /login."""
    print(f"[brute_force] Sending {n} login attempts...")
    for _ in range(n):
        email, pw = random.choice(_CREDENTIALS)
        status = _post("/login", {"email": email, "password": pw})
        print(f"  POST /login {email} → {status}")
        time.sleep(random.uniform(0.05, 0.2))


def scenario_credential_stuffing(n: int = 20):
    """Credential stuffing — slower, varying IPs simulated via User-Agent."""
    print(f"[credential_stuffing] {n} stuffing attempts...")
    emails = [
        "alice@samplestore.test", "bob@samplestore.test",
        "carol@samplestore.test", "dave@example.com", "eve@company.org",
    ]
    for _ in range(n):
        email = random.choice(emails)
        pw = "Summer2024!"
        status = _post("/login", {"email": email, "password": pw})
        print(f"  POST /login {email} → {status}")
        time.sleep(random.uniform(0.3, 1.5))


def scenario_dir_scan(paths: list | None = None):
    """Directory enumeration scan."""
    paths = paths or _SCAN_PATHS
    print(f"[dir_scan] Scanning {len(paths)} paths...")
    for path in paths:
        status = _get(path)
        print(f"  GET {path} → {status}")
        time.sleep(random.uniform(0.01, 0.1))


def scenario_flood(n: int = 100):
    """High-rate flood."""
    print(f"[flood] Flooding with {n} requests...")
    for _ in range(n):
        status = _get("/")
        print(f"  GET / → {status}", end="\r")
    print()


def scenario_scraper(pages: int = 50):
    """Scraping the product catalogue."""
    print(f"[scraper] Scraping {pages} product pages...")
    for page in range(1, pages + 1):
        status = _get(f"/products?page={page}")
        print(f"  GET /products?page={page} → {status}")
        time.sleep(random.uniform(0.05, 0.15))


def scenario_slow_recon(n: int = 10, delay: float = 30.0):
    """Low-and-slow reconnaissance with long inter-request gaps."""
    paths = random.sample(_SCAN_PATHS + _COMMON_PATHS, min(n, len(_SCAN_PATHS + _COMMON_PATHS)))
    print(f"[slow_recon] {len(paths)} requests, {delay}s apart...")
    for path in paths:
        status = _get(path)
        print(f"  GET {path} → {status}")
        print(f"  (sleeping {delay}s...)")
        time.sleep(delay)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Adamantine attack simulator — localhost only")
    parser.add_argument("--scenario", choices=ATTACK_CLASSES + ["all"], default="normal")
    parser.add_argument("--n", type=int, default=None, help="Override request count")
    args = parser.parse_args()

    scenario_map = {
        "normal":               scenario_normal,
        "brute_force":          scenario_brute_force,
        "credential_stuffing":  scenario_credential_stuffing,
        "dir_scan":             scenario_dir_scan,
        "flood":                scenario_flood,
        "scraper":              scenario_scraper,
        "slow_recon":           scenario_slow_recon,
    }

    if args.scenario == "all":
        for name, fn in scenario_map.items():
            print(f"\n{'='*60}\nRunning scenario: {name}\n{'='*60}")
            if args.n:
                try:
                    fn(args.n)
                except TypeError:
                    fn()
            else:
                fn()
    else:
        fn = scenario_map[args.scenario]
        if args.n:
            try:
                fn(args.n)
            except TypeError:
                fn()
        else:
            fn()


if __name__ == "__main__":
    main()
