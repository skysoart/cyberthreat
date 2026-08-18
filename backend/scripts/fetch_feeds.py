"""
Adamantine — threat intelligence feed downloader.

Pulls real, free, no-account-required feeds and caches them to
backend/app/data/feeds/. Run once before the demo; never call out at request
time. If a feed is unreachable the existing cache is kept and the failure is
reported rather than crashing.

    python backend/scripts/fetch_feeds.py

Feeds:
  CISA KEV      known-exploited vulnerabilities  -> exploitability = 1.0
  FIRST EPSS    probability of exploitation      -> exploitability fallback
  Feodo Tracker botnet C2 IP blocklist           -> ip_reputation_hit
  Tor Project   exit node list                   -> is_tor_exit
"""

import json
import sys
from pathlib import Path

import httpx
import yaml

# Windows consoles default to cp1252, which cannot encode the box-drawing
# and typographic characters used below. Without this, piping this script's
# output crashes with UnicodeEncodeError on a default Windows install.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).resolve().parents[1]
FEEDS = ROOT / "app" / "data" / "feeds"
PATH_MAP = ROOT / "app" / "data" / "path_cve_map.yaml"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
TOR_URL = "https://check.torproject.org/torbulkexitlist"

TIMEOUT = 30.0
UA = {"User-Agent": "Adamantine-CTI/1.0 (academic project)"}


def cves_we_care_about() -> list[str]:
    doc = yaml.safe_load(PATH_MAP.read_text(encoding="utf-8")) or {}
    return sorted({v["cve"] for v in (doc.get("paths") or {}).values() if v.get("cve")})


def fetch(client: httpx.Client, name: str, url: str, dest: Path, parse=None) -> bool:
    try:
        r = client.get(url, headers=UA, timeout=TIMEOUT, follow_redirects=True)
        r.raise_for_status()
        payload = parse(r) if parse else r.text
        if isinstance(payload, (dict, list)):
            dest.write_text(json.dumps(payload), encoding="utf-8")
        else:
            dest.write_text(payload, encoding="utf-8")
        return True
    except Exception as exc:
        kept = " (existing cache kept)" if dest.exists() else ""
        print(f"  ! {name}: {type(exc).__name__}{kept}")
        return False


def main() -> None:
    FEEDS.mkdir(parents=True, exist_ok=True)
    ok = 0

    with httpx.Client() as client:
        print("fetching threat intelligence feeds...")

        if fetch(client, "CISA KEV", KEV_URL, FEEDS / "kev.json", lambda r: r.json()):
            n = len(json.loads((FEEDS / "kev.json").read_text())["vulnerabilities"])
            print(f"  + CISA KEV          {n:,} known-exploited CVEs")
            ok += 1

        cves = cves_we_care_about()
        def epss_parse(r):
            return {d["cve"]: float(d["epss"]) for d in r.json().get("data", [])}
        if fetch(client, "EPSS", f"{EPSS_URL}?cve={','.join(cves)}",
                 FEEDS / "epss.json", epss_parse):
            scores = json.loads((FEEDS / "epss.json").read_text())
            print(f"  + EPSS              {len(scores)}/{len(cves)} of our CVEs scored")
            for c, s in sorted(scores.items(), key=lambda kv: -kv[1])[:3]:
                print(f"      {c}  {s:.3f}")
            ok += 1

        def lines(r):
            return "\n".join(ln for ln in r.text.splitlines()
                             if ln.strip() and not ln.startswith("#"))
        if fetch(client, "Feodo Tracker", FEODO_URL, FEEDS / "feodo_ips.txt", lines):
            n = len((FEEDS / "feodo_ips.txt").read_text().splitlines())
            print(f"  + Feodo Tracker     {n:,} botnet C2 IPs")
            ok += 1
        if fetch(client, "Tor exit list", TOR_URL, FEEDS / "tor_exits.txt", lines):
            n = len((FEEDS / "tor_exits.txt").read_text().splitlines())
            print(f"  + Tor exit nodes    {n:,} addresses")
            ok += 1

    print(f"\n{ok}/4 feeds cached to {FEEDS}")
    if ok < 4:
        print("partial cache is fine — enrichment degrades gracefully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
