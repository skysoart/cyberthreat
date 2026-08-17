"""
Adamantine — enrichment.

Turns a bare event into a scored one by answering three questions:

  1. Did this probe map to a real vulnerability we actually run?
  2. Is the source IP known-bad?
  3. How much do we care about the asset it touched?

Question 1 is what separates "someone poked at us" from "someone probed for
Spring4Shell on the one host that runs Spring Boot". It is the single largest
contributor to exploitability, and it is the reason the demo campaign escalates.

All feed data is read from backend/app/data/feeds/ — nothing calls out at
request time. Run scripts/fetch_feeds.py to populate the cache.
"""

from __future__ import annotations

import csv
import ipaddress
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml

DATA = Path(__file__).resolve().parents[1] / "data"
FEEDS = DATA / "feeds"

# ASNs that are datacentres rather than consumer ISPs. A residential user does
# not browse from AWS; a bot very often does.
HOSTING_ASNS = {
    14061, 16509, 14618, 8075, 15169, 9009, 24940, 63949, 20473,
    16276, 51167, 45102, 132203, 135377, 396982, 19551, 13335,
}

HIGH_RISK_COUNTRIES = {"RU", "KP", "IR", "BY", "SY"}


@dataclass
class AssetInfo:
    asset_id: str
    name: str
    kind: str
    criticality: float
    software: str
    cpe_product: str
    version: str


@dataclass
class Enrichment:
    """Everything enrichment knows about one event."""
    asset_criticality: float = 0.1
    asset_name: Optional[str] = None
    exploitability: float = 0.0
    sensitive_path: bool = False
    cve: Optional[str] = None
    cve_name: Optional[str] = None
    in_kev: bool = False
    kev_added: Optional[str] = None
    epss: Optional[float] = None
    matched_asset: Optional[str] = None
    matched_software: Optional[str] = None
    probe_succeeded: bool = False
    ip_reputation_hit: bool = False
    ip_reputation_source: Optional[str] = None
    is_tor_exit: bool = False
    asn_is_hosting: bool = False
    country_risk: float = 0.1
    threat_intel: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


# --------------------------------------------------------------- loaders

@lru_cache(maxsize=1)
def load_assets() -> dict[str, AssetInfo]:
    out: dict[str, AssetInfo] = {}
    path = DATA / "assets.csv"
    if not path.exists():
        return out
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out[row["asset_id"]] = AssetInfo(
                asset_id=row["asset_id"], name=row["name"], kind=row["kind"],
                criticality=float(row["criticality"]), software=row["software"],
                cpe_product=row.get("cpe_product", ""), version=row.get("version", ""),
            )
    return out


@lru_cache(maxsize=1)
def load_path_map() -> tuple[dict[str, dict], set[str]]:
    path = DATA / "path_cve_map.yaml"
    if not path.exists():
        return {}, set()
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return doc.get("paths", {}) or {}, set(doc.get("sensitive_no_cve", []) or [])


@lru_cache(maxsize=1)
def load_kev() -> dict[str, dict]:
    """CISA Known Exploited Vulnerabilities. Real feed, cached to disk."""
    path = FEEDS / "kev.json"
    if not path.exists():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {v["cveID"]: v for v in doc.get("vulnerabilities", [])}


@lru_cache(maxsize=1)
def load_epss() -> dict[str, float]:
    path = FEEDS / "epss.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_ip_blocklists() -> tuple[set[str], set[str]]:
    """(botnet C2 IPs from Feodo, Tor exit nodes)."""
    def read(name: str) -> set[str]:
        p = FEEDS / name
        if not p.exists():
            return set()
        return {
            ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")
        }
    return read("feodo_ips.txt"), read("tor_exits.txt")


def feeds_status() -> dict[str, Any]:
    """Shown on the dashboard so it is obvious whether real intel is loaded."""
    kev, epss = load_kev(), load_epss()
    feodo, tor = load_ip_blocklists()
    return {
        "kev_entries": len(kev),
        "epss_entries": len(epss),
        "feodo_ips": len(feodo),
        "tor_exits": len(tor),
        "cached": FEEDS.exists(),
        "note": ("run scripts/fetch_feeds.py to populate"
                 if not kev else "loaded from local cache"),
    }


# --------------------------------------------------------------- enrichment

def _subnet24(ip: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def enrich(url_path: str, http_status: int, asset_id: Optional[str],
           src_ip: str, asn: Optional[int], country: Optional[str]) -> Enrichment:
    """
    Enrich one event. Pure function of its inputs plus the cached feeds, so it
    is trivially testable and produces identical results offline.
    """
    e = Enrichment()
    assets = load_assets()
    paths, sensitive = load_path_map()

    # --- asset criticality
    if asset_id and asset_id in assets:
        e.asset_criticality = assets[asset_id].criticality
        e.asset_name = assets[asset_id].name

    # --- network origin
    e.asn_is_hosting = bool(asn and asn in HOSTING_ASNS)
    e.country_risk = 0.8 if (country in HIGH_RISK_COUNTRIES) else 0.1

    feodo, tor = load_ip_blocklists()
    if src_ip in feodo:
        e.ip_reputation_hit = True
        e.ip_reputation_source = "Feodo Tracker"
    elif src_ip in tor:
        e.is_tor_exit = True
        e.ip_reputation_hit = True
        e.ip_reputation_source = "Tor exit list"

    # --- path -> CVE -> KEV/EPSS -> our inventory
    base = url_path.split("?")[0]
    if base in sensitive or any(base.startswith(s) for s in sensitive):
        e.sensitive_path = True

    entry = paths.get(base) or next(
        (v for k, v in paths.items() if base.startswith(k)), None)

    if entry:
        e.sensitive_path = True
        cve = entry.get("cve")
        e.probe_succeeded = http_status == entry.get("hit_status", 200)
        if cve:
            e.cve = cve
            e.cve_name = entry.get("name")
            kev, epss = load_kev(), load_epss()
            e.in_kev = cve in kev
            e.kev_added = kev.get(cve, {}).get("dateAdded")
            e.epss = epss.get(cve)

            # Only claim exploitability if we ACTUALLY run the affected product.
            # A Spring4Shell probe against a PHP host is noise, not a finding.
            target = entry.get("asset")
            info = assets.get(target) if target else None
            product_match = bool(info and info.cpe_product == entry.get("product"))

            if product_match:
                e.matched_asset = info.asset_id
                e.matched_software = info.software
                if e.probe_succeeded:
                    # Confirmed exposure of a vulnerable component we run.
                    e.exploitability = 1.0 if e.in_kev else max(e.epss or 0.5, 0.5)
                else:
                    # Probed for it, did not land. Still meaningful, less severe.
                    e.exploitability = 0.45 if e.in_kev else (e.epss or 0.2) * 0.5
            else:
                e.exploitability = 0.15   # probing for something we do not run

            e.threat_intel.append({
                "kind": "cve", "value": cve, "name": e.cve_name,
                "in_kev": e.in_kev, "kev_added": e.kev_added, "epss": e.epss,
                "matched_asset": e.matched_asset,
                "matched_software": e.matched_software,
                "triggered_by_path": base,
                "source": "CISA KEV" if e.in_kev else "NVD / EPSS",
            })
    elif e.sensitive_path:
        e.exploitability = 0.10   # credential-file probing, no specific CVE

    if e.ip_reputation_hit:
        e.exploitability = min(1.0, e.exploitability + 0.30)
        e.threat_intel.append({
            "kind": "ip_reputation", "value": src_ip,
            "name": f"Listed on {e.ip_reputation_source}",
            "in_kev": False, "epss": None,
            "matched_asset": None, "matched_software": None,
            "triggered_by_path": None, "source": e.ip_reputation_source,
        })

    return e


def entities_for(src_ip: str, asn: Optional[int], user_id: Optional[str],
                 asset_id: Optional[str], session_id: Optional[str],
                 cve: Optional[str], ua_hash: Optional[str] = None
                 ) -> list[tuple[str, str]]:
    """(kind, value) pairs this event contributes to the correlation graph."""
    out: list[tuple[str, str]] = [("ip", src_ip)]
    sn = _subnet24(src_ip)
    if sn:
        out.append(("subnet", sn))
    if asn:
        out.append(("asn", str(asn)))
    if user_id:
        out.append(("user", user_id))
    if asset_id:
        out.append(("asset", asset_id))
    if session_id:
        out.append(("session", session_id))
    if cve:
        out.append(("cve", cve))
    if ua_hash:
        out.append(("ua_hash", ua_hash))
    return out
