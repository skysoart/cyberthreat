"""
backend/scripts/seed.py  — SHARED (Team 1 + Team 2)
DO NOT change IDs, emails, or user_id values — these are the demo contract.

Run:
    python backend/scripts/seed.py
"""
import sys
import os
import json
import hashlib
from datetime import datetime, timedelta, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from passlib.context import CryptContext
from backend.app.database import engine, Base, SessionLocal
from backend.app.models.tables import (
    Product, User, Asset, Event, Incident, SettingsWeight
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# Helpers — must match contract conventions exactly
# ---------------------------------------------------------------------------

def _user_id(email: str) -> str:
    """Deterministic u_<6hex> from email per contract §8."""
    return "u_" + hashlib.sha256(email.lower().encode()).hexdigest()[:6]


def _j(obj) -> str:
    return json.dumps(obj)


# ---------------------------------------------------------------------------
# Demo users — fixed user_ids per contract §7
# ---------------------------------------------------------------------------
DEMO_USERS = [
    {"email": "alice@samplestore.test", "name": "Alice Demo",  "user_id": "u_8f2a1c"},
    {"email": "bob@samplestore.test",   "name": "Bob Demo",    "user_id": "u_3b71ef"},
    {"email": "carol@samplestore.test", "name": "Carol Demo",  "user_id": "u_c04d92"},
]

# ---------------------------------------------------------------------------
# Assets — matches api-contract.md §36
# ---------------------------------------------------------------------------
ASSETS = [
    ("payments-api",   1.00, "Stripe SDK"),
    ("orders-db",      0.95, "PostgreSQL 14"),
    ("auth-service",   0.90, "Node 20"),
    ("admin-portal",   0.85, "React"),
    ("checkout-web",   0.80, "Next.js"),
    ("catalogue-api",  0.50, "Spring Boot 2.5"),
    ("search-service", 0.40, "Elasticsearch"),
    ("cdn-edge",       0.30, "nginx 1.18"),
    ("blog-cms",       0.20, "WordPress 6.4"),
    ("metrics-agent",  0.20, "Spring Boot Actuator"),
]


def seed_db():
    print("=== Adamantine seed ===")
    print("Dropping and recreating all tables...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # ---- Settings weights ----
        print("Seeding settings_weights...")
        db.add(SettingsWeight())

        # ---- Products ----
        print("Seeding products...")
        products = [
            Product(name="Wireless Bluetooth Headphones", category="ELECTRONICS", price=2499.0, stock=45,
                    description="High-fidelity wireless over-ear headphones with active noise cancellation.",
                    gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
            Product(name="Mechanical Gaming Keyboard", category="ELECTRONICS", price=3299.0, stock=30,
                    description="RGB tactile mechanical keyboard with custom switches.",
                    gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
            Product(name="Stainless Steel Water Bottle", category="HOME & KITCHEN", price=799.0, stock=120,
                    description="Double-wall vacuum insulated flask keeping drinks cold.",
                    gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
            Product(name="Smart LED Desk Lamp", category="HOME & OFFICE", price=1099.0, stock=60,
                    description="Dimmable LED desk lamp with touch control.",
                    gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
            Product(name="Adjustable Aluminum Laptop Stand", category="OFFICE", price=1299.0, stock=70,
                    description="Ergonomic foldable aluminum riser supporting laptops up to 17 inches.",
                    gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
        ]
        db.add_all(products)

        # ---- Users ----
        print("Seeding users (password: demo1234)...")
        for u in DEMO_USERS:
            db.add(User(
                user_id=u["user_id"],
                name=u["name"],
                email=u["email"],
                password_hash=pwd_context.hash("demo1234"),
            ))

        # ---- Assets ----
        print("Seeding assets...")
        for asset_id, crit, sw in ASSETS:
            db.add(Asset(asset_id=asset_id, criticality=crit, software=sw))

        db.flush()  # get IDs before seeding incidents/events

        # ---- Sample incident INC-0187 ----
        print("Seeding incidents...")
        now = datetime.now(timezone.utc)

        risk_breakdown = {
            "model_confidence":  {"raw": 0.94, "weight": 0.20, "points": 18.8},
            "asset_criticality": {"raw": 0.90, "weight": 0.20, "points": 18.0},
            "exploitability":    {"raw": 1.00, "weight": 0.20, "points": 20.0},
            "blast_radius":      {"raw": 0.59, "weight": 0.15, "points": 8.8},
            "kill_chain_depth":  {"raw": 0.50, "weight": 0.15, "points": 7.5},
            "recency":           {"raw": 0.96, "weight": 0.10, "points": 9.6},
        }
        kill_chain = [
            {"tactic": "Reconnaissance",    "technique_id": "T1595.002",
             "technique": "Vulnerability Scanning",
             "first_seen": "2026-08-16T09:14:22Z", "event_count": 5},
            {"tactic": "Credential Access", "technique_id": "T1110.004",
             "technique": "Credential Stuffing",
             "first_seen": "2026-08-16T09:51:08Z", "event_count": 3},
            {"tactic": "Initial Access",    "technique_id": "T1078",
             "technique": "Valid Accounts",
             "first_seen": "2026-08-16T10:02:41Z", "event_count": 1},
        ]
        entities = [
            {"kind": "ip",     "value": "185.220.101.34", "event_count": 6, "reputation_hit": False},
            {"kind": "ip",     "value": "185.220.101.61", "event_count": 3, "reputation_hit": False},
            {"kind": "subnet", "value": "185.220.101.0/24", "event_count": 9},
            {"kind": "asn",    "value": "14061",           "event_count": 9},
            {"kind": "user",   "value": "u_8f2a1c",        "event_count": 3},
            {"kind": "asset",  "value": "metrics-agent",   "event_count": 5},
            {"kind": "asset",  "value": "auth-service",    "event_count": 4},
            {"kind": "cve",    "value": "CVE-2022-22965",  "event_count": 2},
        ]
        threat_intel = [
            {"kind": "cve", "value": "CVE-2022-22965", "name": "Spring4Shell",
             "in_kev": True, "kev_added": "2022-04-04", "epss": 0.974,
             "matched_asset": "metrics-agent", "matched_software": "Spring Boot Actuator",
             "triggered_by_path": "/actuator/env", "source": "CISA KEV"},
        ]
        recommendations = {
            "containment": [
                {"id": "PB-C-011", "action": "Block ASN 14061 at WAF, 30-minute TTL",
                 "owner": "Network Ops", "eta_min": 5,
                 "rollback": "Remove ASN rule; verify legitimate traffic restored"},
                {"id": "PB-C-024", "action": "Force password reset for 3 targeted accounts",
                 "owner": "IAM", "eta_min": 10, "rollback": "N/A — safe-forward"},
            ],
            "eradication": [
                {"id": "PB-E-007", "action": "Revoke all active sessions for affected users",
                 "owner": "IAM", "eta_min": 2, "rollback": "N/A"},
            ],
            "recovery": [
                {"id": "PB-R-003",
                 "action": "Patch metrics-agent to Spring Boot 2.6.6+ (CVE-2022-22965)",
                 "owner": "Platform", "eta_min": 60, "rollback": "Redeploy previous image tag"},
            ],
            "hunt": [
                {"id": "PB-H-002",
                 "action": "Search all authentication events from ASN 14061, last 30 days",
                 "owner": "SOC", "eta_min": 15,
                 "query": "SELECT * FROM events WHERE asn=14061 AND ts > now()-interval '30 days'"},
            ],
        }
        similar_incident = {
            "id": "INC-0142", "similarity": 0.87,
            "opened_at": "2026-07-23T02:11:00Z", "days_ago": 24,
            "verdict": "confirmed_malicious",
            "shared": ["ASN 14061", "T1595.002", "T1110.004", "low_and_slow timing"],
        }

        inc = Incident(
            id="INC-0187",
            title="Multi-stage reconnaissance and credential attack",
            status="open",
            priority="P1",
            risk_score=82.7,
            opened_at=now - timedelta(minutes=48),
            last_seen_at=now,
            event_count=9,
            primary_class="slow_recon",
            kill_chain_depth=3,
            assets_affected=_j(["metrics-agent", "auth-service"]),
            users_affected=3,
            top_asn=14061,
            has_similar=True,
            risk_breakdown=_j(risk_breakdown),
            summary=(
                "Nine events over 48 minutes from ASN 14061 (DigitalOcean). "
                "Individually all scored P4. Correlated, they form a reconnaissance "
                "campaign that identified a Spring Boot Actuator endpoint on "
                "metrics-agent, followed by credential stuffing against auth-service "
                "and one successful authentication."
            ),
            kill_chain=_j(kill_chain),
            entities=_j(entities),
            entity_graph_svg=(
                '<svg viewBox="0 0 640 360" xmlns="http://www.w3.org/2000/svg">'
                '<circle cx="100" cy="180" r="30" fill="#dc2626"/>'
                '<text x="80" y="225" font-size="12" fill="#fff">185.220.101.34</text>'
                '<circle cx="320" cy="100" r="25" fill="#ea580c"/>'
                '<text x="295" y="145" font-size="12" fill="#fff">metrics-agent</text>'
                '<circle cx="320" cy="260" r="25" fill="#ea580c"/>'
                '<text x="300" y="305" font-size="12" fill="#fff">auth-service</text>'
                '<line x1="130" y1="180" x2="295" y2="100" stroke="#94a3b8" stroke-width="2"/>'
                '<line x1="130" y1="180" x2="295" y2="260" stroke="#94a3b8" stroke-width="2"/>'
                '</svg>'
            ),
            threat_intel=_j(threat_intel),
            similar_incident=_j(similar_incident),
            recommendations=_j(recommendations),
            narrative=(
                "This incident began as low-volume reconnaissance against the Spring Boot "
                "Actuator endpoint. The attacker used 6 IPs in the same /24, pacing "
                "requests ~5 minutes apart to evade rate limits. After discovering the "
                "endpoint, credential stuffing against auth-service followed, resulting "
                "in one successful login for user u_8f2a1c."
            ),
        )
        db.add(inc)
        db.flush()

        # ---- Sample events linked to INC-0187 ----
        print("Seeding events...")
        sample_events = [
            Event(
                tenant_id="sample-store",
                ts=now - timedelta(minutes=48),
                session_id=None,
                source="server",
                src_ip="185.220.101.34",
                asn=14061,
                country="NL",
                user_id=None,
                asset_id="cdn-edge",
                url_path="/.env",
                http_status=404,
                raw_json=_j({"method": "GET", "path": "/.env", "user_agent": "curl/7.88"}),
                features_json=_j({
                    "req_rate_10s": 1, "req_rate_60s": 1, "req_rate_300s": 1,
                    "sensitive_path_hit": 1, "ua_known_tool": 1,
                    "browser_telemetry_present": 0,
                }),
                pred_class="slow_recon",
                pred_confidence=0.71,
                individual_priority="P4",
                attack_technique="T1595.002",
                evidence_json=_j([
                    {"feature": "browser_telemetry_present", "value": 0,
                     "baseline": "1", "deviation": "absent",
                     "note": "no JavaScript executed — request did not come from a browser"},
                    {"feature": "sensitive_path_hit", "value": 1,
                     "baseline": "0", "deviation": "present",
                     "note": "requested a credentials file path"},
                    {"feature": "asn_is_hosting", "value": 1,
                     "baseline": "0", "deviation": "present",
                     "note": "datacentre origin, not residential"},
                    {"feature": "interarrival_std_ms", "value": 3.1,
                     "baseline": "800–4000", "deviation": "258× below baseline",
                     "note": "machine-uniform request timing"},
                ]),
                incident_id="INC-0187",
            ),
            Event(
                tenant_id="sample-store",
                ts=now - timedelta(minutes=38),
                session_id=None,
                source="server",
                src_ip="185.220.101.34",
                asn=14061,
                country="NL",
                user_id=None,
                asset_id="metrics-agent",
                url_path="/actuator/env",
                http_status=200,
                raw_json=_j({"method": "GET", "path": "/actuator/env", "user_agent": "curl/7.88"}),
                features_json=_j({"sensitive_path_hit": 1, "browser_telemetry_present": 0}),
                pred_class="slow_recon",
                pred_confidence=0.83,
                individual_priority="P3",
                attack_technique="T1595.002",
                evidence_json=_j([]),
                incident_id="INC-0187",
            ),
        ]
        db.add_all(sample_events)

        db.commit()
        print("=== Database seeded successfully! ===")

    except Exception as exc:
        db.rollback()
        print(f"[seed] ERROR: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_db()
