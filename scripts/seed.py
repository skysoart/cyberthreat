import sys
import os
from datetime import datetime, timedelta, timezone

# Add parent directory to path so we can import backend
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app.database import engine, Base, SessionLocal
from backend.app.models import Product, User, Asset, Event, Incident, SettingsWeight
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def seed_db():
    print("Dropping and recreating tables...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    
    try:
        # Seed SettingsWeight
        print("Seeding settings...")
        settings = SettingsWeight()
        db.add(settings)

        # Seed Products
        print("Seeding products...")
        products = [
            Product(name="Wireless Bluetooth Headphones", category="ELECTRONICS", price=2499.0, stock=45, description="High-fidelity wireless over-ear headphones with active noise cancellation.", gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
            Product(name="Mechanical Gaming Keyboard", category="ELECTRONICS", price=3299.0, stock=30, description="RGB tactile mechanical keyboard with custom switches.", gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
            Product(name="Stainless Steel Water Bottle", category="HOME & KITCHEN", price=799.0, stock=120, description="Double-wall vacuum insulated flask keeping drinks cold.", gradient="linear-gradient(135deg, #f5f5f7, #e5e5ea)"),
        ]
        db.add_all(products)
        
        # Seed Users
        print("Seeding users...")
        users = [
            User(name="Demo User 1", email="alice@samplestore.test", password_hash=pwd_context.hash("demo1234")),
            User(name="Demo User 2", email="bob@samplestore.test", password_hash=pwd_context.hash("demo1234")),
            User(name="Demo User 3", email="carol@samplestore.test", password_hash=pwd_context.hash("demo1234"))
        ]
        db.add_all(users)
        
        # Seed Assets
        print("Seeding assets...")
        assets = [
            Asset(asset_id="payments-api", criticality=1.00, software="Stripe SDK"),
            Asset(asset_id="orders-db", criticality=0.95, software="PostgreSQL 14"),
            Asset(asset_id="auth-service", criticality=0.90, software="Node 20"),
            Asset(asset_id="admin-portal", criticality=0.85, software="React"),
            Asset(asset_id="checkout-web", criticality=0.80, software="Next.js"),
            Asset(asset_id="catalogue-api", criticality=0.50, software="Spring Boot 2.5"),
            Asset(asset_id="metrics-agent", criticality=0.20, software="Spring Boot Actuator"),
            Asset(asset_id="cdn-edge", criticality=0.30, software="nginx 1.18")
        ]
        db.add_all(assets)

        # Seed Incidents
        print("Seeding incidents...")
        now = datetime.now(timezone.utc)
        
        inc1 = Incident(
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
            assets_affected=["metrics-agent", "auth-service"],
            users_affected=3,
            top_asn=14061,
            has_similar=True,
            risk_breakdown={
                "model_confidence":  { "raw": 0.94, "weight": 0.20, "points": 18.8 },
                "asset_criticality": { "raw": 0.90, "weight": 0.20, "points": 18.0 },
                "exploitability":    { "raw": 1.00, "weight": 0.20, "points": 20.0 },
                "blast_radius":      { "raw": 0.59, "weight": 0.15, "points": 8.8 },
                "kill_chain_depth":  { "raw": 0.50, "weight": 0.15, "points": 7.5 },
                "recency":           { "raw": 0.96, "weight": 0.10, "points": 9.6 }
            },
            summary="Nine events over 48 minutes from ASN 14061 (DigitalOcean). Individually all scored P4. Correlated, they form a reconnaissance campaign...",
            kill_chain=[
                { "tactic": "Reconnaissance", "technique_id": "T1595.002", "technique": "Vulnerability Scanning", "first_seen": "2026-08-16T09:14:22Z", "event_count": 5 }
            ],
            entities=[
                { "kind": "ip", "value": "185.220.101.34", "event_count": 6, "reputation_hit": False }
            ],
            entity_graph_svg="<svg viewBox=\"0 0 640 360\" xmlns=\"http://www.w3.org/2000/svg\"><text x=\"20\" y=\"20\">Graph</text></svg>",
            threat_intel=[],
            recommendations={},
            narrative="This incident began as low-volume reconnaissance..."
        )
        db.add(inc1)

        # Seed Events
        print("Seeding events...")
        e1 = Event(
            timestamp=now - timedelta(minutes=48),
            src_ip="185.220.101.34",
            url_path="/.env",
            status_code=404,
            asset_id="cdn-edge",
            pred_class="slow_recon",
            pred_confidence=0.71,
            individual_priority="P4",
            attack_technique="T1595.002",
            evidence=[
                { "feature": "browser_telemetry_present", "value": 0, "baseline": "1", "deviation": "absent", "note": "no JavaScript executed" }
            ],
            incident_id="INC-0187"
        )
        db.add(e1)

        db.commit()
        print("Database seeded successfully!")
    except Exception as e:
        print(f"Error seeding DB: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_db()
