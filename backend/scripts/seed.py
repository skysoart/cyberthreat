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
import csv
from datetime import datetime, timedelta, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from passlib.context import CryptContext
from backend.app.database import engine, Base, SessionLocal
from backend.app.models.tables import (
    Product, User, Asset, Event, Incident, SettingsWeight
)
# Importing registers Feedback / ModelVersion / IncidentFingerprint on the same
# Base, so create_all() below builds them too. Team 2 tables, no schema edit.
import backend.app.models.security_tables  # noqa: F401
from backend.scripts.generate_events import seed_events

# Windows consoles default to cp1252, which cannot encode the box-drawing
# and typographic characters used below. Without this, piping this script's
# output crashes with UnicodeEncodeError on a default Windows install.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

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
# Assets — read from backend/app/data/assets.csv
# ---------------------------------------------------------------------------



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
        csv_path = os.path.join(os.path.dirname(__file__), "..", "app", "data", "assets.csv")
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                db.add(Asset(
                    asset_id=row["asset_id"],
                    name=row["name"],
                    kind=row["kind"],
                    criticality=float(row["criticality"]),
                    software=row["software"],
                    cpe_product=row["cpe_product"],
                    version=row["version"]
                ))

        db.flush()  # get IDs before seeding events

        # ---- Events ----
        # 30 days of history: benign traffic plus five planted campaigns.
        # EVENTS ONLY — no incidents. correlate() has to rediscover the
        # campaigns from the events alone, which is the whole demonstration.
        print("Seeding events (30 days of history)...")
        stats = seed_events(db, Event)
        print(f"  {stats['total']:,} events  "
              f"{stats['first']:%Y-%m-%d} -> {stats['last']:%Y-%m-%d}")
        print(f"  individual priorities: {stats['priorities']}")

        db.commit()
        print("=== Database seeded successfully! ===")
        print("Next: python backend/scripts/verify_intelligence.py")

    except Exception as exc:
        db.rollback()
        print(f"[seed] ERROR: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_db()
