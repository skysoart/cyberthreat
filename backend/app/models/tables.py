"""
backend/app/models/tables.py  — SHARED (Team 1 + Team 2)
DO NOT change field names or types without both teams agreeing.
Schema matches backend-contract.md §3 exactly.
"""
import os
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, ForeignKey, Text, DateTime
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Sample Store tables (Team 1)
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    # Canonical hashed user_id format: u_<6 hex>
    user_id = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    sessions = relationship("UserSession", back_populates="user")
    orders = relationship("Order", back_populates="user")


class UserSession(Base):
    __tablename__ = "user_sessions"

    # Format: s_<8 lowercase hex>
    session_id = Column(String, primary_key=True, index=True)
    user_id_fk = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    user = relationship("User", back_populates="sessions")


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    category = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    rating = Column(Float, default=0.0)
    stock = Column(Integer, default=0)
    description = Column(String)
    gradient = Column(String)


class CartItem(Base):
    __tablename__ = "cart_items"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    product_id = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer, default=1)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    session_id = Column(String)
    total = Column(Float, nullable=False)
    status = Column(String, default="completed")
    payment_method = Column(String, default="demo")
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")


class OrderItem(Base):
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer)
    unit_price = Column(Float)

    order = relationship("Order", back_populates="items")


# ---------------------------------------------------------------------------
# Security / Platform tables
# ---------------------------------------------------------------------------

class Asset(Base):
    """
    Mirrors backend/app/data/assets.csv. Seeded on startup.
    asset_id must match Event.asset_id exactly.
    """
    __tablename__ = "assets"

    asset_id = Column(String, primary_key=True, index=True)
    criticality = Column(Float, nullable=False)   # 0.0–1.0
    software = Column(String, nullable=False)


class Event(Base):
    """
    The seam between Team 1 (writes) and Team 2 (reads + fills predictions).

    Team 1 fills everything up to and including features_json.
    Team 2 fills pred_class, pred_confidence, evidence_json,
          attack_technique, individual_priority.
    Team 1 NEVER writes a prediction field.
    Team 2 NEVER writes a raw field.
    """
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, nullable=False, default="sample-store")
    ts = Column(DateTime(timezone=True), default=_utcnow, index=True)
    session_id = Column(String, nullable=True, index=True)  # s_<8hex> or None
    source = Column(String, nullable=False, default="server")
    # SOURCES: widget | server | firewall | email_gw | edr

    src_ip = Column(String, nullable=False, index=True)
    asn = Column(Integer, nullable=True)
    country = Column(String(2), nullable=True)          # ISO-3166 alpha-2
    user_id = Column(String, nullable=True)             # u_<6hex>, hashed
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=True)
    url_path = Column(String, nullable=False)
    http_status = Column(Integer, nullable=True)

    raw_json = Column(Text, nullable=False, default="{}")    # original payload
    features_json = Column(Text, nullable=False, default="{}")  # 47-feature dict

    # Written by Team 2 only — null on insert
    pred_class = Column(String, nullable=True)
    pred_confidence = Column(Float, nullable=True)
    evidence_json = Column(Text, nullable=True)
    attack_technique = Column(String, nullable=True)        # ATT&CK ID
    individual_priority = Column(String, nullable=True)     # P1..P4

    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)   # INC-XXXX
    title = Column(String)
    status = Column(String, default="open")             # open|confirmed|false_positive|closed
    priority = Column(String)                           # P1|P2|P3|P4
    risk_score = Column(Float)
    opened_at = Column(DateTime(timezone=True), default=_utcnow)
    last_seen_at = Column(DateTime(timezone=True), default=_utcnow)
    event_count = Column(Integer, default=0)
    primary_class = Column(String)
    kill_chain_depth = Column(Integer, default=0)
    assets_affected = Column(Text)    # JSON list of asset_ids
    users_affected = Column(Integer, default=0)
    top_asn = Column(Integer, nullable=True)
    has_similar = Column(Boolean, default=False)
    risk_breakdown = Column(Text)     # JSON
    summary = Column(String)
    kill_chain = Column(Text)         # JSON
    entities = Column(Text)           # JSON
    entity_graph_svg = Column(Text)
    threat_intel = Column(Text)       # JSON
    similar_incident = Column(Text, nullable=True)   # JSON
    recommendations = Column(Text)   # JSON
    narrative = Column(Text)


class SettingsWeight(Base):
    __tablename__ = "settings_weights"

    id = Column(Integer, primary_key=True)
    model_confidence = Column(Float, default=0.20)
    asset_criticality = Column(Float, default=0.20)
    exploitability = Column(Float, default=0.20)
    blast_radius = Column(Float, default=0.15)
    kill_chain_depth = Column(Float, default=0.15)
    recency = Column(Float, default=0.10)
