from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, JSON, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    
    sessions = relationship("Session", back_populates="user")
    orders = relationship("Order", back_populates="user")

class Session(Base):
    __tablename__ = "sessions"
    session_id = Column(String, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    
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
    created_at = Column(DateTime, default=utcnow)
    
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

class Asset(Base):
    __tablename__ = "assets"
    asset_id = Column(String, primary_key=True, index=True)
    criticality = Column(Float, nullable=False)
    software = Column(String, nullable=False)

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    src_ip = Column(String, index=True)
    http_method = Column(String)
    url_path = Column(String)
    status_code = Column(Integer)
    user_id = Column(Integer, nullable=True)
    session_id = Column(String, nullable=True)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=True)
    user_agent = Column(String)
    request_size = Column(Integer, default=0)
    response_size = Column(Integer, default=0)
    referrer = Column(String, nullable=True)
    browser_telemetry = Column(JSON, nullable=True)
    
    # ML Outputs
    pred_class = Column(String, nullable=True)
    pred_confidence = Column(Float, nullable=True)
    individual_priority = Column(String, nullable=True)
    attack_technique = Column(String, nullable=True)
    evidence = Column(JSON, nullable=True)
    
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True, index=True) # e.g. INC-0187
    title = Column(String)
    status = Column(String, default="open") # open, confirmed, false_positive, closed
    priority = Column(String) # P1, P2, P3, P4
    risk_score = Column(Float)
    opened_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow)
    event_count = Column(Integer, default=0)
    primary_class = Column(String)
    kill_chain_depth = Column(Integer, default=0)
    assets_affected = Column(JSON) # list of asset_ids
    users_affected = Column(Integer, default=0)
    top_asn = Column(Integer, nullable=True)
    has_similar = Column(Boolean, default=False)
    risk_breakdown = Column(JSON)
    summary = Column(String)
    kill_chain = Column(JSON)
    entities = Column(JSON)
    entity_graph_svg = Column(String)
    threat_intel = Column(JSON)
    similar_incident = Column(JSON, nullable=True)
    recommendations = Column(JSON)
    narrative = Column(String)

class SettingsWeight(Base):
    __tablename__ = "settings_weights"
    id = Column(Integer, primary_key=True)
    model_confidence = Column(Float, default=0.20)
    asset_criticality = Column(Float, default=0.20)
    exploitability = Column(Float, default=0.20)
    blast_radius = Column(Float, default=0.15)
    kill_chain_depth = Column(Float, default=0.15)
    recency = Column(Float, default=0.10)
