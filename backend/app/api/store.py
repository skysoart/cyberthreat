"""
backend/app/api/store.py  — Team 1
Sample Store backend endpoints + demo checkout.
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Response, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from backend.app.database import get_db
from backend.app.models.tables import User, UserSession, Product, Order, OrderItem
from backend.app.counters import ip_counter
from backend.app.schemas import UserCreate, UserLogin, UserResponse, CheckoutRequest
from backend.app.core.config import settings

import secrets
import hashlib

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user_id(email: str) -> str:
    """Deterministic u_<6hex> from email — matches seed.py contract."""
    digest = hashlib.sha256(email.lower().encode()).hexdigest()
    return "u_" + digest[:6]


def _make_session_id() -> str:
    """s_<8 lowercase hex>."""
    return "s_" + secrets.token_hex(4)


# ---------------------------------------------------------------------------
# Auth endpoints  (the demo-site JS POSTs here)
# ---------------------------------------------------------------------------

@router.get("/login")
def login_page():
    return FileResponse("demo-site/login.html")


@router.post("/login")
@router.post("/api/v1/auth/login")
def login(
    login_in: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    src_ip = request.client.host if request.client else "127.0.0.1"
    user = db.query(User).filter(User.email == login_in.email).first()

    if not user or not pwd_context.verify(login_in.password, user.password_hash):
        ip_counter.record_auth_fail(src_ip, email=login_in.email)
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    ip_counter.record_auth_success(src_ip)

    sid = _make_session_id()
    db_session = UserSession(session_id=sid, user_id_fk=user.id)
    db.add(db_session)
    db.commit()

    response.set_cookie(key="session_id", value=sid, httponly=True, samesite="lax")
    return {
        "ok": True,
        "session_id": sid,
        "user": {"email": user.email, "name": user.name, "user_id": user.user_id},
    }


@router.get("/register")
def register_page():
    return FileResponse("demo-site/register.html")


@router.post("/register")
@router.post("/api/v1/auth/register")
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    uid = _make_user_id(user_in.email)
    hashed_pw = pwd_context.hash(user_in.password)
    user = User(user_id=uid, name=user_in.full_name, email=user_in.email, password_hash=hashed_pw)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"ok": True, "user_id": uid}


@router.get("/account/me")
@router.get("/api/v1/auth/account")
def account(request: Request, db: Session = Depends(get_db)):
    sid = request.cookies.get("session_id")
    if not sid:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db_session = db.query(UserSession).filter(UserSession.session_id == sid).first()
    if not db_session:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = db.query(User).filter(User.id == db_session.user_id_fk).first()
    return {"email": user.email, "name": user.name, "user_id": user.user_id}


# ---------------------------------------------------------------------------
# Product catalog
# ---------------------------------------------------------------------------

@router.get("/api/v1/store/products")
def get_products(db: Session = Depends(get_db)):
    return db.query(Product).all()


@router.get("/api/v1/store/products/{product_id}")
def get_product(product_id: int, db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == product_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    return p


# ---------------------------------------------------------------------------
# Checkout
# ---------------------------------------------------------------------------

@router.post("/api/v1/store/checkout")
def checkout(order_req: CheckoutRequest, request: Request, db: Session = Depends(get_db)):
    sid = request.cookies.get("session_id")
    user = db.query(User).filter(User.email == order_req.email).first()

    # NEVER persist card_number or card_cvc
    order = Order(
        user_id=user.id if user else None,
        session_id=sid,
        total=0.0,
        status="completed",
        payment_method="demo",
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return {"ok": True, "order_id": order.id, "status": "completed"}
