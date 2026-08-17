from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from backend.app.database import get_db
from backend.app.models import User, Session as DBSession
from backend.app.schemas import UserCreate, UserLogin, UserResponse
from backend.app.counters import ip_counter
import uuid

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post("/api/v1/auth/register", response_model=UserResponse)
@router.post("/register") # Alias for frontend
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = pwd_context.hash(user_in.password)
    user = User(name=user_in.full_name, email=user_in.email, password_hash=hashed_pw)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/api/v1/auth/login")
@router.post("/login")
def login(login_in: UserLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    src_ip = request.client.host if request.client else "127.0.0.1"
    user = db.query(User).filter(User.email == login_in.email).first()
    
    if not user or not pwd_context.verify(login_in.password, user.password_hash):
        ip_counter.record_failed_login(src_ip)
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # Create session
    session_id = str(uuid.uuid4())
    db_session = DBSession(session_id=session_id, user_id=user.id)
    db.add(db_session)
    db.commit()
    
    # Set cookie
    response.set_cookie(key="session_id", value=session_id, httponly=True)
    return {"ok": True, "session_id": session_id, "user": {"email": user.email, "name": user.name}}

@router.get("/api/v1/auth/account")
@router.get("/account/me")
def account(request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    db_session = db.query(DBSession).filter(DBSession.session_id == session_id).first()
    if not db_session:
        raise HTTPException(status_code=401, detail="Invalid session")
        
    user = db.query(User).filter(User.id == db_session.user_id).first()
    return {"email": user.email, "name": user.name}
