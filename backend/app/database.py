"""
backend/app/database.py  — Team 1
SQLAlchemy engine, session factory, and dependency injector.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.core.config import settings
from backend.app.models.tables import Base   # re-export so seed.py can use it

# Ensure the database directory exists for SQLite paths like ./adamantine.db
db_path = settings.DATABASE_URL.replace("sqlite:///", "").replace("sqlite://", "")
if db_path.startswith("./"):
    db_path = db_path[2:]
db_dir = os.path.dirname(os.path.abspath(db_path))
if db_dir:
    os.makedirs(db_dir, exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency — yields a DB session and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
