import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ADAMANTINE_DEMO_KEY: str = "adm_live_demo"
    DATABASE_URL: str = "sqlite:///./backend/data/adamantine.db"
    DEBUG: bool = True

    class Config:
        env_file = ".env"

settings = Settings()
