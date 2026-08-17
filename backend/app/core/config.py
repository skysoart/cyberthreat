"""
backend/app/core/config.py  — Team 1
Settings loaded from environment / .env file.
All names and defaults match backend-contract.md §9.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Core
    DATABASE_URL: str = "sqlite:///./adamantine.db"
    API_KEY: str = "adm_live_demo"
    DEBUG: bool = True
    OFFLINE: int = 0            # 1 = block all outbound HTTP; feeds read from cache

    # ML (Team 2 reads these)
    MODEL_PATH: str = "backend/ml/artifacts/current.joblib"

    # Correlation / risk (Team 2 reads these)
    EDGE_CUT_THRESHOLD: float = 0.9
    SIMILARITY_THRESHOLD: float = 0.75
    MAX_CLUSTER_EVENTS: int = 200

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
