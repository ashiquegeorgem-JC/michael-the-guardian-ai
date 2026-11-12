"""
Application configuration using pydantic-settings.
Reads from environment variables and .env file.
"""

from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    # App
    APP_ENV: str = "development"
    APP_SECRET_KEY: str = "dev-secret-key-change-in-production"
    PORT: int = int(os.getenv("PORT", "8000"))

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Supabase
    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""

    # Database / Persistence (Phase 5.0)
    DATABASE_URL: str = ""
    PERSISTENCE_BACKEND: str = "memory"  # "memory", "postgres", "sqlite"
    SQLITE_DB_PATH: str = "./data/michael.db"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30

    # File Upload
    MAX_UPLOAD_SIZE_MB: int = 50
    UPLOAD_DIR: str = "./uploads"

    # ML Settings
    MODEL_CONTAMINATION: float = 0.05
    TFIDF_MAX_FEATURES: int = 500

    # Threat Intelligence Settings (Phase 4.2B)
    VIRUSTOTAL_API_KEY: str = ""
    THREAT_INTEL_PROVIDER: str = "offline_mock"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()
