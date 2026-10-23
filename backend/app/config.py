import os
import secrets
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Powered Insider Threat Behavioral Intelligence System"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    APP_ENV: str = os.getenv("APP_ENV", "production")
    
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Database: Default to local SQLite for instant zero-config running, PostgreSQL when DATABASE_URL is set
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./insider_threat.db")
    
    # CORS — no wildcard (security fix)
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    
    # Rate limiting
    RATE_LIMIT_LOGIN: str = os.getenv("RATE_LIMIT_LOGIN", "5/minute")
    RATE_LIMIT_API: str = os.getenv("RATE_LIMIT_API", "60/minute")
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR: str = os.path.join(os.path.dirname(BASE_DIR), "data")
    MODEL_DIR: str = os.path.join(os.path.dirname(BASE_DIR), "models")
    
    class Config:
        case_sensitive = True

settings = Settings()
for frontend_url in (os.getenv("FRONTEND_URL"), os.getenv("VERCEL_URL")):
    if frontend_url:
        origin = frontend_url.strip().rstrip("/")
        if origin and "://" not in origin:
            origin = f"https://{origin}"
        if origin and origin not in settings.CORS_ORIGINS:
            settings.CORS_ORIGINS.append(origin)

if not settings.SECRET_KEY:
    if settings.APP_ENV.lower() in {"dev", "development", "demo"}:
        settings.SECRET_KEY = secrets.token_urlsafe(32)
    else:
        raise RuntimeError("SECRET_KEY must be configured outside development/demo mode")

os.makedirs(settings.DATA_DIR, exist_ok=True)
os.makedirs(settings.MODEL_DIR, exist_ok=True)
