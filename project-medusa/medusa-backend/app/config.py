"""
Configuration management for MEDUSA Backend
"""

import os
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Environment
    environment: str = os.getenv("ENVIRONMENT", "development")
    
    # API Configuration
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    
    # CORS Configuration
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://frontend:3000",
        os.getenv("FRONTEND_URL", "http://localhost:3000")
    ]
    
    # Gemini API
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-pro")
    
    # Database Configuration (PostgreSQL)
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql://medusa:medusa_password@postgres:5432/medusa_db"
    )
    
    # Redis Configuration
    redis_url: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    
    # Docker Configuration
    docker_host: str = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    
    # Session Configuration
    session_timeout: int = int(os.getenv("SESSION_TIMEOUT", "3600"))  # 1 hour
    max_sessions: int = int(os.getenv("MAX_SESSIONS", "10"))
    
    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()

