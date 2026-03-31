from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "API Security Scanner"
    API_V1_STR: str = "/api/v1"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = "production"  # development | production

    # ── JWT ──────────────────────────────────────────────────────────────────
    # Must be set via environment variable or .env file. No default in production.
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # ── CORS ─────────────────────────────────────────────────────────────────
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "https://api-security-scanner-ild7yx8ci-3tternps-projects.vercel.app",
    ]
    BACKEND_CORS_ORIGIN_REGEX: Optional[str] = r"^https://.*-3tternps-projects\.vercel\.app$"

    # ── PostgreSQL ────────────────────────────────────────────────────────────
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "apiscanner"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ── Initial admin (first-run only) ────────────────────────────────────────
    # Set these env vars to auto-create the admin on first boot.
    # Unset them after the first successful start for security.
    ADMIN_EMAIL: Optional[str] = None
    ADMIN_PASSWORD: Optional[str] = None

    # ── Security hardening ────────────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS: int = 5          # lock after N failures
    LOCKOUT_MINUTES: int = 15            # lock duration
    MIN_PASSWORD_LENGTH: int = 12


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
