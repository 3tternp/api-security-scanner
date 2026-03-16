import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.api_v1.endpoints import login, users, scans
from app.core.config import settings
from app.db.session import engine
from app.models import user, scan

# Create tables
user.Base.metadata.create_all(bind=engine)
scan.Base.metadata.create_all(bind=engine)

# Lightweight migration: ensure new columns exist in existing SQLite databases
try:
    from sqlalchemy import text
    with engine.connect() as _conn:
        for _col, _def in [("status", "VARCHAR DEFAULT 'Open'"), ("cvss_score", "VARCHAR DEFAULT ''")]:
            try:
                _conn.execute(text(f"ALTER TABLE scan_results ADD COLUMN {_col} {_def}"))
                _conn.commit()
                logger.info(f"Migration: added column scan_results.{_col}")
            except Exception:
                pass  # Column already exists
except Exception as _e:
    logger.warning(f"Migration step skipped: {_e}")

app = FastAPI(title=settings.PROJECT_NAME, openapi_url=f"{settings.API_V1_STR}/openapi.json")

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(login.router, prefix=f"{settings.API_V1_STR}", tags=["login"])
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["scans"])
