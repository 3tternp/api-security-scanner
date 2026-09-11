import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.api_v1.endpoints import scans
from app.core.config import settings
from app.db.session import engine
from app.db.schema_sync import ensure_columns
from app.models import scan

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    # Hide docs in production
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
)

@app.on_event("startup")
def _startup() -> None:
    try:
        scan.Base.metadata.create_all(bind=engine)
        # Reconcile columns for databases that pre-date the confidence/signals
        # fields — create_all only creates missing tables, not missing columns
        # on a table that already exists.
        json_type = "JSON" if engine.dialect.name == "postgresql" else "TEXT"
        ensure_columns(engine, "scan_results", {
            "confidence": ("VARCHAR", "medium"),
            "signals": (json_type, "[]"),
        })
    except Exception as _e:
        logger.warning(f"Startup bootstrap skipped: {_e}")


# ── Security headers middleware ───────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Cache-Control"] = "no-store"
        if "server" in response.headers:
            del response.headers["server"]
        return response


app.add_middleware(SecurityHeadersMiddleware)

# ── CORS ──────────────────────────────────────────────────────────────────────
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(o) for o in settings.BACKEND_CORS_ORIGINS],
        allow_origin_regex=settings.BACKEND_CORS_ORIGIN_REGEX,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(scans.router,  prefix=f"{settings.API_V1_STR}/scans",  tags=["scans"])
