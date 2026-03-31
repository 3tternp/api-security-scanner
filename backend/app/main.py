import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.api_v1.endpoints import login, users, scans, setup
from app.core.config import settings
from app.db.session import engine
from app.models import user, scan

# ── Create / migrate tables ───────────────────────────────────────────────────
user.Base.metadata.create_all(bind=engine)
scan.Base.metadata.create_all(bind=engine)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    # Hide docs in production
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
)


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
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )

# ── Run initial-data bootstrap ────────────────────────────────────────────────
try:
    from app.initial_data import init as _init
    _init()
except Exception as _e:
    logger.warning(f"Initial data bootstrap skipped: {_e}")

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(login.router,  prefix=f"{settings.API_V1_STR}",        tags=["auth"])
app.include_router(setup.router,  prefix=f"{settings.API_V1_STR}/setup",  tags=["setup"])
app.include_router(users.router,  prefix=f"{settings.API_V1_STR}/users",  tags=["users"])
app.include_router(scans.router,  prefix=f"{settings.API_V1_STR}/scans",  tags=["scans"])
