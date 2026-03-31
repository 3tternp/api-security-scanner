from datetime import timedelta, datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.schemas.token import Token

router = APIRouter()

def _effective_max_login_attempts() -> int:
    env = (settings.ENVIRONMENT or "").lower()
    if env == "development":
        return max(settings.MAX_LOGIN_ATTEMPTS, 20)
    return settings.MAX_LOGIN_ATTEMPTS


def _effective_lockout_minutes() -> int:
    env = (settings.ENVIRONMENT or "").lower()
    if env == "development":
        return max(0, min(settings.LOCKOUT_MINUTES, 1))
    return settings.LOCKOUT_MINUTES


def _check_lockout(user: User) -> None:
    """Raise 429 if the account is still locked."""
    if _effective_lockout_minutes() <= 0:
        return
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        remaining = int((user.locked_until - datetime.now(timezone.utc)).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Account locked due to too many failed attempts. Try again in {remaining} minute(s).",
        )


def _record_failed_attempt(db: Session, user: User) -> None:
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    max_attempts = _effective_max_login_attempts()
    lockout_minutes = _effective_lockout_minutes()
    if max_attempts > 0 and lockout_minutes > 0 and user.failed_login_attempts >= max_attempts:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
    db.add(user)
    db.commit()


def _reset_failed_attempts(db: Session, user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    db.add(user)
    db.commit()


@router.post("/login/access-token", response_model=Token)
def login_access_token(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
    user = db.query(User).filter(User.email == form_data.username).first()

    # Use a generic error to avoid user-enumeration
    _bad_credentials = HTTPException(status_code=401, detail="Incorrect email or password")

    if not user:
        raise _bad_credentials

    _check_lockout(user)

    if not security.verify_password(form_data.password, user.hashed_password):
        _record_failed_attempt(db, user)
        raise _bad_credentials

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled. Contact your administrator.")

    _reset_failed_attempts(db, user)

    access_token = security.create_access_token(
        subject=user.email,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}
