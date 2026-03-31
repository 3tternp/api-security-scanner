import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Union

from jose import jwt
from passlib.context import CryptContext
from passlib.exc import UnknownHashError

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Password strength requirements
_PASSWORD_RULES = [
    (r"[A-Z]", "at least one uppercase letter"),
    (r"[a-z]", "at least one lowercase letter"),
    (r"\d",    "at least one digit"),
    (r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", "at least one special character"),
]


def validate_password_strength(password: str) -> list[str]:
    """Return a list of unmet password requirements (empty = strong enough)."""
    errors: list[str] = []
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        errors.append(f"at least {settings.MIN_PASSWORD_LENGTH} characters")
    for pattern, message in _PASSWORD_RULES:
        if not re.search(pattern, password):
            errors.append(message)
    return errors


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except UnknownHashError:
        return False


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"exp": expire, "sub": str(subject), "iat": datetime.now(timezone.utc)}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
