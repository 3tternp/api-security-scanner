"""
First-run setup endpoint.

POST /api/v1/setup  — create the initial admin user.
GET  /api/v1/setup/status — returns {"setup_required": bool}

Both endpoints are locked once an admin user exists.
"""
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import settings
from app.core.security import get_password_hash, validate_password_strength
from app.models.user import User

router = APIRouter()


class SetupRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None


def _admin_exists(db: Session) -> bool:
    return db.query(User).filter(User.role == "admin").first() is not None


@router.get("/status")
def setup_status(db: Session = Depends(get_db)) -> dict:
    """Check whether initial setup has been completed."""
    return {"setup_required": not _admin_exists(db)}


@router.post("/", status_code=201)
def initial_setup(payload: SetupRequest, db: Session = Depends(get_db)) -> Any:
    """
    Create the very first admin user.
    This endpoint is permanently disabled once any admin account exists.
    """
    if _admin_exists(db):
        raise HTTPException(
            status_code=403,
            detail="Setup has already been completed. Contact your administrator.",
        )

    errors = validate_password_strength(payload.password)
    if errors:
        raise HTTPException(
            status_code=422,
            detail=f"Password is too weak. Required: {', '.join(errors)}.",
        )

    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=409, detail="Email already registered.")

    admin = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role="admin",
        is_active=True,
    )
    db.add(admin)
    db.commit()

    return {"message": "Admin account created successfully.", "email": admin.email}
