from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api import deps
from app.core import security
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import User as UserSchema, UserCreate

router = APIRouter()


@router.get("/", response_model=List[UserSchema])
def read_users(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(deps.get_current_active_admin),
) -> Any:
    return db.query(User).offset(skip).limit(limit).all()


@router.post("/", response_model=UserSchema, status_code=201)
def create_user(
    *,
    db: Session = Depends(get_db),
    user_in: UserCreate,
    current_user: User = Depends(deps.get_current_active_admin),
) -> Any:
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=409, detail="A user with this email already exists.")

    errors = security.validate_password_strength(user_in.password)
    if errors:
        raise HTTPException(
            status_code=422,
            detail=f"Password is too weak. Required: {', '.join(errors)}.",
        )

    user = User(
        email=user_in.email,
        full_name=getattr(user_in, "full_name", None),
        hashed_password=security.get_password_hash(user_in.password),
        role=user_in.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/me", response_model=UserSchema)
def read_user_me(
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    return current_user


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_admin),
) -> None:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    db.delete(user)
    db.commit()
