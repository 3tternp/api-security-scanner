from sqlalchemy.orm import Session
from app.db.session import SessionLocal, engine
from app.models.user import User
from app.core.security import get_password_hash

def init_db(db: Session):
    user = db.query(User).filter(User.email == "admin@example.com").first()
    if not user:
        user = User(
            email="admin@example.com",
            hashed_password=get_password_hash("admin123"),
            is_active=True,
            role="admin",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print("Superuser created")
    else:
        print("Superuser already exists")

if __name__ == "__main__":
    db = SessionLocal()
    init_db(db)
