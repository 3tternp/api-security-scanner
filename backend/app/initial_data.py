import logging
import sys
import os

# Add parent dir to path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal, engine
from app.models.user import User
from app.core.security import get_password_hash
from app.models import user as user_model

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init():
    db = SessionLocal()
    
    try:
        user = db.query(User).filter(User.email == "admin@example.com").first()
        if not user:
            user = User(
                email="admin@example.com",
                hashed_password=get_password_hash("admin123"),
                role="admin",
                is_active=True,
            )
            db.add(user)
            db.commit()
            logger.info("Admin user created")
        else:
            logger.info("Admin user already exists")
    except Exception as e:
        logger.error(f"Error creating initial data: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    logger.info("Creating initial data")
    # Ensure tables exist
    user_model.Base.metadata.create_all(bind=engine)
    init()
    logger.info("Initial data created")
