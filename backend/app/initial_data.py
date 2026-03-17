"""
Bootstrap script — creates the initial admin user on first boot.

Reads credentials from environment variables:
  ADMIN_EMAIL     — required to auto-create the admin
  ADMIN_PASSWORD  — required to auto-create the admin

If neither is set the app starts normally; use the /api/v1/setup endpoint
(or the Setup page in the UI) to create the first admin interactively.
"""
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal, engine
from app.models import user as user_model, scan as scan_model
from app.models.user import User
from app.core.security import get_password_hash, validate_password_strength
from app.core.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init() -> None:
    db = SessionLocal()
    try:
        admin_exists = db.query(User).filter(User.role == "admin").first()
        if admin_exists:
            logger.info("Admin user already exists — skipping initial setup.")
            return

        admin_email = settings.ADMIN_EMAIL
        admin_password = settings.ADMIN_PASSWORD

        if not admin_email or not admin_password:
            logger.warning(
                "No admin found and ADMIN_EMAIL / ADMIN_PASSWORD are not set. "
                "Visit /api/v1/setup in the UI to create the first admin account."
            )
            return

        errors = validate_password_strength(admin_password)
        if errors:
            logger.error(
                f"ADMIN_PASSWORD does not meet requirements: {', '.join(errors)}. "
                "Fix the env var and restart."
            )
            sys.exit(1)

        admin = User(
            email=admin_email,
            hashed_password=get_password_hash(admin_password),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        logger.info(f"Initial admin account created: {admin_email}")
    except Exception as exc:
        logger.error(f"Failed to create initial data: {exc}", exc_info=True)
    finally:
        db.close()


if __name__ == "__main__":
    logger.info("Running initial data setup...")
    user_model.Base.metadata.create_all(bind=engine)
    scan_model.Base.metadata.create_all(bind=engine)
    init()
    logger.info("Done.")
