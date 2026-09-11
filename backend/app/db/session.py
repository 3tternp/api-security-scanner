import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool, StaticPool

from app.core.config import settings

_database_url = settings.DATABASE_URL
_is_sqlite = _database_url.startswith("sqlite")
_on_vercel = os.getenv("VERCEL") == "1"

_engine_kwargs: dict = {}
if _is_sqlite:
    _engine_kwargs = {
        "connect_args": {"check_same_thread": False},
        "poolclass": StaticPool,
    }
else:
    _engine_kwargs = {"pool_pre_ping": True}
    if _on_vercel:
        _engine_kwargs["poolclass"] = NullPool
    else:
        _engine_kwargs.update(
            {
                "pool_size": 10,
                "max_overflow": 20,
                "pool_recycle": 300,
            }
        )

engine = create_engine(_database_url, **_engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
