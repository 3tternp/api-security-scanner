"""
Lightweight, additive schema reconciliation run on startup.

This project has no wired-up migration tool (Base.metadata.create_all only
creates missing *tables*, never adds missing *columns* to a table that
already exists). For a fresh database that's fine, but a pre-existing
production database that predates a model change would otherwise be left
with a stale schema and start failing every query that touches the new
columns. This adds any columns the ORM models expect but the database is
missing, so an existing deployment picks up model changes automatically.
"""
import logging
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)


def ensure_columns(engine: Engine, table: str, columns: dict) -> None:
    """Add any of `columns` (name -> (sql_type, default_literal)) missing from `table`."""
    inspector = inspect(engine)
    if table not in inspector.get_table_names():
        return  # table doesn't exist yet — create_all will handle it

    existing = {col["name"] for col in inspector.get_columns(table)}
    missing = {name: spec for name, spec in columns.items() if name not in existing}
    if not missing:
        return

    with engine.begin() as conn:
        for name, (sql_type, default_literal) in missing.items():
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
            conn.execute(text(f"UPDATE {table} SET {name} = :default WHERE {name} IS NULL").bindparams(default=default_literal))
            logger.info(f"Added missing column '{name}' to table '{table}'")
