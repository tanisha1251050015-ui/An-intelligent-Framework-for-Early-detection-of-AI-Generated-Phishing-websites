"""Idempotent additive migrations.

Migrations add new columns/tables only; they never delete or alter existing
records. Running them repeatedly is a no-op, so they are safe to run on every
startup. Column/table names are internal constants, never user input.
"""

from __future__ import annotations

from sqlalchemy import Engine, text

# (table, column, column type) additions, applied in order.
_COLUMN_ADDITIONS: tuple[tuple[str, str, str], ...] = (
    ("inspections", "collection_json", "TEXT"),  # Phase 2A
    ("inspections", "dns_data", "TEXT"),  # Phase 2B
    ("inspections", "ssl_data", "TEXT"),  # Phase 2C
    ("inspections", "whois_data", "TEXT"),  # Phase 2C
    ("inspections", "intelligence_json", "TEXT"),  # Phase 2C
    ("inspections", "screenshot_data", "TEXT"),  # Phase 2D
    ("inspections", "ocr_data", "TEXT"),  # Phase 2D
    ("inspections", "llm_data", "TEXT"),  # Phase 2D
)


def _column_exists(engine: Engine, table: str, column: str) -> bool:
    with engine.connect() as conn:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(row[1] == column for row in rows)


def run_migrations(engine: Engine) -> None:
    """Apply all pending additive migrations."""
    for table, column, column_type in _COLUMN_ADDITIONS:
        if not _column_exists(engine, table, column):
            with engine.begin() as conn:
                conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
                )
