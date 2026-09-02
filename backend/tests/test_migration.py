"""Tests for the idempotent additive database migration (Phase 2A)."""

from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.migrate import run_migrations

LEGACY_DDL = """
CREATE TABLE inspections (
    id INTEGER PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    status VARCHAR(32) NOT NULL,
    score INTEGER,
    classification VARCHAR(32),
    features_json TEXT,
    reasons_json TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
)
"""


def _engine():
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _columns(engine):
    with engine.connect() as conn:
        return [row[1] for row in conn.execute(text("PRAGMA table_info(inspections)"))]


def test_migration_adds_column_and_preserves_existing_rows():
    engine = _engine()
    with engine.begin() as conn:
        conn.execute(text(LEGACY_DDL))
        conn.execute(
            text(
                "INSERT INTO inspections (id, url, status, created_at, updated_at) "
                "VALUES (1, 'https://example.com/', 'completed', "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )

    run_migrations(engine)

    assert "collection_json" in _columns(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT url, collection_json FROM inspections WHERE id = 1")
        ).fetchone()
        assert row[0] == "https://example.com/"
        assert row[1] is None  # absent collection evidence stays SQL NULL


def test_migration_is_idempotent():
    engine = _engine()
    with engine.begin() as conn:
        conn.execute(text(LEGACY_DDL))

    run_migrations(engine)
    run_migrations(engine)  # second run must be a no-op

    assert _columns(engine).count("collection_json") == 1


def test_migration_noop_on_current_schema():
    engine = _engine()
    Base.metadata.create_all(bind=engine)  # already includes collection_json

    run_migrations(engine)

    assert _columns(engine).count("collection_json") == 1


def test_migration_adds_dns_data_column_and_preserves_rows():
    engine = _engine()
    with engine.begin() as conn:
        conn.execute(text(LEGACY_DDL))
        conn.execute(
            text(
                "INSERT INTO inspections (id, url, status, created_at, updated_at) "
                "VALUES (1, 'https://example.com/', 'completed', "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )

    run_migrations(engine)

    columns = _columns(engine)
    assert "dns_data" in columns
    assert columns.count("dns_data") == 1
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT url, collection_json, dns_data FROM inspections WHERE id = 1")
        ).fetchone()
        assert row[0] == "https://example.com/"
        assert row[1] is None  # absent collection stays SQL NULL
        assert row[2] is None  # absent DNS stays SQL NULL

    run_migrations(engine)  # idempotent
    assert _columns(engine).count("dns_data") == 1
