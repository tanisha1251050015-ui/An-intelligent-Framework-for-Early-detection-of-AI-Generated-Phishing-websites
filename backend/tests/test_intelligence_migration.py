"""Tests for Phase 2C database migration."""

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
    collection_json TEXT,
    dns_data TEXT,
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


def test_migration_adds_intelligence_columns():
    """Phase 2C migration adds ssl_data, whois_data, intelligence_json."""
    engine = _engine()
    with engine.begin() as conn:
        conn.execute(text(LEGACY_DDL))

    run_migrations(engine)

    columns = _columns(engine)
    assert "ssl_data" in columns
    assert "whois_data" in columns
    assert "intelligence_json" in columns


def test_migration_is_idempotent():
    """Running migration twice does not duplicate columns."""
    engine = _engine()
    with engine.begin() as conn:
        conn.execute(text(LEGACY_DDL))

    run_migrations(engine)
    run_migrations(engine)

    columns = _columns(engine)
    assert columns.count("ssl_data") == 1
    assert columns.count("whois_data") == 1
    assert columns.count("intelligence_json") == 1


def test_migration_preserves_existing_rows():
    """Existing records are preserved and new columns are NULL."""
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

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT url, ssl_data, whois_data, intelligence_json FROM inspections WHERE id = 1")
        ).fetchone()
        assert row[0] == "https://example.com/"
        assert row[1] is None  # ssl_data is SQL NULL
        assert row[2] is None  # whois_data is SQL NULL
        assert row[3] is None  # intelligence_json is SQL NULL


def test_migration_noop_on_current_schema():
    """Migration is a no-op when schema already has all columns."""
    engine = _engine()
    Base.metadata.create_all(bind=engine)

    run_migrations(engine)

    columns = _columns(engine)
    assert columns.count("ssl_data") == 1
    assert columns.count("whois_data") == 1
    assert columns.count("intelligence_json") == 1


def test_migration_adds_to_phase2a_schema():
    """Migration works when starting from Phase 2A schema (with collection_json)."""
    phase2a_ddl = """
    CREATE TABLE inspections (
        id INTEGER PRIMARY KEY,
        url VARCHAR(2048) NOT NULL,
        status VARCHAR(32) NOT NULL,
        score INTEGER,
        classification VARCHAR(32),
        features_json TEXT,
        reasons_json TEXT,
        collection_json TEXT,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL
    )
    """
    engine = _engine()
    with engine.begin() as conn:
        conn.execute(text(phase2a_ddl))

    run_migrations(engine)  # adds collection_json (no-op), dns_data, ssl_data, whois_data, intelligence_json

    columns = _columns(engine)
    assert "collection_json" in columns
    assert "dns_data" in columns
    assert "ssl_data" in columns
    assert "whois_data" in columns
    assert "intelligence_json" in columns
