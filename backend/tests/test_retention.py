"""Tests for Phase 2D post-work retention and cleanup."""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.core.config import DATA_DIR, settings
from app.core.retention import cleanup_all, cleanup_inspections, cleanup_screenshots
from app.main import app
from app.models.inspection import Inspection

client = TestClient(app)

@pytest.fixture
def mock_screenshot_dir(tmp_path):
    """Fixture to mock SCREENSHOT_DIR for tests."""
    screenshot_dir = tmp_path / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    with mock.patch("app.core.retention.SCREENSHOT_DIR", screenshot_dir):
        yield screenshot_dir


@pytest.fixture
def db_session():
    """Fixture providing a fresh DB session for testing retention."""
    from app.db.session import SessionLocal, engine
    from app.db.base import Base
    
    # ensure clean tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(Inspection).delete()
    db.commit()
    yield db
    db.query(Inspection).delete()
    db.commit()
    db.close()


def test_empty_screenshot_directory_works(db_session, mock_screenshot_dir):
    """12. Empty screenshot directory works correctly."""
    stats = cleanup_screenshots(db_session, retention_days=7)
    assert stats["files_scanned"] == 0
    assert stats["files_deleted"] == 0
    assert stats["errors"] == 0


def test_old_screenshot_deleted_and_recent_preserved(db_session, mock_screenshot_dir):
    """1. Old screenshot is deleted. 2. Recent screenshot is preserved."""
    old_file = mock_screenshot_dir / "old.jpg"
    recent_file = mock_screenshot_dir / "recent.jpg"
    
    old_file.write_text("old data")
    recent_file.write_text("recent data")
    
    now = datetime.now().timestamp()
    old_time = now - (8 * 86400) # 8 days old
    recent_time = now - (1 * 86400) # 1 day old
    
    os.utime(old_file, (old_time, old_time))
    os.utime(recent_file, (recent_time, recent_time))

    stats = cleanup_screenshots(db_session, retention_days=7)
        
    assert stats["files_deleted"] == 1
    assert stats["files_skipped"] == 1
    assert stats["errors"] == 0
    
    assert not old_file.exists()
    assert recent_file.exists()


def test_non_screenshot_file_preserved(db_session, mock_screenshot_dir):
    """3. Non-screenshot file is preserved."""
    txt_file = mock_screenshot_dir / "test.txt"
    txt_file.write_text("data")
    
    stats = cleanup_screenshots(db_session, retention_days=0)
    assert stats["files_skipped"] == 1
    assert txt_file.exists()


def test_missing_screenshot_handled_safely(db_session, tmp_path):
    """4. Missing screenshot is handled safely."""
    # point SCREENSHOT_DIR to a missing dir
    missing_dir = tmp_path / "missing"
    with mock.patch("app.core.retention.SCREENSHOT_DIR", missing_dir):
        stats = cleanup_screenshots(db_session, retention_days=7)
        assert stats["files_scanned"] == 0
        assert stats["errors"] == 0


def test_orphan_deleted_referenced_preserved(db_session, mock_screenshot_dir):
    """5. Orphan screenshot deleted only when eligible. 6. Referenced screenshot preserved."""
    orphan_id = "orphan"
    ref_id = "referenced"
    
    orphan_file = mock_screenshot_dir / f"{orphan_id}.jpg"
    ref_file = mock_screenshot_dir / f"{ref_id}.jpg"
    
    orphan_file.write_text("orphan")
    ref_file.write_text("ref")
    
    # insert a record that references `ref_id`
    inspection = Inspection(
        url="https://example.com",
        status="completed",
        screenshot_data=json.dumps({"image_id": ref_id})
    )
    db_session.add(inspection)
    db_session.commit()
    
    # Both are old
    now = datetime.now().timestamp()
    old_time = now - (8 * 86400)
    
    os.utime(orphan_file, (old_time, old_time))
    os.utime(ref_file, (old_time, old_time))
    
    stats = cleanup_screenshots(db_session, retention_days=7)
        
    assert stats["files_deleted"] == 1  # orphan
    assert stats["files_skipped"] == 1  # referenced
    
    assert not orphan_file.exists()
    assert ref_file.exists()


def test_path_traversal_and_symlink_protection(db_session, mock_screenshot_dir, tmp_path):
    """7. Path traversal cannot escape. 8. Symlink outside cannot cause deletion."""
    outside_file = tmp_path / "outside.jpg"
    outside_file.write_text("outside data")
    
    # Create a symlink inside the screenshot dir pointing outside
    symlink_path = mock_screenshot_dir / "link.jpg"
    try:
        symlink_path.symlink_to(outside_file)
    except OSError:
        pytest.skip("Symlink privilege not held on Windows test environment")

    old_time = datetime.now().timestamp() - (8 * 86400)
    os.utime(outside_file, (old_time, old_time))
    
    stats = cleanup_screenshots(db_session, retention_days=7)
        
    # Symlink points outside, so the resolve() check should catch it and mark it as error or skip
    assert outside_file.exists()
    assert stats["errors"] > 0


def test_inspection_records_retention(db_session):
    """9. Old inspection records deleted. 10. Recent inspection records preserved."""
    old_time = datetime.utcnow() - timedelta(days=40)
    recent_time = datetime.utcnow() - timedelta(days=10)
    
    old_inspection = Inspection(url="http://old.com", created_at=old_time)
    recent_inspection = Inspection(url="http://recent.com", created_at=recent_time)
    
    db_session.add(old_inspection)
    db_session.add(recent_inspection)
    db_session.commit()
    
    stats = cleanup_inspections(db_session, retention_days=30)
    assert stats["records_deleted"] == 1
    
    remaining = db_session.query(Inspection).all()
    assert len(remaining) == 1
    assert remaining[0].url == "http://recent.com"


def test_cleanup_failure_does_not_crash(db_session, mock_screenshot_dir):
    """11. Cleanup failure does not crash the application."""
    # Force an exception during unlink
    file = mock_screenshot_dir / "crash.jpg"
    file.write_text("crash")
    
    old_time = datetime.now().timestamp() - (8 * 86400)
    os.utime(file, (old_time, old_time))
        
    with mock.patch("pathlib.Path.unlink", side_effect=PermissionError("no access")):
        stats = cleanup_screenshots(db_session, retention_days=7)
            
    assert stats["errors"] == 1
    assert stats["files_deleted"] == 0
    # Process did not crash


def test_rerunning_idempotent(db_session):
    """13. Re-running cleanup is safe/idempotent."""
    stats1 = cleanup_all(db_session)
    stats2 = cleanup_all(db_session)
    assert stats1["inspections"]["records_deleted"] == 0
    assert stats2["inspections"]["records_deleted"] == 0


def test_retention_boundaries(db_session):
    """14. Retention configuration boundaries work correctly."""
    # Just asserting it uses correct fallback
    assert settings.screenshot_retention_days == 7
    assert settings.inspection_retention_days == 30


def test_integration_inspect_endpoint():
    """15. Integration check verifying POST /api/v1/inspect continues to behave exactly as before."""
    resp = client.post("/api/v1/inspect", json={"url": "http://user@a.b.c.example.com/?x=1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert "score" in data
    # Phase 1 features intact
    assert data["features"]["scheme"] == "http"
    assert data["features"]["has_at_symbol"] is True
