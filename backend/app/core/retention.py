"""Data retention and cleanup module (Phase 2D Post-Work).

Safely purges stale inspection records and orphaned screenshots.
"""

import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import DATA_DIR, settings
from app.models.inspection import Inspection

SCREENSHOT_DIR = DATA_DIR / "screenshots"


def cleanup_screenshots(db: Session, retention_days: int | None = None) -> dict[str, Any]:
    """Clean up orphan/stale screenshots safely.

    Deletes .jpg files in the SCREENSHOT_DIR that are older than
    retention_days and are not referenced by any retained inspection.
    """
    if retention_days is None:
        retention_days = settings.screenshot_retention_days

    # Use naive UTC to match SQLAlchemy SQLite standard behavior if we need DB sync,
    # but for files we use local/system time relative to UTC.
    # To be perfectly safe across platforms, we just use a timedelta from current timestamp.
    cutoff_timestamp = (datetime.now() - timedelta(days=retention_days)).timestamp()

    stats: dict[str, Any] = {
        "files_scanned": 0,
        "files_deleted": 0,
        "files_skipped": 0,
        "errors": 0,
        "bytes_reclaimed": 0,
    }

    if not SCREENSHOT_DIR.exists():
        return stats

    # 1. Find all active screenshot IDs
    active_image_ids = set()
    try:
        # Only check records that have screenshot_data
        for record in db.query(Inspection).filter(Inspection.screenshot_data.isnot(None)).all():
            try:
                data = json.loads(record.screenshot_data)
                if data and isinstance(data, dict):
                    image_id = data.get("image_id")
                    if image_id:
                        active_image_ids.add(str(image_id))
            except Exception:
                pass
    except Exception as exc:
        stats["errors"] += 1
        stats["error_message"] = f"DB query failed: {exc}"
        return stats

    try:
        real_screenshot_dir = SCREENSHOT_DIR.resolve(strict=True)
    except Exception:
        # Directory might not exist or be resolvable
        return stats

    # 2. Scan and safely delete
    try:
        for file_path in SCREENSHOT_DIR.iterdir():
            if not file_path.is_file():
                continue

            stats["files_scanned"] += 1

            # Path traversal and symlink protections
            try:
                resolved_path = file_path.resolve(strict=True)
                if not resolved_path.is_relative_to(real_screenshot_dir):
                    stats["errors"] += 1
                    continue
            except Exception:
                stats["errors"] += 1
                continue

            if file_path.suffix.lower() != ".jpg":
                stats["files_skipped"] += 1
                continue

            try:
                file_stat = file_path.stat()
                if file_stat.st_mtime > cutoff_timestamp:
                    stats["files_skipped"] += 1
                    continue

                image_id = file_path.stem
                if image_id in active_image_ids:
                    # Still referenced by a valid inspection record
                    stats["files_skipped"] += 1
                    continue

                file_size = file_stat.st_size
                file_path.unlink()
                stats["files_deleted"] += 1
                stats["bytes_reclaimed"] += file_size
            except Exception:
                stats["errors"] += 1
    except Exception as exc:
        stats["errors"] += 1
        stats["error_message"] = str(exc)

    return stats


def cleanup_inspections(db: Session, retention_days: int | None = None) -> dict[str, Any]:
    """Clean up stale inspection records from the database."""
    if retention_days is None:
        retention_days = settings.inspection_retention_days

    # SQLAlchemy SQLite datetime mapping generally stores as naive UTC.
    cutoff_time = datetime.utcnow() - timedelta(days=retention_days)

    stats: dict[str, Any] = {
        "records_deleted": 0,
        "errors": 0,
    }

    try:
        records_to_delete = db.query(Inspection).filter(Inspection.created_at < cutoff_time).all()
        for record in records_to_delete:
            db.delete(record)
            stats["records_deleted"] += 1
        db.commit()
    except Exception as exc:
        db.rollback()
        stats["errors"] += 1
        stats["error_message"] = str(exc)

    return stats


def cleanup_all(db: Session) -> dict[str, Any]:
    """Run full retention policy execution.
    
    Order is important: delete inspections first so their screenshots
    become orphans, then clean screenshots.
    """
    inspection_stats = cleanup_inspections(db)
    screenshot_stats = cleanup_screenshots(db)
    
    return {
        "inspections": inspection_stats,
        "screenshots": screenshot_stats,
    }
