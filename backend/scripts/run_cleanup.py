"""Execution script for Phase 2D post-work cleanup.

Safe to trigger via cron or OS scheduler.
"""

import sys
from pathlib import Path

# Ensure the backend directory is in the PYTHONPATH so imports work when run as script
backend_dir = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(backend_dir))

from app.db.session import SessionLocal
from app.core.retention import cleanup_all


def main():
    print("Starting cleanup...")
    db = SessionLocal()
    try:
        stats = cleanup_all(db)
        print("Cleanup completed successfully.")
        print(f"Inspections: {stats.get('inspections', {})}")
        print(f"Screenshots: {stats.get('screenshots', {})}")
    except Exception as exc:
        print(f"Cleanup failed with error: {exc}")
    finally:
        db.close()

if __name__ == "__main__":
    main()
