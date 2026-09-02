"""Health endpoint: GET /api/v1/health."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    """Return basic application health information."""
    database_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # pragma: no cover - exercised when DB is unavailable
        database_status = "error"

    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
        database=database_status,
        timestamp=datetime.now(timezone.utc),
    )
