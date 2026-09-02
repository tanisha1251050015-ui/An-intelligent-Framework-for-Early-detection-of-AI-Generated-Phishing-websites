"""Health endpoint response schema."""

from datetime import datetime

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Payload returned by GET /api/v1/health."""

    status: str
    service: str
    version: str
    database: str
    timestamp: datetime
