"""Inspection request/response schemas (Phase 1 + Phase 2A)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class InspectRequest(BaseModel):
    """Payload for POST /api/v1/inspect.

    ``url`` is validated by the engine, which returns 422 for malformed URLs.
    ``collect`` opts into Phase 2A HTTP/HTML collection; when False (default)
    only Phase 1 scoring runs and the collection result is absent (NULL).
    ``intelligence`` opts into Phase 2C intelligence enrichment; when False
    (default) no Phase 2C processing occurs.
    """

    url: str = Field(..., description="URL to inspect", min_length=1)
    collect: bool = Field(
        default=False,
        description="Opt in to safe HTTP/HTML collection (Phase 2A)",
    )
    intelligence: bool = Field(
        default=False,
        description="Opt in to Phase 2C intelligence enrichment",
    )


class InspectionCreate(BaseModel):
    """Payload for creating an inspection (used from later phases)."""

    url: str = Field(..., description="URL to inspect", min_length=1)


class InspectionRead(BaseModel):
    """Serialized inspection record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    url: str
    status: str
    score: int | None
    classification: str | None
    collection_json: str | None
    dns_data: str | None
    ssl_data: str | None
    whois_data: str | None
    intelligence_json: str | None
    screenshot_data: str | None
    ocr_data: str | None
    llm_data: str | None
    created_at: datetime
    updated_at: datetime


class InspectionResponse(BaseModel):
    """Full inspection result returned to clients.

    Phase 1 fields are unchanged; ``collection``, ``dns``, ``ssl``,
    ``whois``, and ``intelligence`` are added additively and are
    ``null`` when not computed.
    """

    id: int
    url: str
    status: str
    score: int
    classification: str
    features: dict[str, Any]
    reasons: list[str]
    collection: dict[str, Any] | None = None
    dns: dict[str, Any] | None = None
    ssl: dict[str, Any] | None = None
    whois: dict[str, Any] | None = None
    intelligence: dict[str, Any] | None = None
    screenshot: dict[str, Any] | None = None
    ocr: dict[str, Any] | None = None
    llm: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime
