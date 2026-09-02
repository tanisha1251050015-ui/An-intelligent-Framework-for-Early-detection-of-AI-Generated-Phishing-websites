"""Inspection ORM model.

Phase 1 extends the Phase 0 schema with the results of the deterministic
scoring engine: risk score, classification, and serialized features/reasons.
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class InspectionStatus(str, Enum):
    """Lifecycle states of an inspection record."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Inspection(Base):
    """A single URL inspection record."""

    __tablename__ = "inspections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=InspectionStatus.PENDING.value,
    )
    # Phase 1 results (NULL until an inspection completes).
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    features_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 2A: collection evidence (SQL NULL when no collection was performed).
    collection_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 2B: DNS intelligence (SQL NULL for records created before Phase 2B).
    dns_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 2C: SSL intelligence (SQL NULL for records created before Phase 2C).
    ssl_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 2C: WHOIS intelligence (SQL NULL when not configured).
    whois_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 2C: Fusion intelligence summary (SQL NULL when not computed).
    intelligence_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 2D: Intelligence data components (SQL NULL when not computed).
    screenshot_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    ocr_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )
