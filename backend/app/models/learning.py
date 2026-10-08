"""Continual learning and adaptive model lifecycle ORM models."""

from datetime import datetime
from sqlalchemy import Boolean, DateTime, Integer, String, Text, func, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Feedback(Base):
    """Analyst/user feedback for an inspection."""
    __tablename__ = "learning_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    inspection_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    label: Mapped[str] = mapped_column(String(32), nullable=False) # phishing, legitimate, suspicious, unknown
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    validated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())


class TrainingExample(Base):
    """A validated training example derived from feedback."""
    __tablename__ = "learning_training_examples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    inspection_id: Mapped[int] = mapped_column(Integer, nullable=False)
    feedback_id: Mapped[int] = mapped_column(Integer, ForeignKey("learning_feedback.id"), nullable=False)
    features_json: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String(32), nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())


class ModelVersion(Base):
    """Metadata for a trained model version."""
    __tablename__ = "learning_model_versions"

    version: Mapped[str] = mapped_column(String(128), primary_key=True)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(128), nullable=False)
    model_type: Mapped[str] = mapped_column(String(64), nullable=False)
    training_samples: Mapped[int] = mapped_column(Integer, nullable=False)
    metrics_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False) # candidate, active, rejected, archived
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())


class LearningEvent(Base):
    """Audit trail for learning lifecycle events."""
    __tablename__ = "learning_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
