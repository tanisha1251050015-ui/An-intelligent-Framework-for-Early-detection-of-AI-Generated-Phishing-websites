"""Schemas for continual learning."""

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from typing import Any

class FeedbackCreate(BaseModel):
    inspection_id: int = Field(..., description="ID of the inspection")
    label: str = Field(..., description="phishing, legitimate, suspicious, or unknown")
    source: str = Field(..., description="Source of the label (e.g. analyst)")
    validated: bool = Field(False, description="Whether the label is confirmed")
    comment: str | None = Field(None, description="Optional comment")

class FeedbackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    inspection_id: int
    label: str
    status: str # "validated" or "pending" (based on 'validated' bool)
    created_at: datetime

class DriftStatus(BaseModel):
    detected: bool
    features: list[dict[str, Any]]

class LearningStatus(BaseModel):
    active_model: dict[str, Any] | None
    dataset: dict[str, Any]
    feedback: dict[str, Any]
    drift: DriftStatus
    candidate_model: dict[str, Any] | None

class PromotionRequest(BaseModel):
    # Only explicit action triggers promotion
    pass
