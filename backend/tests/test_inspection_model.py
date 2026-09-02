"""Tests for the Inspection ORM model and Pydantic schemas."""

from sqlalchemy import select

from app.models import Inspection, InspectionStatus
from app.schemas.inspection import InspectionCreate, InspectionRead


def test_inspection_creates_with_pending_status(db_session):
    inspection = Inspection(url="https://example.com/login")
    db_session.add(inspection)
    db_session.commit()

    row = db_session.scalar(select(Inspection).where(Inspection.id == inspection.id))
    assert row is not None
    assert row.url == "https://example.com/login"
    assert row.status == InspectionStatus.PENDING.value
    assert row.score is None
    assert row.classification is None
    assert row.created_at is not None
    assert row.updated_at is not None


def test_inspection_status_enum_values():
    assert [s.value for s in InspectionStatus] == [
        "pending",
        "processing",
        "completed",
        "failed",
    ]


def test_inspection_create_schema_accepts_raw_string():
    inspection = InspectionCreate(url="https://example.com/login")
    assert inspection.url == "https://example.com/login"


def test_inspection_read_schema_from_model(db_session):
    inspection = Inspection(url="https://example.com/")
    db_session.add(inspection)
    db_session.commit()
    db_session.refresh(inspection)

    payload = InspectionRead.model_validate(inspection)
    assert payload.id == inspection.id
    assert payload.url == inspection.url
    assert payload.status == InspectionStatus.PENDING.value
    assert payload.score is None
    assert payload.classification is None


def test_inspection_stores_phase1_fields(db_session):
    inspection = Inspection(
        url="https://example.com/login",
        status="completed",
        score=45,
        classification="suspicious",
        features_json='{"scheme": "https"}',
        reasons_json='["Hostname contains suspicious keyword(s): login"]',
    )
    db_session.add(inspection)
    db_session.commit()
    db_session.refresh(inspection)

    row = db_session.scalar(select(Inspection).where(Inspection.id == inspection.id))
    assert row.score == 45
    assert row.classification == "suspicious"
    assert row.features_json == '{"scheme": "https"}'
    assert row.reasons_json is not None
