"""Tests for Continual Learning (Priority 8)."""

import pytest
import json
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.learning import Feedback, TrainingExample, ModelVersion, LearningEvent
from app.models.inspection import Inspection
from app.core import learning

@pytest.fixture(scope="function")
def db():
    session = SessionLocal()
    # clean up learning tables for fresh state
    session.query(LearningEvent).delete()
    session.query(TrainingExample).delete()
    session.query(Feedback).delete()
    session.query(ModelVersion).delete()
    session.query(Inspection).delete()
    session.commit()
    yield session
    session.close()

@pytest.fixture(scope="function")
def client():
    return TestClient(app)

def create_mock_inspection(db, url="https://example.com/login", features=None, html=None):
    if features is None:
        features = {"url_length": 25}
    if html is None:
        html = {"password_input_count": 1}
        
    insp = Inspection(
        url=url,
        features_json=json.dumps(features),
        collection_json=json.dumps({"html": html})
    )
    db.add(insp)
    db.commit()
    db.refresh(insp)
    return insp

def test_p8_feedback_lifecycle(client, db):
    """TEST 1: Create analyst feedback. TEST 2: Unvalidated feedback."""
    insp = create_mock_inspection(db)
    
    # Unvalidated
    res = client.post("/api/v1/learning/feedback", json={
        "inspection_id": insp.id,
        "label": "phishing",
        "source": "analyst",
        "validated": False
    })
    assert res.status_code == 200
    assert res.json()["status"] == "pending"
    
    # Try building dataset, should not include unvalidated
    client.post("/api/v1/learning/dataset/build")
    examples = db.query(TrainingExample).count()
    assert examples == 0

def test_p8_validated_feedback(client, db):
    """TEST 3 & 4 & 5: Validated feedback entering dataset."""
    i_phish = create_mock_inspection(db, "http://bad.com")
    i_legit = create_mock_inspection(db, "http://good.com")
    i_unk = create_mock_inspection(db, "http://unknown.com")
    
    client.post("/api/v1/learning/feedback", json={"inspection_id": i_phish.id, "label": "phishing", "source": "analyst", "validated": True})
    client.post("/api/v1/learning/feedback", json={"inspection_id": i_legit.id, "label": "legitimate", "source": "analyst", "validated": True})
    client.post("/api/v1/learning/feedback", json={"inspection_id": i_unk.id, "label": "unknown", "source": "analyst", "validated": True})
    
    # Build dataset
    client.post("/api/v1/learning/dataset/build")
    
    examples = db.query(TrainingExample).all()
    # TEST 5: Unknown is excluded. Only phishing and legitimate are included.
    assert len(examples) == 2
    labels = [e.label for e in examples]
    assert "phishing" in labels
    assert "legitimate" in labels
    assert "unknown" not in labels
    
    # TEST 6: Feature schema version
    assert all(e.feature_schema_version == "v1" for e in examples)
    
    # TEST 7: Dataset versioning (generates dataset-v...)
    assert all("dataset-v" in e.dataset_version for e in examples)

def test_p8_training_data_constraints(client, db):
    """TEST 8 & 9: Insufficient data and class imbalance."""
    i1 = create_mock_inspection(db)
    client.post("/api/v1/learning/feedback", json={"inspection_id": i1.id, "label": "phishing", "source": "analyst", "validated": True})
    
    # Only 1 sample (requires 5) -> Insufficient data
    res = client.post("/api/v1/learning/train")
    assert res.status_code == 400
    assert "insufficient" in res.json()["detail"].lower()
    
    for _ in range(5):
        client.post("/api/v1/learning/feedback", json={"inspection_id": i1.id, "label": "phishing", "source": "analyst", "validated": True})
        
    # 6 samples, but ALL phishing -> Class imbalance
    res = client.post("/api/v1/learning/train")
    assert res.status_code == 400
    assert "imbalance" in res.json()["detail"].lower()

def test_p8_model_lifecycle(client, db):
    """TEST 10, 11, 12, 13, 14, 19: Full model lifecycle."""
    # Seed valid dataset: 3 phishing, 3 legitimate
    for _ in range(3):
        i_p = create_mock_inspection(db, "http://bad.com")
        client.post("/api/v1/learning/feedback", json={"inspection_id": i_p.id, "label": "phishing", "source": "analyst", "validated": True})
        i_l = create_mock_inspection(db, "http://good.com")
        client.post("/api/v1/learning/feedback", json={"inspection_id": i_l.id, "label": "legitimate", "source": "analyst", "validated": True})
        
    res = client.post("/api/v1/learning/train")
    assert res.status_code == 200
    model_version = res.json()["model_version"]
    
    # TEST 10: Metadata created
    model = db.query(ModelVersion).filter_by(version=model_version).first()
    assert model.status == "candidate" # TEST 19: Candidate cannot accidentally become active
    
    # TEST 11: Metrics
    metrics = json.loads(model.metrics_json)
    assert "recall" in metrics
    
    # TEST 12: Promotion
    res = client.post(f"/api/v1/learning/models/{model_version}/promote")
    assert res.status_code == 200
    db.refresh(model)
    assert model.status == "active"
    
    # Train another model to test Rollback
    for _ in range(3):
        i_p = create_mock_inspection(db, "http://bad.com")
        client.post("/api/v1/learning/feedback", json={"inspection_id": i_p.id, "label": "phishing", "source": "analyst", "validated": True})
        
    res2 = client.post("/api/v1/learning/train")
    model_version_2 = res2.json()["model_version"]
    
    # Let's say model 2 fails safety gate manually by lowering its recall
    m2 = db.query(ModelVersion).filter_by(version=model_version_2).first()
    m2.metrics_json = json.dumps({"recall": 0.50, "f1": 0.50}) # Very bad
    db.commit()
    
    # TEST 13: Promotion failure
    res_fail = client.post(f"/api/v1/learning/models/{model_version_2}/promote")
    assert res_fail.status_code == 400
    db.refresh(model) # Model 1 should still be active
    assert model.status == "active"
    
    # Force promote model 2 by bypassing gate just to test rollback
    m2.status = "candidate"
    m2.metrics_json = json.dumps({"recall": 0.99, "f1": 0.99, "false_positive_rate": 0.02})
    db.commit()
    
    res_force = client.post(f"/api/v1/learning/models/{model_version_2}/promote")
    assert res_force.status_code == 200
    
    db.refresh(model)
    assert model.status == "archived"
    
    # TEST 14: Rollback
    client.post(f"/api/v1/learning/models/{model_version}/rollback")
    db.refresh(model)
    db.refresh(m2)
    assert model.status == "active"
    assert m2.status == "archived"

def test_p8_drift_detection(client, db):
    """TEST 15 & 16: Drift detection."""
    # Seed training dataset with url_length around 20
    for _ in range(5):
        i = create_mock_inspection(db, "http://good.com") # len 15
        client.post("/api/v1/learning/feedback", json={"inspection_id": i.id, "label": "legitimate", "source": "analyst", "validated": True})
    client.post("/api/v1/learning/dataset/build")
    
    # Test 16: No drift
    # Feed inspections of similar length
    for _ in range(5):
        create_mock_inspection(db, "http://good.com")
        
    status = client.get("/api/v1/learning/status").json()
    assert status["drift"]["detected"] is False
    
    # Test 15: Drift detected
    # Feed very long inspections
    long_url = "http://" + "a" * 100 + ".com"
    for _ in range(5):
        create_mock_inspection(db, long_url)
        
    status2 = client.get("/api/v1/learning/status").json()
    assert status2["drift"]["detected"] is True

def test_p8_phase1_isolation(client, db):
    """TEST 17 & 18: Phase 1 unchanged and inspection works with no model."""
    res = client.post("/api/v1/inspect", json={"url": "https://example.com/login", "collect": False})
    assert res.status_code == 200
    assert "score" in res.json()
    assert res.json()["classification"] in ("safe", "suspicious", "phishing")

def test_p8_audit_events(client, db):
    """TEST 20: Audit events generated."""
    i = create_mock_inspection(db)
    client.post("/api/v1/learning/feedback", json={"inspection_id": i.id, "label": "legitimate", "source": "analyst", "validated": True})
    client.post("/api/v1/learning/dataset/build")
    
    events = db.query(LearningEvent).all()
    types = [e.event_type for e in events]
    assert "feedback_created" in types
    assert "dataset_generated" in types
