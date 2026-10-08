"""Continual Learning Core Logic."""

import json
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.learning import Feedback, TrainingExample, ModelVersion, LearningEvent
from app.models.inspection import Inspection

FEATURE_SCHEMA_VERSION = "v1"

# Configuration Constraints
MIN_TRAINING_SAMPLES = 5
MIN_PHISHING_RECALL = 0.90
MAX_FALSE_POSITIVE_INCREASE = 0.05
MIN_F1_SCORE = 0.85

def _log_event(db: Session, event_type: str, entity_type: str, entity_id: str, details: dict):
    """Create an audit trail event."""
    event = LearningEvent(
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        details_json=json.dumps(details)
    )
    db.add(event)

def extract_features_v1(inspection: Inspection) -> dict:
    """Explicit deterministic feature extraction for training. Version v1."""
    features = {}
    f_json = json.loads(inspection.features_json) if inspection.features_json else {}
    c_json = json.loads(inspection.collection_json) if inspection.collection_json else {}
    html = c_json.get("html", {})
    
    # URL Features
    features["url_length"] = len(inspection.url)
    features["suspicious_tld"] = 1 if f_json.get("suspicious_tld") else 0
    features["suspicious_keyword_count"] = len(f_json.get("suspicious_keywords", []))
    
    # HTML Features
    features["password_input_count"] = html.get("password_input_count", 0)
    features["credential_input_count"] = html.get("credential_input_count", 0)
    features["external_form_action_count"] = html.get("external_form_action_count", 0)
    features["iframe_count"] = html.get("iframe_count", 0)
    
    return features

def get_active_model(db: Session) -> ModelVersion | None:
    return db.query(ModelVersion).filter(ModelVersion.status == "active").order_by(ModelVersion.created_at.desc()).first()

def get_candidate_model(db: Session) -> ModelVersion | None:
    return db.query(ModelVersion).filter(ModelVersion.status == "candidate").order_by(ModelVersion.created_at.desc()).first()

def create_feedback(db: Session, inspection_id: int, label: str, source: str, validated: bool, comment: str | None = None) -> Feedback:
    active = get_active_model(db)
    
    feedback = Feedback(
        inspection_id=inspection_id,
        label=label,
        source=source,
        validated=validated,
        comment=comment,
        model_version=active.version if active else None
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    
    _log_event(db, "feedback_created", "feedback", str(feedback.id), {"label": label, "validated": validated})
    db.commit()
    
    return feedback

def build_training_dataset(db: Session) -> str:
    """Converts validated feedback into explicit training examples."""
    # Find validated feedback without training examples
    feedbacks = db.query(Feedback).filter(
        Feedback.validated == True,
        Feedback.label.in_(["phishing", "legitimate"]) # EXCLUDE "unknown" and "suspicious"
    ).outerjoin(TrainingExample).filter(TrainingExample.id == None).all()
    
    if not feedbacks:
        # Check if we already have a dataset, return its version
        latest_ex = db.query(TrainingExample).order_by(TrainingExample.created_at.desc()).first()
        return latest_ex.dataset_version if latest_ex else "dataset-v0"
        
    dataset_version = f"dataset-v{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    
    count = 0
    for fb in feedbacks:
        insp = db.query(Inspection).filter(Inspection.id == fb.inspection_id).first()
        if not insp:
            continue
            
        features = extract_features_v1(insp)
        example = TrainingExample(
            inspection_id=insp.id,
            feedback_id=fb.id,
            features_json=json.dumps(features),
            label=fb.label,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            dataset_version=dataset_version
        )
        db.add(example)
        count += 1
        
    # Also update previous training examples to be included in this new "logical" dataset view
    # In a real system, dataset_version might just be a timestamp or a separate relation table.
    # For now, we will just stamp the new ones. When training, we query ALL examples.
    
    _log_event(db, "dataset_generated", "dataset", dataset_version, {"new_samples": count})
    db.commit()
    
    return dataset_version

def detect_drift(db: Session) -> tuple[bool, list]:
    """Lightweight deterministic drift detection."""
    # Compare recent 50 inspections vs training set means
    # Here we simulate drift logic.
    recent = db.query(Inspection).order_by(Inspection.created_at.desc()).limit(50).all()
    if not recent:
        return False, []
        
    # Example logic: if average URL length shifts significantly
    avg_len = sum(len(i.url) for i in recent) / len(recent)
    
    examples = db.query(TrainingExample).all()
    if examples:
        train_len = sum(json.loads(e.features_json).get("url_length", 0) for e in examples) / len(examples)
        if abs(avg_len - train_len) > 20: # arbitrary threshold for deterministic test
            return True, [{"feature": "url_length", "change": abs(avg_len - train_len), "status": "drift"}]
            
    # Always return false in baseline unless triggered by specific test data
    return False, []

def train_candidate(db: Session) -> dict:
    """Mock candidate model training for the adaptive lifecycle."""
    dataset_version = build_training_dataset(db)
    examples = db.query(TrainingExample).all()
    
    if len(examples) < MIN_TRAINING_SAMPLES:
        return {"status": "error", "reason": "insufficient_training_data"}
        
    phishing_count = sum(1 for e in examples if e.label == "phishing")
    legit_count = sum(1 for e in examples if e.label == "legitimate")
    
    if phishing_count == 0 or legit_count == 0:
        return {"status": "error", "reason": "severe_class_imbalance"}
        
    model_version = f"edi-xgb-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    
    # Mock evaluation metrics
    metrics = {
        "accuracy": 0.95,
        "precision": 0.92,
        "recall": 0.96, # High recall
        "f1": 0.94,
        "false_positive_rate": 0.02
    }
    
    model = ModelVersion(
        version=model_version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        dataset_version=dataset_version,
        model_type="mock_xgboost",
        training_samples=len(examples),
        metrics_json=json.dumps(metrics),
        status="candidate"
    )
    db.add(model)
    _log_event(db, "candidate_trained", "model", model_version, {"samples": len(examples)})
    db.commit()
    
    return {"status": "success", "model_version": model_version}

def promote_model(db: Session, version: str) -> dict:
    """Safely promote a candidate model."""
    candidate = db.query(ModelVersion).filter(ModelVersion.version == version).first()
    if not candidate or candidate.status != "candidate":
        return {"status": "error", "reason": "invalid_candidate"}
        
    metrics = json.loads(candidate.metrics_json)
    
    # Safety Gates
    if metrics.get("recall", 0) < MIN_PHISHING_RECALL:
        candidate.status = "rejected"
        db.commit()
        return {"status": "error", "reason": "safety_gate_failed_recall"}
        
    if metrics.get("f1", 0) < MIN_F1_SCORE:
        candidate.status = "rejected"
        db.commit()
        return {"status": "error", "reason": "safety_gate_failed_f1"}
        
    # Active vs Candidate check
    active = get_active_model(db)
    if active:
        active_metrics = json.loads(active.metrics_json)
        # Check FPR degradation
        if metrics.get("false_positive_rate", 0) - active_metrics.get("false_positive_rate", 0) > MAX_FALSE_POSITIVE_INCREASE:
            candidate.status = "rejected"
            db.commit()
            return {"status": "error", "reason": "safety_gate_failed_fpr"}
            
        active.status = "archived"
        
    candidate.status = "active"
    _log_event(db, "model_promoted", "model", version, {"previous": active.version if active else None})
    db.commit()
    return {"status": "success", "model_version": version}

def rollback_model(db: Session, version: str) -> dict:
    """Rollback to a previously archived model."""
    target = db.query(ModelVersion).filter(ModelVersion.version == version).first()
    if not target or target.status != "archived":
        return {"status": "error", "reason": "invalid_target"}
        
    active = get_active_model(db)
    if active:
        active.status = "archived"
        
    target.status = "active"
    _log_event(db, "model_rolled_back", "model", version, {"previous": active.version if active else None})
    db.commit()
    return {"status": "success", "model_version": version}
