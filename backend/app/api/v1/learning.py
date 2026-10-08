"""Learning and feedback API endpoints."""

import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core import learning
from app.models.learning import Feedback, TrainingExample, ModelVersion
from app.schemas.learning import FeedbackCreate, FeedbackResponse, LearningStatus, DriftStatus

router = APIRouter(prefix="/learning", tags=["Learning"])

@router.post("/feedback", response_model=FeedbackResponse)
def submit_feedback(req: FeedbackCreate, db: Session = Depends(get_db)):
    """Submit analyst/user feedback for an inspection."""
    fb = learning.create_feedback(
        db=db,
        inspection_id=req.inspection_id,
        label=req.label,
        source=req.source,
        validated=req.validated,
        comment=req.comment
    )
    return {
        "id": fb.id,
        "inspection_id": fb.inspection_id,
        "label": fb.label,
        "status": "validated" if fb.validated else "pending",
        "created_at": fb.created_at
    }

@router.get("/status", response_model=LearningStatus)
def get_status(db: Session = Depends(get_db)):
    """Get the status of the continual learning lifecycle."""
    active = learning.get_active_model(db)
    candidate = learning.get_candidate_model(db)
    
    val_samples = db.query(TrainingExample).count()
    pend_samples = db.query(Feedback).filter(Feedback.validated == False).count()
    
    dataset_version = db.query(TrainingExample).order_by(TrainingExample.created_at.desc()).first()
    d_version = dataset_version.dataset_version if dataset_version else "none"
    
    drift_detected, drift_features = learning.detect_drift(db)
    
    def format_model(m):
        if not m: return None
        return {
            "model_version": m.version,
            "feature_schema_version": m.feature_schema_version,
            "status": m.status,
            "metrics": json.loads(m.metrics_json)
        }
        
    return {
        "active_model": format_model(active),
        "dataset": {
            "version": d_version,
            "samples": val_samples
        },
        "feedback": {
            "validated_samples": val_samples,
            "pending_samples": pend_samples
        },
        "drift": {
            "detected": drift_detected,
            "features": drift_features
        },
        "candidate_model": format_model(candidate)
    }

@router.post("/dataset/build")
def build_dataset(db: Session = Depends(get_db)):
    """Convert validated feedback into explicit training examples."""
    version = learning.build_training_dataset(db)
    return {"status": "success", "dataset_version": version}

@router.post("/train")
def train_candidate(db: Session = Depends(get_db)):
    """Train a candidate model and evaluate it."""
    res = learning.train_candidate(db)
    if res["status"] == "error":
        raise HTTPException(status_code=400, detail=res["reason"])
    return res

@router.post("/models/{model_version}/promote")
def promote_model(model_version: str, db: Session = Depends(get_db)):
    """Safely promote a candidate model to active."""
    res = learning.promote_model(db, model_version)
    if res["status"] == "error":
        raise HTTPException(status_code=400, detail=res["reason"])
    return res

@router.post("/models/{model_version}/rollback")
def rollback_model(model_version: str, db: Session = Depends(get_db)):
    """Rollback to a previously archived model."""
    res = learning.rollback_model(db, model_version)
    if res["status"] == "error":
        raise HTTPException(status_code=400, detail=res["reason"])
    return res
