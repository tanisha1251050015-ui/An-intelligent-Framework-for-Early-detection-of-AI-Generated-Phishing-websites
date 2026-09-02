"""Deterministic, transparent URL inspection engine (Phase 1).

The engine is fully rule-based: feature extraction is explicit and scoring
rules are declarative and inspectable. No machine learning, LLMs, or external
intelligence are used.
"""

from app.engine.classifier import classify
from app.engine.features import Features, extract_features
from app.engine.parser import MalformedURLError, parse_url
from app.engine.scorer import MAX_SCORE, MIN_SCORE, ScoreOutcome, score_features

__all__ = [
    "Features",
    "MalformedURLError",
    "MAX_SCORE",
    "MIN_SCORE",
    "ScoreOutcome",
    "classify",
    "extract_features",
    "parse_url",
    "score_features",
]
