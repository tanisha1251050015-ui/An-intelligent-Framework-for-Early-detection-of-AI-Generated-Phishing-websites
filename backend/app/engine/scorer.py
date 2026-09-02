"""Scoring engine: sums fired rules, clamps to 0-100, and classifies."""

from dataclasses import dataclass

from app.engine.classifier import classify
from app.engine.features import Features
from app.engine.rules import evaluate_rules

MIN_SCORE = 0
MAX_SCORE = 100


@dataclass(frozen=True)
class ScoreOutcome:
    """Final Phase 1 result for a URL."""

    score: int
    classification: str
    reasons: tuple[str, ...]


def score_features(features: Features) -> ScoreOutcome:
    """Score extracted features deterministically.

    The score is the sum of all fired rule penalties, clamped to the inclusive
    range 0-100, then mapped to a classification band.
    """
    results = evaluate_rules(features)
    total = sum(result.penalty for result in results)
    score = max(MIN_SCORE, min(MAX_SCORE, total))
    return ScoreOutcome(
        score=score,
        classification=classify(score),
        reasons=tuple(result.reason for result in results),
    )
