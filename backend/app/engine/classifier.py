"""Phase 1 classification bands.

    0–29   -> safe
    30–69  -> suspicious
    70–100 -> malicious
"""

SAFE_MAX = 29
SUSPICIOUS_MAX = 69


def classify(score: int) -> str:
    """Map a clamped risk score to its classification band."""
    if score <= SAFE_MAX:
        return "safe"
    if score <= SUSPICIOUS_MAX:
        return "suspicious"
    return "malicious"
