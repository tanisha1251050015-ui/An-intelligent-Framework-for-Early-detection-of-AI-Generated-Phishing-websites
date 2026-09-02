"""Tests for the Phase 1 classification bands.

    0-29   safe
    30-69  suspicious
    70-100 malicious
"""

import pytest

from app.engine.classifier import classify


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "safe"),
        (29, "safe"),
        (30, "suspicious"),
        (69, "suspicious"),
        (70, "malicious"),
        (100, "malicious"),
    ],
)
def test_classification_bands(score, expected):
    assert classify(score) == expected
