"""Tests for the Phase 1 scoring engine.

Each rule is exercised in isolation so its exact penalty is verified, plus
integration cases for clamping and combined scores.
"""

import pytest

from app.engine.features import extract_features
from app.engine.scorer import score_features


def score(url: str) -> int:
    return score_features(extract_features(url)).score


def reasons(url: str) -> tuple[str, ...]:
    return score_features(extract_features(url)).reasons


def test_http_scheme_penalty():
    assert score("http://example.com/") == 15
    assert "Uses HTTP instead of HTTPS" in reasons("http://example.com/")


def test_ip_hostname_penalty():
    assert score("https://127.0.0.1/") == 40


def test_ipv6_hostname_penalty():
    assert score("https://[2001:db8::1]/") == 40


def test_at_symbol_penalty():
    assert score("https://user@example.com/") == 30


def test_suspicious_keyword_penalty():
    assert score("https://example.com/login") == 10


def test_suspicious_keyword_penalty_capped():
    url = "https://example.com/login/verify/account/banking/confirm"
    assert score(url) == 40


def test_long_url_penalty_tier1():
    assert score("https://example.com/" + "a" * 90) == 10


def test_long_url_penalty_tier2():
    assert score("https://example.com/" + "a" * 200) == 20


def test_many_subdomains_penalty():
    assert score("https://a.b.c.example.com/") == 15


def test_many_query_params_penalty():
    assert score("https://example.com/?a=1&b=2&c=3") == 10


def test_suspicious_tld_penalty():
    assert score("https://example.tk/") == 25


def test_digit_heavy_hostname_penalty():
    assert score("https://example1234.com/") == 10


def test_hyphenated_hostname_penalty():
    assert score("https://aa-bb-cc.com/") == 10


def test_clean_url_scores_zero():
    outcome = score_features(extract_features("https://example.com/"))
    assert outcome.score == 0
    assert outcome.classification == "safe"
    assert outcome.reasons == ()


def test_score_clamped_to_100():
    url = "http://user@a.b.c.example-verify-account.tk/?x=1&y=2&z=3"
    outcome = score_features(extract_features(url))
    assert outcome.score == 100
    assert outcome.classification == "malicious"


def test_combined_known_score():
    url = "https://login.example.tk/?a=1&b=2&c=3"
    outcome = score_features(extract_features(url))
    assert outcome.score == 45
    assert outcome.classification == "suspicious"


def test_reasons_explain_every_fired_rule():
    url = "http://user@a.b.c.example-verify-account.tk/?x=1&y=2&z=3"
    fired = reasons(url)
    assert len(fired) == 7
    assert all(isinstance(reason, str) and reason for reason in fired)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "http://example.com/",
        "https://user@a.b.c.example-verify-account.tk/?x=1&y=2&z=3",
        "https://192.168.1.1/",
        "https://example.com/" + "a" * 400,
    ],
)
def test_score_always_within_bounds(url):
    assert 0 <= score(url) <= 100
