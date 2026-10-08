"""Tests for the Phase 1 feature extractor."""

import pytest

from app.engine.features import SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, extract_features
from app.engine.parser import MalformedURLError


def test_extract_http_scheme():
    assert extract_features("http://example.com/").scheme == "http"


def test_extract_https_scheme():
    assert extract_features("https://example.com/").scheme == "https"


def test_ipv4_hostname_detected():
    features = extract_features("https://192.168.1.1/")
    assert features.is_ip_hostname is True
    assert features.hostname == "192.168.1.1"


def test_ipv6_hostname_detected():
    features = extract_features("https://[2001:db8::1]/")
    assert features.is_ip_hostname is True
    assert features.hostname == "2001:db8::1"


def test_regular_hostname_is_not_ip():
    assert extract_features("https://example.com/").is_ip_hostname is False


def test_at_symbol_present():
    features = extract_features("https://user@example.com/")
    assert features.has_at_symbol is True
    assert features.hostname == "example.com"


def test_at_symbol_absent():
    assert extract_features("https://example.com/").has_at_symbol is False


def test_suspicious_keywords_detected():
    features = extract_features("https://example.com/login/verify")
    assert features.suspicious_keywords == ("login", "verify")


def test_suspicious_keyword_locations_are_component_accurate():
    features = extract_features("https://example.com/login?verify=1#account")
    assert features.suspicious_keywords == ("account", "login", "verify")
    assert features.suspicious_keyword_locations == (
        ("account", "fragment"), ("login", "path"), ("verify", "query")
    )


def test_no_suspicious_keywords():
    assert extract_features("https://example.com/").suspicious_keywords == ()


def test_keyword_list_is_non_empty():
    assert len(SUSPICIOUS_KEYWORDS) > 10


def test_url_length():
    assert extract_features("https://example.com/").url_length == 20


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/", 0),
        ("https://www.example.com/", 1),
        ("https://a.b.c.example.com/", 3),
    ],
)
def test_subdomain_count(url, expected):
    assert extract_features(url).subdomain_count == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/", 0),
        ("https://example.com/?a=1", 1),
        ("https://example.com/?a=1&b=2&c=3", 3),
    ],
)
def test_query_parameter_count(url, expected):
    assert extract_features(url).query_parameter_count == expected


def test_suspicious_tld_detected():
    features = extract_features("https://example.tk/")
    assert features.is_suspicious_tld is True
    assert features.tld == "tk"


def test_suspicious_tld_absent():
    features = extract_features("https://example.com/")
    assert features.is_suspicious_tld is False
    assert features.tld == "com"


def test_suspicious_tld_list_is_non_empty():
    assert len(SUSPICIOUS_TLDS) > 10


def test_hostname_digit_count():
    assert extract_features("https://example1234.com/").hostname_digit_count == 4


def test_hostname_hyphen_count():
    assert extract_features("https://aa-bb-cc.com/").hostname_hyphen_count == 2


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "   ",
        "example.com",  # missing scheme
        "not-a-url",  # missing scheme
        "https://",  # missing hostname
        "ftp://example.com/file",  # unsupported scheme
    ],
)
def test_malformed_input_raises(bad_url):
    with pytest.raises(MalformedURLError):
        extract_features(bad_url)


def test_whitespace_is_trimmed():
    features = extract_features("  https://example.com/  ")
    assert features.url == "https://example.com/"
    assert features.hostname == "example.com"
