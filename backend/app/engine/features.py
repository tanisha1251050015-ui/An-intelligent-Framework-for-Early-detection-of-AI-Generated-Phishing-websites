"""Deterministic URL feature extraction — the Phase 1 feature set.

Every feature is computed with explicit, testable logic. The keyword and TLD
lists are fixed constants so behavior is fully reproducible.
"""

import ipaddress
from dataclasses import dataclass
from urllib.parse import parse_qsl

from app.engine.parser import parse_url

# Suspicious terms looked for in the lowercased full URL.
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "confirm",
    "account",
    "secure",
    "security",
    "banking",
    "bank",
    "update",
    "password",
    "credential",
    "credentials",
    "webscr",
    "paypal",
    "appleid",
    "icloud",
    "microsoft",
    "outlook",
    "office365",
    "gmail",
    "amazon",
    "ebay",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "coinbase",
    "wallet",
    "blockchain",
    "bitcoin",
    "suspend",
    "suspended",
    "alert",
    "unlock",
    "invoice",
    "gift",
    "prize",
    "winner",
    "lottery",
    "crypto",
)

# Top-level domains frequently abused by phishing campaigns.
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "club",
        "work",
        "zip",
        "stream",
        "click",
        "country",
        "loan",
        "men",
        "pw",
        "icu",
        "cyou",
        "rest",
        "surf",
        "party",
        "quest",
        "gdn",
        "bid",
        "trade",
        "review",
        "win",
        "date",
        "racing",
        "download",
        "science",
        "kim",
        "mom",
        "mona",
    }
)


@dataclass(frozen=True)
class Features:
    """All extracted features for a single URL."""

    url: str
    scheme: str
    hostname: str
    is_ip_hostname: bool
    has_at_symbol: bool
    suspicious_keywords: tuple[str, ...] = ()
    url_length: int = 0
    subdomain_count: int = 0
    query_parameter_count: int = 0
    tld: str = ""
    is_suspicious_tld: bool = False
    hostname_digit_count: int = 0
    hostname_hyphen_count: int = 0


def _is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features(raw_url: str) -> Features:
    """Extract the full Phase 1 feature set from a URL.

    Raises :class:`app.engine.parser.MalformedURLError` for malformed input.
    """
    parsed = parse_url(raw_url)
    hostname = parsed.hostname
    is_ip = _is_ip_hostname(hostname)

    lowered = raw_url.strip().lower()
    keywords = tuple(sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered}))

    # Subdomain count = labels beyond the registered domain (e.g. "example.com").
    labels = hostname.split(".") if not is_ip else []
    subdomain_count = max(0, len(labels) - 2) if len(labels) >= 2 else 0

    tld = labels[-1] if len(labels) >= 2 else ""

    return Features(
        url=raw_url.strip(),
        scheme=parsed.scheme,
        hostname=hostname,
        is_ip_hostname=is_ip,
        has_at_symbol="@" in parsed.netloc,
        suspicious_keywords=keywords,
        url_length=len(raw_url.strip()),
        subdomain_count=subdomain_count,
        query_parameter_count=len(parse_qsl(parsed.query)),
        tld=tld,
        is_suspicious_tld=tld in SUSPICIOUS_TLDS,
        hostname_digit_count=sum(char.isdigit() for char in hostname),
        hostname_hyphen_count=hostname.count("-"),
    )
