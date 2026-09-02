"""Explicit, inspectable Phase 1 scoring rules.

Each rule is a standalone function that returns a :class:`RuleResult` when the
feature it guards is present, otherwise ``None``. The :data:`RULES` registry
lists every rule in evaluation order, so the scoring behavior is fully
auditable. Rules are fixed for Phase 1 and only change on a genuine defect.
"""

from dataclasses import dataclass
from typing import Callable, Optional

from app.engine.features import Features


@dataclass(frozen=True)
class RuleResult:
    """One fired rule: its key, penalty points, and human-readable reason."""

    rule: str
    penalty: int
    reason: str


def _http_scheme(features: Features) -> Optional[RuleResult]:
    if features.scheme == "http":
        return RuleResult("http_scheme", 15, "Uses HTTP instead of HTTPS")
    return None


def _ip_hostname(features: Features) -> Optional[RuleResult]:
    if features.is_ip_hostname:
        return RuleResult(
            "ip_hostname", 40, f"Hostname is a raw IP address ({features.hostname})"
        )
    return None


def _at_symbol(features: Features) -> Optional[RuleResult]:
    if features.has_at_symbol:
        return RuleResult("at_symbol", 30, "URL contains an '@' symbol")
    return None


def _suspicious_keywords(features: Features) -> Optional[RuleResult]:
    if features.suspicious_keywords:
        penalty = min(10 * len(features.suspicious_keywords), 40)
        return RuleResult(
            "suspicious_keywords",
            penalty,
            "Hostname contains suspicious keyword(s): "
            + ", ".join(features.suspicious_keywords),
        )
    return None


def _long_url(features: Features) -> Optional[RuleResult]:
    length = features.url_length
    if length > 300:
        penalty = 30
    elif length > 150:
        penalty = 20
    elif length > 75:
        penalty = 10
    else:
        return None
    return RuleResult(
        "long_url", penalty, f"URL is unusually long ({length} characters)"
    )


def _many_subdomains(features: Features) -> Optional[RuleResult]:
    count = features.subdomain_count
    if count >= 5:
        penalty = 25
    elif count >= 3:
        penalty = 15
    else:
        return None
    return RuleResult(
        "many_subdomains", penalty, f"Hostname has many subdomains ({count})"
    )


def _many_query_params(features: Features) -> Optional[RuleResult]:
    count = features.query_parameter_count
    if count >= 8:
        penalty = 20
    elif count >= 3:
        penalty = 10
    else:
        return None
    return RuleResult(
        "many_query_params", penalty, f"URL has many query parameters ({count})"
    )


def _suspicious_tld(features: Features) -> Optional[RuleResult]:
    if features.is_suspicious_tld:
        return RuleResult(
            "suspicious_tld", 25, f"Suspicious top-level domain: {features.tld}"
        )
    return None


def _digit_heavy_hostname(features: Features) -> Optional[RuleResult]:
    if features.is_ip_hostname:
        return None
    digits = features.hostname_digit_count
    if digits >= 8:
        penalty = 20
    elif digits >= 4:
        penalty = 10
    else:
        return None
    return RuleResult(
        "digit_heavy_hostname", penalty, f"Hostname contains many digits ({digits})"
    )


def _hyphenated_hostname(features: Features) -> Optional[RuleResult]:
    if features.is_ip_hostname:
        return None
    hyphens = features.hostname_hyphen_count
    if hyphens >= 4:
        penalty = 15
    elif hyphens >= 2:
        penalty = 10
    else:
        return None
    return RuleResult(
        "hyphenated_hostname",
        penalty,
        f"Hostname contains many hyphens ({hyphens})",
    )


RULES: tuple[Callable[[Features], Optional[RuleResult]], ...] = (
    _http_scheme,
    _ip_hostname,
    _at_symbol,
    _suspicious_keywords,
    _long_url,
    _many_subdomains,
    _many_query_params,
    _suspicious_tld,
    _digit_heavy_hostname,
    _hyphenated_hostname,
)


def evaluate_rules(features: Features) -> list[RuleResult]:
    """Evaluate every rule in registry order and return the fired results."""
    results: list[RuleResult] = []
    for rule in RULES:
        result = rule(features)
        if result is not None:
            results.append(result)
    return results
