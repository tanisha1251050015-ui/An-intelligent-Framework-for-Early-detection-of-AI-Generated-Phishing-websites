"""URL parsing and validation for the Phase 1 engine."""

from dataclasses import dataclass
from urllib.parse import urlsplit

SUPPORTED_SCHEMES = frozenset({"http", "https"})


class MalformedURLError(ValueError):
    """Raised when a submitted URL cannot be inspected."""


@dataclass(frozen=True)
class ParsedURL:
    """Normalized components of a valid, inspectable URL."""

    scheme: str
    hostname: str
    netloc: str
    path: str
    query: str
    fragment: str


def parse_url(raw: str) -> ParsedURL:
    """Parse and validate a URL for inspection.

    Raises :class:`MalformedURLError` for empty input, unsupported or missing
    schemes, and missing hostnames so callers can respond with HTTP 422.
    """
    if raw is None:
        raise MalformedURLError("URL must not be empty")

    cleaned = raw.strip()
    if not cleaned:
        raise MalformedURLError("URL must not be empty")

    parts = urlsplit(cleaned)

    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        missing = "missing" if not scheme else f"unsupported ({scheme!r})"
        raise MalformedURLError(f"URL scheme is {missing}; expected http or https")

    if not parts.hostname:
        raise MalformedURLError("URL must include a hostname")

    return ParsedURL(
        scheme=scheme,
        hostname=parts.hostname.lower().rstrip("."),
        netloc=parts.netloc,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
    )
