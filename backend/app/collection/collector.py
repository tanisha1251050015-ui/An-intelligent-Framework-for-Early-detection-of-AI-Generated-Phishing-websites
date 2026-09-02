"""Safe HTTP/HTML collection (Phase 2A).

Collects limited, bounded evidence for eligible URLs:

- HTTP status, content type, response size (bytes read), redirect chain,
  response time, and (for HTML content) title/link/form/script/input/password
  counts.
- No JavaScript execution, no browser automation, no crawling, no link
  enumeration, no port scanning, no raw body storage.

Bounded requests: configurable timeout, response-size limit, and redirect
limit. SSRF protection (app.collection.ssrf) runs before any connection.
"""

from __future__ import annotations

import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.collection.html_parser import html_stats
from app.collection.ssrf import check_target

DEFAULT_TIMEOUT_SECONDS: float = 5.0
DEFAULT_MAX_BYTES: int = 512 * 1024
DEFAULT_MAX_REDIRECTS: int = 5

BLOCKED = "blocked"
COLLECTED = "collected"
ERROR = "error"


def _request_url(raw_url: str) -> str:
    """Reconstruct the URL without userinfo so credentials are never sent."""
    parts = urlsplit(raw_url)
    try:
        port = parts.port
    except ValueError:
        port = None

    host = parts.hostname or ""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"

    return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))


def _read_limited(response: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes``; returns (body, truncated)."""
    chunks: list[bytes] = []
    total = 0
    truncated = False

    for chunk in response.iter_bytes():
        remaining = max_bytes - total
        if remaining <= 0:
            truncated = True
            break
        keep = chunk[:remaining]
        chunks.append(keep)
        total += len(keep)
        if len(chunk) > remaining:
            truncated = True
            break

    return b"".join(chunks), truncated


def collect(
    raw_url: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> dict:
    """Collect limited HTTP/HTML evidence for a URL.

    Never raises. Returns a dict with ``status`` one of:

    - ``"collected"`` — evidence gathered (see below)
    - ``"blocked"``   — target refused before any connection (e.g. SSRF)
    - ``"error"``     — request failed (timeout, DNS, too many redirects, ...)

    Evidence keys (status ``"collected"``): ``final_url``, ``http_status``,
    ``content_type``, ``response_size``, ``truncated``, ``redirect_count``,
    ``redirects``, ``response_time_ms``, and ``html`` (present only for
    ``text/html`` content; contains title/link/form/script/input/password counts).
    """
    raw_url = raw_url.strip()

    target = check_target(raw_url)
    if not target.allowed:
        return {"status": target.status, "reason": target.reason}

    request_url = _request_url(raw_url)
    own_client = client is None
    if client is None:
        client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            max_redirects=max_redirects,
        )

    started = time.monotonic()
    current_url = request_url
    redirects: list[str] = []

    try:
        while True:
            with client.stream("GET", current_url) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        break

                    if len(redirects) >= max_redirects:
                        raise httpx.TooManyRedirects("too many redirects")

                    # Convert possibly relative location to absolute URL
                    next_url = urljoin(str(response.url), location)

                    # Re-verify SSRF for the redirect target BEFORE connecting
                    target = check_target(next_url)
                    if not target.allowed:
                        return {"status": "blocked", "reason": target.reason}

                    redirects.append(next_url)
                    current_url = _request_url(next_url)
                    continue

                elapsed_ms = int((time.monotonic() - started) * 1000)
                body, truncated = _read_limited(response, max_bytes)

            content_type = response.headers.get("content-type") or ""
            html = html_stats(body) if "text/html" in content_type.lower() else None

            return {
                "status": COLLECTED,
                "final_url": str(response.url),
                "http_status": response.status_code,
                "content_type": content_type,
                "response_size": len(body),
                "truncated": truncated,
                "redirect_count": len(redirects),
                "redirects": redirects,
                "response_time_ms": elapsed_ms,
                "html": html,
            }
    except httpx.TooManyRedirects:
        return {"status": ERROR, "reason": "too_many_redirects"}
    except httpx.TimeoutException:
        return {"status": ERROR, "reason": "request_timeout"}
    except httpx.RequestError:
        return {"status": ERROR, "reason": "request_failed"}
    finally:
        if own_client:
            client.close()
