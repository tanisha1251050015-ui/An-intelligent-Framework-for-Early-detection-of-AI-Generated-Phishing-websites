"""Bounded screenshot capture for Phase 2D.

The browser is used only to render one inspected public HTTP(S) URL. Every
request is checked before it is allowed, downloads and service workers are
disabled, navigation and request counts are bounded, and browser resources are
closed on every path. Network-level egress restrictions should still be used
when deploying this worker because application-level DNS checks cannot fully
eliminate DNS-rebinding races.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.collection.ssrf import check_target
from app.core.config import DATA_DIR

SCREENSHOT_TIMEOUT_MS = 10_000
SCREENSHOT_DIR = DATA_DIR / "screenshots"
MAX_REQUESTS = 100
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024


def _safe_request_url(raw_url: str) -> bool:
    """Reject non-web schemes and URLs containing embedded credentials."""
    try:
        parts = urlsplit(raw_url)
        return (
            parts.scheme.lower() in {"http", "https"}
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
        )
    except (TypeError, ValueError):
        return False


def capture_screenshot(url: str) -> dict[str, Any]:
    """Capture a bounded screenshot of an eligible public web page.

    The function never raises to the API caller. A successful result contains
    an opaque image ID, not a filesystem path. Callers must treat the rendered
    page as untrusted content.
    """
    target = check_target(url)
    if not target.allowed:
        return {
            "status": "blocked",
            "reason": target.reason or "target_not_allowed",
            "url": url,
        }

    if not _safe_request_url(url):
        return {"status": "blocked", "reason": "unsupported_or_credentialed_url", "url": url}

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    image_id = str(uuid.uuid4())
    image_path = SCREENSHOT_DIR / f"{image_id}.jpg"
    browser = None
    context = None

    try:
        from playwright.sync_api import Route, sync_playwright

        # On Windows, Playwright's sync API needs a compatible event-loop policy
        # when invoked from applications that may already have an event loop.
        import sys

        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox"],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                accept_downloads=False,
                service_workers="block",
                ignore_https_errors=False,
            )
            page = context.new_page()
            page.set_default_timeout(SCREENSHOT_TIMEOUT_MS)
            page.set_default_navigation_timeout(SCREENSHOT_TIMEOUT_MS)

            request_count = 0

            def handle_route(route: Route) -> None:
                nonlocal request_count
                request_count += 1

                request_url = route.request.url
                if request_count > MAX_REQUESTS:
                    route.abort("blockedbyclient")
                    return

                # Do not allow file:, data:, javascript:, websocket, or
                # credential-bearing URLs to reach the browser's network stack.
                if not _safe_request_url(request_url):
                    route.abort("blockedbyclient")
                    return

                request_target = check_target(request_url)
                if not request_target.allowed:
                    route.abort("blockedbyclient")
                    return

                # Downloads and websocket upgrades are not needed for a static
                # evidence screenshot.
                if route.request.resource_type in {"websocket", "eventsource"}:
                    route.abort("blockedbyclient")
                    return

                route.continue_()

            page.route("**/*", handle_route)
            page.goto(url, timeout=SCREENSHOT_TIMEOUT_MS, wait_until="domcontentloaded")
            # Give the page a short, fixed settling window without waiting
            # indefinitely for trackers or long-running network activity.
            page.wait_for_timeout(500)
            page.screenshot(
                path=str(image_path),
                type="jpeg",
                quality=50,
                animations="disabled",
                timeout=SCREENSHOT_TIMEOUT_MS,
            )

        if not image_path.is_file():
            return {"status": "failed", "reason": "screenshot_missing", "url": url}

        image_size = image_path.stat().st_size
        if image_size <= 0 or image_size > MAX_SCREENSHOT_BYTES:
            image_path.unlink(missing_ok=True)
            return {"status": "failed", "reason": "screenshot_size_limit", "url": url}

        return {
            "status": "collected",
            "url": url,
            "image_id": image_id,
            "resolution": "1280x720",
            "size_bytes": image_size,
        }

    except Exception as exc:
        image_path.unlink(missing_ok=True)
        message = str(exc).lower()
        if "timeout" in message:
            reason = "timeout"
        elif "executable doesn't exist" in message or "executable path" in message:
            reason = "dependency_unavailable"
        elif "err_name_not_resolved" in message:
            reason = "dns_resolution_failed"
        elif "err_connection" in message or "unreachable" in message:
            reason = "domain_unreachable"
        else:
            reason = "browser_error"
        return {"status": "failed", "reason": reason, "url": url}
    finally:
        # Explicitly close resources even if navigation or screenshot fails.
        for resource in (context, browser):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
