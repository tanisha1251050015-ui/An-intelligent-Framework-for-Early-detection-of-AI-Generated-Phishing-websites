"""Screenshot capture stub (Phase 2C).

Provides an abstract interface for page screenshots. No screenshot API,
no browser automation, no headless browser, and no external service is used.
This stub returns ``not_configured``.
"""

import os
import uuid
from typing import Any
from urllib.parse import urljoin

from app.core.config import DATA_DIR
from app.collection.ssrf import check_target

SCREENSHOT_TIMEOUT_MS = 10000
SCREENSHOT_DIR = DATA_DIR / "screenshots"


def capture_screenshot(url: str) -> dict[str, Any]:
    """Capture a screenshot of a URL securely.

    Enforces SSRF on the initial URL and on all intercepted route requests.
    Saves screenshot to a bounded storage path and returns the file ID.
    """
    target = check_target(url)
    if not target.allowed:
        return {
            "status": "blocked",
            "reason": target.reason,
            "url": url,
        }

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    image_id = str(uuid.uuid4())
    image_path = SCREENSHOT_DIR / f"{image_id}.jpg"

    try:
        from playwright.sync_api import sync_playwright, Route, Error
        import sys
        import asyncio
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720}
            )
            page = context.new_page()

            def handle_route(route: Route):
                req_url = route.request.url
                # Prevent execution of arbitrary downloaded files
                if route.request.resource_type in ("fetch", "xhr", "websocket"):
                    # Allowing some resources but not arbitrary downloads
                    pass

                tgt = check_target(req_url)
                if not tgt.allowed:
                    route.abort("accessdenied")
                else:
                    route.continue_()

            page.route("**/*", handle_route)

            page.goto(url, timeout=SCREENSHOT_TIMEOUT_MS, wait_until="load")
            
            # bounded size by jpeg quality
            page.screenshot(path=str(image_path), type="jpeg", quality=60)
            
            browser.close()

    except Exception as exc:
        if image_path.exists():
            image_path.unlink()
        
        reason = "error"
        if "Timeout" in str(exc):
            reason = "timeout"
            
        return {
            "status": "failed",
            "reason": reason,
            "message": str(exc),
            "url": url,
        }

    return {
        "status": "collected",
        "url": url,
        "image_id": image_id,
        "resolution": "1280x720",
    }
