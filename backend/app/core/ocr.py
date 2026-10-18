"""Bounded OCR for screenshots captured by the Phase 2D collector.

OCR output is untrusted webpage content. It is returned as data and must never
be interpreted as instructions or used to change the deterministic Phase 1 score.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

try:
    from PIL import Image, UnidentifiedImageError
    import pytesseract
    from pytesseract import TesseractNotFoundError
except ImportError:
    Image = None
    pytesseract = None
    TesseractNotFoundError = RuntimeError
    UnidentifiedImageError = OSError

from app.core.config import DATA_DIR

SCREENSHOT_DIR = DATA_DIR / "screenshots"
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_WIDTH = 4096
MAX_HEIGHT = 4096
MAX_OCR_CHARS = 10_000
OCR_TIMEOUT_SECONDS = 10
_IMAGE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

# Configure the optional Tesseract executable without requiring an environment
# variable or reading a .env file.
if pytesseract is not None:
    tesseract_path = shutil.which("tesseract")
    if tesseract_path:
        pytesseract.pytesseract.tesseract_cmd = tesseract_path


def extract_text(image_id: str) -> dict[str, Any]:
    """Extract bounded text from a screenshot identified by its UUID."""
    if Image is None or pytesseract is None:
        return {"status": "failed", "reason": "ocr_engine_missing"}

    if not isinstance(image_id, str) or not _IMAGE_ID_RE.fullmatch(image_id):
        return {"status": "failed", "reason": "invalid_image_id"}

    try:
        controlled_dir = SCREENSHOT_DIR.resolve()
        requested_path = (controlled_dir / f"{image_id}.jpg").resolve()
        # Path.relative_to is boundary-aware; startswith() is not.
        requested_path.relative_to(controlled_dir)
    except (OSError, ValueError):
        return {"status": "failed", "reason": "path_traversal_blocked"}

    try:
        if not requested_path.is_file():
            return {"status": "failed", "reason": "file_not_found"}
        if requested_path.stat().st_size > MAX_FILE_SIZE:
            return {"status": "failed", "reason": "file_too_large"}
    except OSError:
        return {"status": "failed", "reason": "file_read_error"}

    try:
        with Image.open(requested_path) as img:
            if img.format not in ("JPEG", "PNG"):
                return {"status": "failed", "reason": "unsupported_format"}
            if img.width < 1 or img.height < 1 or img.width > MAX_WIDTH or img.height > MAX_HEIGHT:
                return {"status": "failed", "reason": "image_too_large"}
            text = pytesseract.image_to_string(img, timeout=OCR_TIMEOUT_SECONDS)
    except TesseractNotFoundError:
        return {"status": "failed", "reason": "ocr_engine_missing"}
    except RuntimeError as exc:
        if "timeout" in str(exc).lower():
            return {"status": "failed", "reason": "timeout"}
        return {"status": "failed", "reason": "ocr_error"}
    except Exception:
        return {"status": "failed", "reason": "invalid_image"}

    if not isinstance(text, str):
        text = ""
    truncated = len(text) > MAX_OCR_CHARS
    text = text[:MAX_OCR_CHARS]
    return {
        "status": "completed",
        "text": text,
        "character_count": len(text),
        "truncated": truncated,
    }
