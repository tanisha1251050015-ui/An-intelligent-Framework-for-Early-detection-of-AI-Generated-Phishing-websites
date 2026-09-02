"""OCR stub (Phase 2C).

Provides an abstract interface for optical character recognition. No OCR API,
no external service, and no image processing dependency is used. This stub
returns ``not_configured``.
"""

import os
from pathlib import Path

try:
    from PIL import Image
    import pytesseract
except ImportError:
    Image = None
    pytesseract = None

from app.core.config import DATA_DIR

SCREENSHOT_DIR = DATA_DIR / "screenshots"

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_WIDTH = 4096
MAX_HEIGHT = 4096
MAX_OCR_CHARS = 10000


def extract_text(image_id: str) -> dict:
    """Extract text from an image securely.

    Validates that the image_id represents a valid file within the 
    controlled screenshot directory. Implements strict limits on dimensions
    and output size. Returns untrusted text strictly as data.
    """
    if Image is None or pytesseract is None:
        return {
            "status": "failed",
            "reason": "ocr_engine_missing"
        }

    # 1. Path traversal / validation
    try:
        # Resolve to absolute path to verify boundary
        requested_path = (SCREENSHOT_DIR / f"{image_id}.jpg").resolve()
        controlled_dir = SCREENSHOT_DIR.resolve()
        
        # Verify it is within the controlled directory
        if not str(requested_path).startswith(str(controlled_dir)):
            return {"status": "failed", "reason": "path_traversal_blocked"}
    except Exception:
        return {"status": "failed", "reason": "invalid_path"}

    # 2. File exists and is regular file
    if not requested_path.is_file():
        return {"status": "failed", "reason": "file_not_found"}

    # 3. Size limit
    try:
        file_size = requested_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return {"status": "failed", "reason": "file_too_large"}
    except Exception:
        return {"status": "failed", "reason": "file_read_error"}

    # 4. Image Validation and OCR
    try:
        # PIL Image.open does not decode the image immediately, but parses headers
        with Image.open(requested_path) as img:
            # Check format
            if img.format not in ("JPEG", "PNG"):
                return {"status": "failed", "reason": "unsupported_format"}

            # Check dimensions against decompression bombs
            if img.width > MAX_WIDTH or img.height > MAX_HEIGHT:
                return {"status": "failed", "reason": "image_too_large"}

            # Execute OCR with timeout using pytesseract
            # timeout=10 seconds (requires tesseract >= 3.05 for some timeout configs,
            # but pytesseract supports timeout parameter)
            text = pytesseract.image_to_string(img, timeout=10)

    except pytesseract.TesseractNotFoundError:
        return {"status": "failed", "reason": "ocr_engine_missing"}
    except RuntimeError as e:
        if "timeout" in str(e).lower():
            return {"status": "failed", "reason": "timeout"}
        return {"status": "failed", "reason": "ocr_error"}
    except Exception:
        # Corrupted image, decompression bomb error (PIL), etc
        return {"status": "failed", "reason": "invalid_image"}

    # 5. Output limits
    truncated = False
    if len(text) > MAX_OCR_CHARS:
        text = text[:MAX_OCR_CHARS]
        truncated = True

    return {
        "status": "completed",
        "text": text,
        "character_count": len(text),
        "truncated": truncated
    }
