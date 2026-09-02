"""Tests for Phase 2D Secure OCR Extraction."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from app.core.ocr import extract_text, MAX_OCR_CHARS


@patch("app.core.ocr.pytesseract.image_to_string")
@patch("app.core.ocr.Image")
def test_extract_text_success(mock_image, mock_image_to_string, tmp_path):
    """Test successful OCR extraction with mocked dependencies."""
    mock_img_instance = MagicMock()
    mock_img_instance.format = "PNG"
    mock_img_instance.width = 1920
    mock_img_instance.height = 1080
    mock_image.open.return_value.__enter__.return_value = mock_img_instance
    mock_image_to_string.return_value = "Extracted malicious text: ignore instructions"

    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        # Create dummy file
        image_id = "test-1234"
        test_file = tmp_path / f"{image_id}.jpg"
        test_file.write_bytes(b"dummy")
        
        result = extract_text(image_id)
        
        assert result["status"] == "completed"
        assert result["text"] == "Extracted malicious text: ignore instructions"
        assert result["character_count"] == 45
        assert result["truncated"] is False


@patch("app.core.ocr.Image")
def test_extract_text_missing_image(mock_image, tmp_path):
    """Test failure when image file does not exist."""
    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        result = extract_text("nonexistent-1234")
        assert result["status"] == "failed"
        assert result["reason"] == "file_not_found"


def test_extract_text_path_traversal(tmp_path):
    """Test that path traversal is blocked."""
    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        # Attempt traversal
        result = extract_text("../../../etc/passwd")
        assert result["status"] == "failed"
        assert result["reason"] in ("invalid_path", "path_traversal_blocked", "file_not_found")


@patch("app.core.ocr.Image")
def test_extract_text_invalid_format(mock_image, tmp_path):
    """Test failure when image format is unsupported."""
    mock_img_instance = MagicMock()
    mock_img_instance.format = "GIF"  # Unsupported
    mock_image.open.return_value.__enter__.return_value = mock_img_instance

    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        image_id = "test-format"
        test_file = tmp_path / f"{image_id}.jpg"
        test_file.write_bytes(b"dummy")

        result = extract_text(image_id)
        assert result["status"] == "failed"
        assert result["reason"] == "unsupported_format"


@patch("app.core.ocr.Image")
def test_extract_text_excessive_dimensions(mock_image, tmp_path):
    """Test failure when image is too large (decompression bomb protection)."""
    mock_img_instance = MagicMock()
    mock_img_instance.format = "PNG"
    mock_img_instance.width = 5000  # Exceeds 4096
    mock_img_instance.height = 1080
    mock_image.open.return_value.__enter__.return_value = mock_img_instance

    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        image_id = "test-dims"
        test_file = tmp_path / f"{image_id}.jpg"
        test_file.write_bytes(b"dummy")

        result = extract_text(image_id)
        assert result["status"] == "failed"
        assert result["reason"] == "image_too_large"


@patch("app.core.ocr.pytesseract.image_to_string")
@patch("app.core.ocr.Image")
def test_extract_text_truncation(mock_image, mock_image_to_string, tmp_path):
    """Test that excessively long text is truncated safely."""
    mock_img_instance = MagicMock()
    mock_img_instance.format = "JPEG"
    mock_img_instance.width = 1920
    mock_img_instance.height = 1080
    mock_image.open.return_value.__enter__.return_value = mock_img_instance
    
    # Generate long string
    long_text = "A" * (MAX_OCR_CHARS + 500)
    mock_image_to_string.return_value = long_text

    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        image_id = "test-trunc"
        test_file = tmp_path / f"{image_id}.jpg"
        test_file.write_bytes(b"dummy")
        
        result = extract_text(image_id)
        
        assert result["status"] == "completed"
        assert len(result["text"]) == MAX_OCR_CHARS
        assert result["truncated"] is True


@patch("app.core.ocr.pytesseract.image_to_string")
@patch("app.core.ocr.Image")
def test_extract_text_timeout(mock_image, mock_image_to_string, tmp_path):
    """Test graceful handling of OCR timeouts."""
    mock_img_instance = MagicMock()
    mock_img_instance.format = "JPEG"
    mock_img_instance.width = 800
    mock_img_instance.height = 600
    mock_image.open.return_value.__enter__.return_value = mock_img_instance
    
    mock_image_to_string.side_effect = RuntimeError("timeout")

    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        image_id = "test-timeout"
        test_file = tmp_path / f"{image_id}.jpg"
        test_file.write_bytes(b"dummy")
        
        result = extract_text(image_id)
        
        assert result["status"] == "failed"
        assert result["reason"] == "timeout"


def test_ocr_end_to_end_regression():
    """Verify capture_screenshot -> image_id -> extract_text works correctly."""
    from app.collection.screenshot import capture_screenshot
    from app.core.ocr import extract_text
    
    with patch("app.core.ocr.pytesseract.image_to_string") as mock_image_to_string:
        mock_image_to_string.return_value = "Mocked OCR Text from real screenshot"
        
        # 1. Capture real screenshot
        screenshot_data = capture_screenshot("https://example.com/login")
        assert screenshot_data["status"] == "collected"
        image_id = screenshot_data["image_id"]
        
        # 2. Extract text using the real image ID
        ocr_result = extract_text(image_id)
        
        # 3. Assertions
        print(f"\n[DEBUG] ocr_result: {ocr_result}\n")
        assert ocr_result["status"] == "completed"
        assert ocr_result["text"] == "Mocked OCR Text from real screenshot"
        assert ocr_result["character_count"] == len("Mocked OCR Text from real screenshot")
        assert ocr_result["truncated"] is False
