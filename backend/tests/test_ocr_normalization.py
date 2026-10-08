import pytest
from unittest.mock import patch, MagicMock
from app.core.ocr import extract_text

@patch("app.core.ocr.pytesseract.image_to_string")
@patch("app.core.ocr.Image")
def test_extract_text_normalization(mock_image, mock_image_to_string, tmp_path):
    """Test OCR text normalization of mojibake."""
    mock_img_instance = MagicMock()
    mock_img_instance.format = "PNG"
    mock_img_instance.width = 800
    mock_img_instance.height = 600
    mock_image.open.return_value.__enter__.return_value = mock_img_instance
    
    with patch("app.core.ocr.SCREENSHOT_DIR", tmp_path):
        image_id = "test-norm"
        test_file = tmp_path / f"{image_id}.jpg"
        test_file.write_bytes(b"dummy")

        # Test ASCII
        mock_image_to_string.return_value = "Login to continue"
        res1 = extract_text(image_id)
        assert res1["text"] == "Login to continue"

        # Test valid Unicode
        mock_image_to_string.return_value = "réservé"
        res2 = extract_text(image_id)
        assert res2["text"] == "réservé"

        # Test Mojibake
        # rÃ©servÃ© in python string literal
        mock_image_to_string.return_value = "r\u00c3\u00a9serv\u00c3\u00a9"
        res3 = extract_text(image_id)
        assert res3["text"] == "réservé"
        assert res3["character_count"] == 7
