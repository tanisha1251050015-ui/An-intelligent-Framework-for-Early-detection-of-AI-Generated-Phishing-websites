"""Tests for Phase 2D screenshot acquisition."""

import pytest
from unittest.mock import patch, MagicMock
import sys

# Removed global playwright mock to prevent breaking other tests

from app.collection.screenshot import capture_screenshot
from app.collection.ssrf import TargetCheck


@patch("app.collection.screenshot.check_target")
def test_screenshot_blocked_target(mock_check_target):
    """Test that a target failing SSRF is immediately blocked."""
    mock_check_target.return_value = TargetCheck(
        allowed=False, status="blocked", reason="private_target"
    )

    result = capture_screenshot("http://localhost:8080")
    assert result["status"] == "blocked"
    assert result["reason"] == "private_target"
    assert result["url"] == "http://localhost:8080"


@patch("playwright.sync_api.sync_playwright")
@patch("app.collection.screenshot.check_target")
def test_screenshot_success(mock_check_target, mock_sync_playwright):
    """Test successful screenshot capture."""
    mock_check_target.return_value = TargetCheck(
        allowed=True, status="allowed", reason=""
    )

    # Mock playwright
    mock_context = MagicMock()
    mock_browser = MagicMock()
    mock_page = MagicMock()
    mock_playwright = MagicMock()
    
    mock_sync_playwright.return_value.__enter__.return_value = mock_playwright
    mock_playwright.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    result = capture_screenshot("https://example.com")
    
    assert result["status"] == "collected"
    assert result["url"] == "https://example.com"
    assert "image_id" in result
    assert result["resolution"] == "1280x720"
    mock_page.goto.assert_called_once_with(
        "https://example.com", timeout=10000, wait_until="load"
    )
    mock_page.screenshot.assert_called_once()
    mock_browser.close.assert_called_once()


@patch("playwright.sync_api.sync_playwright")
@patch("app.collection.screenshot.check_target")
def test_screenshot_timeout(mock_check_target, mock_sync_playwright):
    """Test timeout during screenshot."""
    mock_check_target.return_value = TargetCheck(
        allowed=True, status="allowed", reason=""
    )

    mock_page = MagicMock()
    # Simulate timeout error
    mock_page.goto.side_effect = Exception("Timeout 10000ms exceeded")
    
    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page
    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context
    mock_playwright = MagicMock()
    mock_playwright.chromium.launch.return_value = mock_browser
    mock_sync_playwright.return_value.__enter__.return_value = mock_playwright

    result = capture_screenshot("https://example.com")
    
    assert result["status"] == "failed"
    assert result["reason"] == "timeout"
    assert result["url"] == "https://example.com"


@patch("playwright.sync_api.sync_playwright")
@patch("app.collection.screenshot.check_target")
def test_screenshot_route_interception_blocked(mock_check_target, mock_sync_playwright):
    """Test route interception aborts blocked targets."""
    # First call is initial URL (allowed), second is subresource (blocked)
    mock_check_target.side_effect = [
        TargetCheck(allowed=True, status="allowed", reason=""),
        TargetCheck(allowed=False, status="blocked", reason="private_target")
    ]

    mock_page = MagicMock()
    mock_route = MagicMock()
    mock_route.request.url = "http://localhost/script.js"
    mock_route.request.resource_type = "script"
    
    # Capture the handle_route function passed to page.route
    def route_side_effect(pattern, handler):
        handler(mock_route)
        
    mock_page.route.side_effect = route_side_effect
    
    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page
    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context
    mock_playwright = MagicMock()
    mock_playwright.chromium.launch.return_value = mock_browser
    mock_sync_playwright.return_value.__enter__.return_value = mock_playwright

    capture_screenshot("https://example.com")
    
    # Subresource route should be aborted due to SSRF
    mock_route.abort.assert_called_once_with("accessdenied")
    mock_route.continue_.assert_not_called()


@patch("playwright.sync_api.sync_playwright")
@patch("app.collection.screenshot.check_target")
def test_screenshot_route_interception_allowed(mock_check_target, mock_sync_playwright):
    """Test route interception continues allowed targets."""
    mock_check_target.return_value = TargetCheck(
        allowed=True, status="allowed", reason=""
    )

    mock_page = MagicMock()
    mock_route = MagicMock()
    mock_route.request.url = "https://example.com/style.css"
    mock_route.request.resource_type = "stylesheet"
    
    def route_side_effect(pattern, handler):
        handler(mock_route)
        
    mock_page.route.side_effect = route_side_effect
    
    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page
    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context
    mock_playwright = MagicMock()
    mock_playwright.chromium.launch.return_value = mock_browser
    mock_sync_playwright.return_value.__enter__.return_value = mock_playwright

    capture_screenshot("https://example.com")
    
    # Subresource route should be continued
    mock_route.continue_.assert_called_once()
    mock_route.abort.assert_not_called()
