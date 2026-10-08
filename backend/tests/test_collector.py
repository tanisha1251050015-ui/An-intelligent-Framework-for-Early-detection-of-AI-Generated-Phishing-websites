"""Tests for the Phase 2A collector.

All HTTP is served by httpx.MockTransport and all DNS is faked, so these tests
never touch real websites or real DNS.
"""

import socket

import httpx
import pytest

from app.collection.collector import collect

HTML_PAGE = b"""<!doctype html>
<html>
  <head><title>  Welcome   Page  </title></head>
  <body>
    <a href="/1">one</a><a href="/2">two</a>
    <form action="/login">
      <input type="text" name="u">
      <input type="password" name="p">
    </form>
    <script>var x = 1;</script>
    <input type="submit">
  </body>
</html>
"""


@pytest.fixture(autouse=True)
def fake_public_dns(monkeypatch):
    """All hostnames resolve to a public address; no real DNS is used."""

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr("app.collection.ssrf.socket.getaddrinfo", fake_getaddrinfo)


def make_client(handler) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        max_redirects=5,
        timeout=5.0,
    )


def test_collect_html_evidence():
    def handler(request):
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=HTML_PAGE,
        )

    evidence = collect("https://example.com/", client=make_client(handler))

    assert evidence["status"] == "collected"
    assert evidence["http_status"] == 200
    assert evidence["content_type"] == "text/html; charset=utf-8"
    assert evidence["response_size"] == len(HTML_PAGE)
    assert evidence["truncated"] is False
    assert evidence["redirect_count"] == 0
    assert evidence["redirects"] == []
    assert evidence["response_time_ms"] >= 0
    assert evidence["html"]["title"] == "Welcome Page"
    assert evidence["html"]["link_count"] == 2
    assert evidence["html"]["form_count"] == 1
    assert evidence["html"]["script_count"] == 1
    assert evidence["html"]["input_count"] == 3
    assert evidence["html"]["password_input_count"] == 1
    assert evidence["html"]["visible_text"]
    assert evidence["html"]["text"] == evidence["html"]["visible_text"]
    assert evidence["html"]["text_length"] == len(evidence["html"]["visible_text"])


def test_html_extraction_is_bounded_and_captures_security_structure():
    page = (b"<title>Sign in</title><body>" + b"A" * 10000 +
            b"<form action='https://outside.test/collect' method='post'>"
            b"<input type='password'><input type='hidden'><textarea></textarea></form>"
            b"<iframe src='https://frame.test'></iframe>"
            b"<script src='https://cdn.test/a.js'></script><script>inline()</script></body>")
    evidence = collect("https://example.com/", client=make_client(lambda request: httpx.Response(
        200, headers={"content-type": "text/html"}, content=page
    )))
    html = evidence["html"]
    assert len(html["visible_text"]) <= 8000
    assert html["password_input_count"] == 1
    assert html["hidden_input_count"] == 1
    assert html["textarea_count"] == 1
    assert html["iframe_count"] == 1
    assert html["external_form_domains"] == ["outside.test"]
    assert html["external_script_domains"] == ["cdn.test"]
    assert html["inline_script_count"] == 1


def test_private_target_never_contacts_network():
    def handler(request):
        raise AssertionError("the network must never be contacted")

    evidence = collect("http://192.168.1.1/login", client=make_client(handler))
    assert evidence == {"status": "blocked", "reason": "private_or_local_target"}


def test_localhost_target_never_contacts_network():
    def handler(request):
        raise AssertionError("the network must never be contacted")

    evidence = collect("http://localhost/", client=make_client(handler))
    assert evidence["status"] == "blocked"
    assert evidence["reason"] == "private_or_local_target"


def test_http_error_status_is_recorded():
    def handler(request):
        return httpx.Response(404, content=b"not found")

    evidence = collect("https://example.com/missing", client=make_client(handler))
    assert evidence["status"] == "collected"
    assert evidence["http_status"] == 404


def test_non_html_content_type_has_no_html_stats():
    def handler(request):
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'{"ok": true}',
        )

    evidence = collect("https://example.com/data.json", client=make_client(handler))
    assert evidence["status"] == "collected"
    assert evidence["html"] is None


def test_redirect_chain_recorded():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(
                302, headers={"location": "https://example.com/final"}
            )
        return httpx.Response(200, content=b"ok")

    evidence = collect("https://example.com/start", client=make_client(handler))
    assert evidence["status"] == "collected"
    assert evidence["redirect_count"] == 1
    assert evidence["redirects"] == ["https://example.com/final"]
    assert evidence["final_url"] == "https://example.com/final"


def test_response_size_limit_truncates():
    def handler(request):
        return httpx.Response(200, content=b"x" * 1000)

    evidence = collect(
        "https://example.com/big", client=make_client(handler), max_bytes=100
    )
    assert evidence["response_size"] == 100
    assert evidence["truncated"] is True


def test_timeout_is_error():
    def handler(request):
        raise httpx.ReadTimeout("timed out")

    evidence = collect("https://example.com/", client=make_client(handler))
    assert evidence == {"status": "error", "reason": "request_timeout"}


def test_too_many_redirects_is_error():
    def handler(request):
        return httpx.Response(302, headers={"location": str(request.url)})

    evidence = collect("https://example.com/a", client=make_client(handler))
    assert evidence == {"status": "error", "reason": "too_many_redirects"}


def test_connection_error_is_error():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    evidence = collect("https://example.com/", client=make_client(handler))
    assert evidence == {"status": "error", "reason": "request_failed"}


def test_userinfo_is_stripped_before_request():
    seen: list[str] = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, content=b"ok")

    collect("https://user:secret@example.com/", client=make_client(handler))
    assert seen == ["https://example.com/"]


def test_redirect_to_localhost_blocked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://localhost/admin"})

    evidence = collect("https://example.com/start", client=make_client(handler))
    assert evidence["status"] == "blocked"
    assert evidence["reason"] == "private_or_local_target"


def test_redirect_to_private_blocked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    evidence = collect("https://example.com/start", client=make_client(handler))
    assert evidence["status"] == "blocked"
    assert evidence["reason"] == "private_or_local_target"


def test_redirect_to_link_local_blocked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    evidence = collect("https://example.com/start", client=make_client(handler))
    assert evidence["status"] == "blocked"


def test_redirect_chain_to_private_blocked():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://example.com/next"})
        if request.url.path == "/next":
            return httpx.Response(302, headers={"location": "http://192.168.1.1/"})
        return httpx.Response(200, content=b"ok")

    evidence = collect("https://example.com/start", client=make_client(handler))
    assert evidence["status"] == "blocked"
    assert evidence["reason"] == "private_or_local_target"
