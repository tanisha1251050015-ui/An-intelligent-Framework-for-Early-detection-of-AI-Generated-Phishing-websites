"""Bounded extraction of useful, non-executable HTML evidence."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

MAX_TEXT_CHARS = 8_000
MAX_URLS = 50
MAX_URL_LENGTH = 2_048
_HIDDEN_CONTAINERS = {"head", "script", "style", "noscript", "template", "svg"}

LOGIN_REGEX = re.compile(r"\b(login|log in|signin|sign in|sign-in|username)\b", re.IGNORECASE)
PAYMENT_REGEX = re.compile(r"\b(payment|pay|billing|invoice|card|credit card|debit card|bank|transaction)\b", re.IGNORECASE)
URGENCY_REGEX = re.compile(r"\b(urgent|immediately|suspended|suspend|expire|expired|warning|alert|action required)\b", re.IGNORECASE)
VERIFICATION_REGEX = re.compile(r"\b(verify|verification|confirm|confirmation|authenticate|authentication|identity|security check)\b", re.IGNORECASE)


class _HtmlEvidenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self._in_title = False
        self._hidden_depth = 0
        self.link_count = 0
        self.form_actions: list[str] = []
        self.form_methods: list[str] = []
        self.script_sources: list[str] = []
        self.external_script_count = 0
        self.form_count = self.script_count = self.input_count = 0
        self.password_input_count = self.hidden_input_count = 0
        self.email_input_count = self.username_input_count = self.credential_input_count = 0
        self.textarea_count = self.iframe_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {key.lower(): value for key, value in attrs if value is not None}
        if tag in _HIDDEN_CONTAINERS:
            self._hidden_depth += 1
        if tag == "title":
            self._in_title = True
        elif tag == "a":
            self.link_count += 1
        elif tag == "form":
            self.form_count += 1
            if len(self.form_actions) < MAX_URLS:
                self.form_actions.append(values.get("action", ""))
                self.form_methods.append(values.get("method", "get").lower()[:20])
        elif tag == "script":
            self.script_count += 1
            src = values.get("src")
            if src:
                self.external_script_count += 1
                if len(self.script_sources) < MAX_URLS:
                    self.script_sources.append(src[:MAX_URL_LENGTH])
        elif tag == "input":
            self.input_count += 1
            input_type = values.get("type", "text").lower()
            name = values.get("name", "").lower()
            id_attr = values.get("id", "").lower()
            placeholder = values.get("placeholder", "").lower()

            is_password = input_type == "password"
            self.password_input_count += is_password
            
            is_email = input_type == "email" or any(k in v for k in ("email", "e-mail", "mail") for v in (name, id_attr, placeholder))
            self.email_input_count += is_email
            
            is_username = not is_email and not is_password and any(k in v for k in ("username", "user", "login") for v in (name, id_attr, placeholder))
            self.username_input_count += is_username
            
            self.credential_input_count += bool(is_password or is_email or is_username)
            self.hidden_input_count += input_type == "hidden"
        elif tag == "textarea":
            self.textarea_count += 1
        elif tag == "iframe":
            self.iframe_count += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag in _HIDDEN_CONTAINERS:
            self._hidden_depth = max(0, self._hidden_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if not self._hidden_depth and not self._in_title and len(" ".join(self.text_parts)) < MAX_TEXT_CHARS:
            self.text_parts.append(data)


def _absolute_urls(values: list[str], base_url: str) -> list[str]:
    result = []
    for value in values:
        try:
            absolute = urljoin(base_url, value)[:MAX_URL_LENGTH]
        except ValueError:
            continue
        if absolute and absolute not in result:
            result.append(absolute)
    return result


def _external_domains(urls: list[str], base_url: str) -> list[str]:
    try:
        base_host = (urlsplit(base_url).hostname or "").lower().rstrip(".")
    except ValueError:
        base_host = ""
    domains = []
    for url in urls:
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme in {"http", "https"} and host and host != base_host and host not in domains:
            domains.append(host)
    return domains[:MAX_URLS]


def html_stats(body: bytes, base_url: str = "") -> dict:
    """Return bounded HTML text and structure; raw markup is never retained."""
    parser = _HtmlEvidenceParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    parser.close()
    title = " ".join("".join(parser.title_parts).split())[:500]
    visible_text = " ".join(" ".join(parser.text_parts).split())[:MAX_TEXT_CHARS]
    form_actions = _absolute_urls(parser.form_actions, base_url)
    script_urls = _absolute_urls(parser.script_sources, base_url)
    base_host = ""
    try:
        base_host = (urlsplit(base_url).hostname or "").lower().rstrip(".")
    except ValueError:
        pass
    external_form_actions = []
    for action in form_actions:
        try:
            action_host = (urlsplit(action).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if action_host and action_host != base_host:
            external_form_actions.append(action)
    return {
        "title": title,
        "text": visible_text,
        "visible_text": visible_text,
        "text_length": len(visible_text),
        "link_count": parser.link_count,
        "form_count": parser.form_count,
        "form_actions": form_actions,
        "form_methods": parser.form_methods,
        "external_form_actions": external_form_actions[:MAX_URLS],
        "external_form_domains": _external_domains(form_actions, base_url),
        "script_count": parser.script_count,
        "inline_script_count": max(0, parser.script_count - parser.external_script_count),
        "external_script_count": parser.external_script_count,
        "external_script_urls": script_urls,
        "external_script_domains": _external_domains(script_urls, base_url),
        "input_count": parser.input_count,
        "email_input_count": parser.email_input_count,
        "username_input_count": parser.username_input_count,
        "credential_input_count": parser.credential_input_count,
        "password_input_count": parser.password_input_count,
        "hidden_input_count": parser.hidden_input_count,
        "textarea_count": parser.textarea_count,
        "iframe_count": parser.iframe_count,
        "login_keyword_count": len(LOGIN_REGEX.findall(visible_text)),
        "payment_keyword_count": len(PAYMENT_REGEX.findall(visible_text)),
        "urgency_keyword_count": len(URGENCY_REGEX.findall(visible_text)),
        "verification_keyword_count": len(VERIFICATION_REGEX.findall(visible_text)),
        "external_form_action_count": len(external_form_actions[:MAX_URLS]),
    }
