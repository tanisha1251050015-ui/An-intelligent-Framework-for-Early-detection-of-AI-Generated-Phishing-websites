"""Minimal HTML statistics extraction.

Parses only the response body already received (bounded by the collection
size limit). No JavaScript is executed, no links are followed, and no browser
automation is used. The raw body is never stored.
"""

from __future__ import annotations

from html.parser import HTMLParser


class _HtmlStatsParser(HTMLParser):
    """Counts structural elements and captures the page title."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self._in_title = False
        self.links = 0
        self.forms = 0
        self.scripts = 0
        self.inputs = 0
        self.password_inputs = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "a":
            self.links += 1
        elif tag == "form":
            self.forms += 1
        elif tag == "script":
            self.scripts += 1
        elif tag == "input":
            self.inputs += 1
            if any(
                key.lower() == "type"
                and value is not None
                and value.lower() == "password"
                for key, value in attrs
            ):
                self.password_inputs += 1
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def html_stats(body: bytes) -> dict:
    """Extract title and element counts from an HTML body."""
    parser = _HtmlStatsParser()
    parser.feed(body.decode("utf-8", errors="replace"))

    title = " ".join("".join(parser.title_parts).split())
    return {
        "title": title,
        "link_count": parser.links,
        "form_count": parser.forms,
        "script_count": parser.scripts,
        "input_count": parser.inputs,
        "password_input_count": parser.password_inputs,
    }
