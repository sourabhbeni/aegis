"""Form and link extraction — turns a page into injectable points."""

from __future__ import annotations

import urllib.parse
from html.parser import HTMLParser


class _FormParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            action = urllib.parse.urljoin(self.base_url, attrs.get("action", ""))
            self._current = {
                "action": action or self.base_url,
                "method": attrs.get("method", "get").upper(),
                "fields": {},
            }
        elif tag == "input" and self._current is not None:
            name = attrs.get("name")
            if name:
                self._current["fields"][name] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def extract_forms(html: str, base_url: str) -> list:
    parser = _FormParser(base_url)
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.forms


def extract_links(html: str, base_url: str) -> list:
    """Same-origin links that carry query strings."""
    base = urllib.parse.urlparse(base_url)
    found = []
    for token in html.split("href=")[1:]:
        quote = token[0] if token[:1] in ("'", '"') else None
        raw = token[1:].split(quote, 1)[0] if quote else token.split()[0].rstrip(">")
        url = urllib.parse.urljoin(base_url, raw)
        p = urllib.parse.urlparse(url)
        if p.netloc == base.netloc and p.query and url not in found:
            found.append(url)
    return found


def build_points(url: str, forms: list, extra_data: str = "") -> list:
    """Flatten URL query params, forms and --data into injection points."""
    points = []
    parsed = urllib.parse.urlparse(url)
    qparams = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    if qparams:
        clean = urllib.parse.urlunparse(parsed._replace(query=""))
        for name in qparams:
            points.append({"method": "GET", "url": clean,
                           "params": dict(qparams), "name": name})
    for form in forms:
        for name in form["fields"]:
            points.append({"method": form["method"], "url": form["action"],
                           "params": dict(form["fields"]), "name": name})
    if extra_data:
        dparams = dict(urllib.parse.parse_qsl(extra_data, keep_blank_values=True))
        if dparams:
            for name in dparams:
                points.append({"method": "POST", "url": url,
                               "params": dict(dparams), "name": name})
    return points
