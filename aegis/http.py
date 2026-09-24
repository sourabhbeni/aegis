"""Minimal HTTP session engine — stdlib only.

Reads error bodies (HTTPError) because database errors and WAF blocks
frequently arrive with 4xx/5xx statuses.
"""

from __future__ import annotations

import http.cookiejar
import time
import urllib.error
import urllib.parse
import urllib.request


class Response:
    __slots__ = ("url", "status", "headers", "body", "elapsed")

    def __init__(self, url, status, headers, body: bytes, elapsed: float):
        self.url = url
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed = elapsed

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Session:
    def __init__(self, timeout: float = 10.0, delay: float = 0.0,
                 user_agent: str = "aegis/0.1.0", cookies: str = "",
                 proxy: str = ""):
        self.timeout = timeout
        self.delay = delay
        self.ua = user_agent
        self.cookies = cookies
        handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)

    def _request(self, method: str, url: str, params=None, data=None) -> Response:
        if self.delay:
            time.sleep(self.delay)
        if params:
            qs = urllib.parse.urlencode(params)
            url = url + ("&" if "?" in url else "?") + qs
        body = None
        headers = {"User-Agent": self.ua, "Accept": "*/*"}
        if self.cookies:
            headers["Cookie"] = self.cookies
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        start = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                raw = r.read()
                return Response(url, r.status, dict(r.headers), raw,
                                time.monotonic() - start)
        except urllib.error.HTTPError as e:  # error pages carry the evidence
            try:
                raw = e.read()
            except Exception:
                raw = b""
            return Response(url, e.code, dict(e.headers or {}), raw,
                            time.monotonic() - start)
        except Exception as e:  # timeouts, DNS, refused
            return Response(url, 0, {}, str(e).encode(),
                            time.monotonic() - start)

    def get(self, url: str, params=None) -> Response:
        return self._request("GET", url, params=params)

    def post(self, url: str, data=None) -> Response:
        return self._request("POST", url, data=data)


def send_point(session: Session, point: dict, name: str, payload: str) -> Response:
    """Send one injection attempt against a single parameter of a point."""
    params = dict(point["params"])
    params[name] = payload
    if point["method"] == "POST":
        return session.post(point["url"], data=params)
    return session.get(point["url"], params=params)
