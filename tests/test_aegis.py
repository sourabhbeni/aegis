"""Offline tests — a mock app simulates vulnerable and clean endpoints."""

import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis import crawler, sqli, xss
from aegis.http import Session


class Handler(BaseHTTPRequestHandler):
    def _params(self):
        if self.command == "GET":
            qs = urllib.parse.urlparse(self.path).query
        else:
            length = int(self.headers.get("Content-Length", 0))
            qs = self.rfile.read(length).decode()
        return dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))

    def _send(self, body, status=200):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        path = urllib.parse.urlparse(self.path).path
        p = self._params()
        if path == "/sqli_error":
            q = p.get("q", "")
            if "'" in q or '"' in q:
                self._send("Warning: mysql_fetch_array(): You have an error "
                           "in your SQL syntax near '''", status=500)
            else:
                self._send(f"<h1>Results for {q}</h1>")
        elif path == "/sqli_bool":
            q = p.get("q", "")
            if "1'='1" in q or "1=1" in q:
                self._send("<h1>Welcome back, admin. Showing 42 rows.</h1>")
            elif "1'='2" in q or "1=2" in q:
                self._send("<h1>No results found.</h1>")
            else:
                self._send("<h1>Welcome back, admin. Showing 42 rows.</h1>")
        elif path == "/sqli_time":
            q = p.get("q", "")
            if "SLEEP" in q.upper() or "PG_SLEEP" in q.upper():
                time.sleep(2)
            self._send("<h1>done</h1>")
        elif path == "/xss":
            q = p.get("q", "")
            self._send(f"<html><body><p>You searched for: {q}</p></body></html>")
        elif path == "/xss_attr":
            q = p.get("q", "")
            self._send(f'<html><body><input value="{q}"></body></html>')
        elif path == "/xss_encoded":
            import html as h
            q = h.escape(p.get("q", ""))
            self._send(f"<html><body><p>You searched for: {q}</p></body></html>")
        elif path == "/clean":
            self._send("<h1>Hello, static world</h1>")
        elif path == "/page":
            self._send("""<html><body>
                <form action="/sqli_error" method="get">
                  <input name="q" value=""><input type="submit">
                </form>
                <a href="/xss?q=hi">link</a>
                </body></html>""")
        else:
            self._send("not found", status=404)

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def session():
    return Session(timeout=10)


def point(url, name, method="GET"):
    return {"method": method, "url": url, "params": {"q": "x"}, "name": name}


# --- SQLi ------------------------------------------------------------------
def test_error_based_mysql(base, session):
    f = sqli.scan_point(session, point(base + "/sqli_error", "q"), "q")
    assert any(x["technique"] == "error-based" and x["dbms"] == "MySQL"
               for x in f), f


def test_boolean_blind(base, session):
    f = sqli.scan_point(session, point(base + "/sqli_bool", "q"), "q")
    assert any(x["technique"] == "boolean-blind" for x in f), f


def test_time_based(base, session):
    f = sqli.scan_point(session, point(base + "/sqli_time", "q"), "q",
                        time_delay=2)
    assert any(x["technique"] == "time-based" for x in f), f


def test_clean_page_no_sqli(base, session):
    f = sqli.scan_point(session, point(base + "/clean", "q"), "q",
                        time_delay=2)
    assert f == [], f


def test_evasion_transforms_expand():
    # long keyword-rich payload: randomcase is ~never a no-op on this
    payloads = list(sqli.expand(["' OR 1=1 UNION SELECT * FROM users-- -"],
                                level=3))
    names = {t for _, t in payloads}
    assert None in names  # base payload kept
    assert {"randomcase", "space2comment", "keyword-split",
            "doubleencode"} <= names
    assert len(payloads) == len({p for p, _ in payloads})  # deduped


# --- XSS -------------------------------------------------------------------
def test_reflected_xss_html(base, session):
    f = xss.scan_point(session, point(base + "/xss", "q"), "q")
    assert any(x["type"] == "xss" and x["context"] == "html" for x in f), f


def test_reflected_xss_attribute(base, session):
    f = xss.scan_point(session, point(base + "/xss_attr", "q"), "q")
    assert any(x["type"] == "xss" and x["context"] == "attribute"
               for x in f), f


def test_encoded_reflection_not_flagged(base, session):
    f = xss.scan_point(session, point(base + "/xss_encoded", "q"), "q")
    assert f == [], f


def test_clean_page_no_xss(base, session):
    f = xss.scan_point(session, point(base + "/clean", "q"), "q")
    assert f == [], f


# --- crawler ---------------------------------------------------------------
def test_crawler_extracts_forms_and_links(base, session):
    resp = session.get(base + "/page")
    forms = crawler.extract_forms(resp.text, base + "/page")
    assert forms and forms[0]["fields"] == {"q": ""}
    links = crawler.extract_links(resp.text, base + "/page")
    assert any("/xss?q=hi" in link for link in links)
    points = crawler.build_points(base + "/page?q=1", forms)
    names = {(p["method"], p["name"]) for p in points}
    assert ("GET", "q") in names
