"""JSON + self-contained HTML reports."""

from __future__ import annotations

import html
import json

SEVERITY_COLORS = {"Critical": "#ff453a", "High": "#ff9f0a",
                   "Medium": "#ffd60a", "Low": "#30d158", "Info": "#0a84ff"}


def to_json(target: str, findings: list, points: int) -> str:
    return json.dumps({
        "tool": "aegis",
        "target": target,
        "points_tested": points,
        "findings_count": len(findings),
        "findings": findings,
    }, indent=2)


def to_html(target: str, findings: list, points: int) -> str:
    esc = html.escape
    rows = []
    for f in findings:
        color = SEVERITY_COLORS.get(f.get("severity", "Info"), "#0a84ff")
        evasion = f.get("evasion")
        rows.append(
            f"<tr><td><span class='sev' style='background:{color}'>"
            f"{esc(f.get('severity', ''))}</span></td>"
            f"<td><b>{esc(f.get('type', '').upper())}</b><br>"
            f"<span class='dim'>{esc(f.get('technique', ''))}</span></td>"
            f"<td><code>{esc(f.get('method', ''))} {esc(f.get('url', ''))}</code>"
            f"<br><span class='dim'>param: <code>{esc(f.get('parameter', ''))}</code></span></td>"
            f"<td><code>{esc(f.get('payload', ''))}</code>"
            + (f"<br><span class='dim'>evasion: {esc(evasion)}</span>" if evasion else "")
            + (f"<br><span class='dim'>dbms: {esc(str(f.get('dbms', '')))}</span>" if f.get("dbms") else "")
            + (f"<br><span class='dim'>context: {esc(str(f.get('context', '')))}</span>" if f.get("context") else "")
            + "</td>"
            f"<td class='ev'><code>{esc(str(f.get('evidence', ''))[:220])}</code></td></tr>"
        )
    body = "\n".join(rows) if rows else (
        "<tr><td colspan='5' class='clean'>No injections found. "
        "The tested parameters appear to handle untrusted input safely.</td></tr>")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Aegis report — {esc(target)}</title>
<style>
body{{font-family:-apple-system,Helvetica,Arial,sans-serif;background:#0b0e14;color:#e6e9f0;margin:0;padding:40px}}
h1{{font-size:28px}} .dim{{color:#8b93a7;font-size:12px}}
table{{width:100%;border-collapse:collapse;margin-top:24px}}
th,td{{text-align:left;padding:12px;border-bottom:1px solid #1c2230;vertical-align:top;font-size:13px}}
th{{color:#8b93a7;text-transform:uppercase;font-size:11px;letter-spacing:1px}}
code{{background:#161c29;padding:2px 6px;border-radius:6px;font-size:12px;word-break:break-all}}
.sev{{color:#0b0e14;font-weight:700;font-size:11px;padding:3px 10px;border-radius:20px}}
.clean{{text-align:center;padding:40px;color:#30d158;font-size:16px}}
.summary{{display:flex;gap:16px;margin:20px 0}}
.card{{background:#121724;border:1px solid #1c2230;border-radius:12px;padding:16px 24px}}
.card b{{font-size:24px;display:block}}
.card span{{color:#8b93a7;font-size:12px}}
.warn{{background:#2a1a08;border:1px solid #7a4a12;color:#ffb86b;border-radius:12px;padding:12px 18px;font-size:13px;margin-top:24px}}
</style></head><body>
<h1>🛡️ Aegis report</h1>
<p class="dim">Target: <code>{esc(target)}</code></p>
<div class="summary">
<div class="card"><b>{len(findings)}</b><span>findings</span></div>
<div class="card"><b>{points}</b><span>points tested</span></div>
<div class="card"><b>{sum(1 for f in findings if f.get('type')=='sqli')}</b><span>SQLi</span></div>
<div class="card"><b>{sum(1 for f in findings if f.get('type')=='xss')}</b><span>XSS</span></div>
</div>
<table><tr><th>Severity</th><th>Type</th><th>Location</th><th>Payload</th><th>Evidence</th></tr>
{body}</table>
<div class="warn">⚠️ For authorized testing only. Scan systems you own or have
written permission to test. Findings should be verified manually before disclosure.</div>
</body></html>
"""
