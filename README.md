# 🛡️ Aegis — Web Injection Scanner

**SQL injection + reflected XSS scanner with a WAF-evasion payload engine.**
Zero dependencies — pure Python standard library.

Aegis probes every parameter it can find (URL query strings, HTML forms,
crawled links, or a raw `--data` body) for two vulnerability classes, and
re-tests each finding through modern filter-bypass transforms so you learn
not just *whether* you're vulnerable, but *which evasions* slip past your WAF.

> ⚠️ **Authorized testing only.** Scan systems you own or have written
> permission to test. The CLI requires `--yes` to confirm this.

## Detection techniques

### SQL injection
| Technique | How it works |
|---|---|
| **Error-based** | Quote probes matched against 25+ DBMS error signatures (MySQL, MariaDB, PostgreSQL, MSSQL, Oracle, SQLite) |
| **Boolean-blind** | True/false condition pairs compared against a baseline response |
| **Time-based** | `SLEEP()` / `pg_sleep()` / `WAITFOR DELAY` payloads measured against a timing threshold |

### Reflected XSS
Context-aware probing: a unique canary is reflected through 24 payloads and
classified by sink — HTML body, attribute value, or JavaScript string. A
finding is recorded **only when the full probe survives verbatim**; encoded
reflections are correctly ignored, not flagged.

## WAF-evasion engine

SQLi payloads are mutated through 9 transforms (levels 2–3):

`randomcase` · `space2comment` (`/**/`) · `tabspace` · `newlinespace` ·
`charencode` · `doubleencode` · `versioned-comments` (`/*!50000UNION*/`) ·
`nullbyte` · `keyword-split` (`UN/**/ION`)

XSS probes include the modern bypass catalogue: spaceless vectors
(`<svg/onload=…>`), nested-tag stripping bypasses (`<scr<script>ipt>`),
case games, entity smuggling (`&#x3c;`), comment breakouts and JS-context
breakouts. When a bypass succeeds, the report names the exact evasion.

## Usage

```bash
pip install .
# or: python -m aegis

# Scan query params of a URL
aegis --url "https://target/search?q=test" --yes

# Crawl forms + links and test everything, aggressive bypasses
aegis --url "https://target/" --forms --level 3 --yes

# Test a login form's POST body, SQLi only
aegis --url "https://target/login" --data "user=admin&pass=x" \
      --techniques sqli --yes

# Keep it polite, save both report formats
aegis --url "https://target/" --forms --delay 0.5 \
      --format both --output report.html --yes
```

### Options

| Flag | Purpose |
|---|---|
| `--forms` | Extract `<form>`s and query-string links from the page and test them |
| `--data` | Raw POST body to test (`"a=1&b=2"`) |
| `--param` | Only test these comma-separated parameter names |
| `--techniques` | `sqli`, `xss`, or `all` (default) |
| `--level` | `1` core payloads · `2` +evasion transforms · `3` +aggressive catalogue |
| `--time-delay` | Seconds for time-based payloads (default 5) |
| `--cookie` / `--proxy` | Session cookie header / HTTP proxy |
| `--delay` / `--workers` | Throttle between requests / concurrency |
| `--format` / `--output` | `html`, `json`, or `both` + output path |

## Example output

```
[*] aegis 0.1.0 — testing 3 parameter(s) on https://target/ (level 2)
[+] High   sqli:error-based        GET https://target/search param=q
[+] High   xss:reflected           GET https://target/search param=q
    (1/3) GET q — 2 finding(s)
[*] Done: 2 finding(s) across 3 point(s).
[*] HTML report → report.html
```

See [`examples/sample-report.html`](examples/sample-report.html) for a full report.

## Project layout

```
aegis/
  cli.py       argument parsing + orchestration
  http.py      stdlib HTTP engine (reads error bodies, measures timing)
  sqli.py      payloads, DBMS signatures, 9 evasion transforms, detectors
  xss.py       24 context-typed probes, verbatim-reflection verifier
  crawler.py   form + link extraction, injection-point builder
  report.py    JSON + self-contained HTML reports
tests/         mock vulnerable app (error/boolean/time XSS sinks) — 10 tests
```

## Tests

```bash
python -m pytest tests/ -q
```

## License

MIT — see [LICENSE](LICENSE).
