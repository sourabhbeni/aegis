"""Aegis CLI — web injection scanner (SQLi + reflected XSS)."""

from __future__ import annotations

import argparse
import concurrent.futures
import sys
import urllib.parse

from . import __version__
from . import crawler, report, sqli, xss
from .http import Session

DISCLAIMER = (
    "Aegis tests for SQL injection and cross-site scripting.\n"
    "Only scan systems you own or have written authorization to test.\n"
    "Unauthorized testing is illegal. The authors accept no liability for misuse."
)


def build_session(args) -> Session:
    return Session(timeout=args.timeout, delay=args.delay,
                   user_agent=args.user_agent, cookies=args.cookie,
                   proxy=args.proxy)


def collect_points(session: Session, args) -> list:
    points = []
    parsed = urllib.parse.urlparse(args.url)
    if parsed.query or args.forms or not (args.data or args.param):
        # fetch the page: harvests query params, and forms/links with --forms
        resp = session.get(args.url)
        if resp.status == 0:
            print(f"[!] Could not fetch {args.url}: {resp.text[:120]}",
                  file=sys.stderr)
            sys.exit(2)
        forms = crawler.extract_forms(resp.text, args.url) if args.forms else []
        links = crawler.extract_links(resp.text, args.url) if args.forms else []
        base_points = crawler.build_points(args.url, forms, args.data or "")
        for link in links:
            base_points.extend(crawler.build_points(link, [], ""))
        points.extend(base_points)
    elif args.data:
        points.extend(crawler.build_points(args.url, [], args.data))
    if args.param:
        wanted = {p.strip() for p in args.param.split(",")}
        points = [p for p in points if p["name"] in wanted]
    # de-duplicate identical (method, url, name)
    seen, unique = set(), []
    for p in points:
        key = (p["method"], p["url"], p["name"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def scan_one(session: Session, point: dict, args) -> list:
    findings = []
    techs = [t.strip().lower() for t in args.techniques.split(",")]
    if "sqli" in techs or "all" in techs:
        findings.extend(sqli.scan_point(session, point, point["name"],
                                        level=args.level,
                                        time_delay=args.time_delay))
    if "xss" in techs or "all" in techs:
        findings.extend(xss.scan_point(session, point, point["name"],
                                       level=args.level))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="aegis",
        description="Web injection scanner — SQLi + reflected XSS with "
                    "WAF-evasion payloads. Authorized testing only.")
    ap.add_argument("--url", required=True,
                    help="Target URL, e.g. https://target/search?q=test")
    ap.add_argument("--forms", action="store_true",
                    help="Crawl the page for forms and links and test them too")
    ap.add_argument("--data", default="",
                    help='POST body to test, e.g. "user=admin&pass=x"')
    ap.add_argument("--param", default="",
                    help="Only test these comma-separated parameter names")
    ap.add_argument("--techniques", default="all",
                    help="Comma list: sqli, xss, or all (default)")
    ap.add_argument("--level", type=int, choices=[1, 2, 3], default=1,
                    help="1=core payloads, 2=+evasion transforms, "
                         "3=+aggressive bypass catalogue")
    ap.add_argument("--time-delay", type=int, default=5,
                    help="Seconds for time-based SQLi payloads (default 5)")
    ap.add_argument("--cookie", default="", help="Cookie header value")
    ap.add_argument("--proxy", default="", help="HTTP proxy URL")
    ap.add_argument("--user-agent", default="aegis/0.1.0")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--delay", type=float, default=0.15,
                    help="Delay between requests in seconds")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--output", default="",
                    help="Write report to this file (.html or .json)")
    ap.add_argument("--format", choices=["html", "json", "both"],
                    default="html")
    ap.add_argument("--yes", action="store_true",
                    help="Acknowledge the authorized-testing disclaimer")
    ap.add_argument("--version", action="version", version="aegis " + __version__)
    args = ap.parse_args(argv)

    if not args.yes:
        print(DISCLAIMER)
        print("\nRe-run with --yes to confirm you are authorized to test "
              "this target.", file=sys.stderr)
        return 2

    session = build_session(args)
    points = collect_points(session, args)
    if not points:
        print("[!] No injectable parameters found. Try --forms, --data, or a "
              "URL with a query string.", file=sys.stderr)
        return 1
    print(f"[*] aegis {__version__} — testing {len(points)} parameter(s) "
          f"on {args.url} (level {args.level})")

    findings = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.workers) as pool:
        futures = {pool.submit(scan_one, session, p, args): p for p in points}
        for i, fut in enumerate(
                concurrent.futures.as_completed(futures), 1):
            p = futures[fut]
            try:
                new = fut.result()
            except Exception as e:
                print(f"[!] error on {p['name']}: {e}", file=sys.stderr)
                continue
            findings.extend(new)
            for f in new:
                ev = f" [evasion: {f['evasion']}]" if f.get("evasion") else ""
                tag = f"{f['type']}:{f['technique']}"
                print(f"[+] {f['severity']:6} {tag:22} "
                      f"{p['method']} {p['url']} param={p['name']}{ev}")
            print(f"    ({i}/{len(points)}) {p['method']} {p['name']} "
                  f"— {len(new)} finding(s)", flush=True)

    print(f"\n[*] Done: {len(findings)} finding(s) across "
          f"{len(points)} point(s).")
    if args.output or args.format in ("json", "both"):
        if args.format in ("html", "both"):
            out = args.output if args.output.endswith(".html") \
                else (args.output or "report.html")
            with open(out, "w") as fh:
                fh.write(report.to_html(args.url, findings, len(points)))
            print(f"[*] HTML report → {out}")
        if args.format in ("json", "both"):
            out = "report.json" if not args.output else \
                args.output.replace(".html", ".json")
            with open(out, "w") as fh:
                fh.write(report.to_json(args.url, findings, len(points)))
            print(f"[*] JSON report → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
