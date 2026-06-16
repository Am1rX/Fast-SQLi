"""
Fast-SQLi — SQL injection heuristic scanner
https://github.com/Am1rX/Fast-SQLi

USE ON SYSTEMS YOU OWN OR HAVE EXPLICIT WRITTEN PERMISSION TO TEST.
The developer assumes no liability for misuse or damages.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import html
import sys
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
DEFAULT_THREADS = 10
TIMEOUT = 10                  # seconds per HTTP request
PAUSE_BETWEEN_REQUESTS = 0.35 # polite pause between payload and baseline
MAX_RETRIES = 2               # retry on connection errors (not 4xx/5xx)
OUTPUT_CSV = "scan-report.csv"
OUTPUT_HTML = "sql-report.html"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
}

# SQL error signatures (case-insensitive match)
SQL_ERROR_SIGNATURES: list[str] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "supplied argument is not a valid mysql",
    "mysql_fetch_assoc()",
    "mysql_num_rows()",
    "ORA-00933",
    "ORA-01756",
    "SQLSTATE[",
    "SQLite.Exception",
    "syntax error near",
    "unterminated quoted string",
    "mysqlnd::",
]

# Payload pairs: plain quote, then quote+comment
PAYLOADS: list[dict] = [
    {"label": "single-quote",         "inj": "'",      "method": "single"},
    {"label": "single-quote-comment", "inj": "' -- ",  "method": "single"},
    {"label": "double-quote",         "inj": '"',      "method": "double"},
    {"label": "double-quote-comment", "inj": '" -- ',  "method": "double"},
]

# ──────────────────────────────────────────────
# ANSI colours
# ──────────────────────────────────────────────
BOLD_WHITE = "\x1b[97;1m"
GREEN      = "\x1b[32m"
YELLOW     = "\x1b[33m"
RED        = "\x1b[31m"
RESET      = "\x1b[0m"

def _c(colour: str, msg: str) -> str:
    return f"{colour}{msg}{RESET}"

def info(msg: str)     -> None: print(_c(BOLD_WHITE, f"[i] {msg}"))
def found(msg: str)    -> None: print(_c(GREEN,      f"[+] {msg}"))
def warn(msg: str)     -> None: print(_c(YELLOW,     f"[!] {msg}"))
def error(msg: str)    -> None: print(_c(RED,        f"[-] {msg}"))


# ──────────────────────────────────────────────
# HTTP SESSION (shared, thread-safe)
# ──────────────────────────────────────────────
def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=0.4,
        status_forcelist=[],          # don't retry on HTTP errors, only network errors
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(HEADERS)
    return session

_SESSION = _build_session()
_CSV_LOCK = Lock()


# ──────────────────────────────────────────────
# URL HELPERS  (bug-fixed)
# ──────────────────────────────────────────────
def parse_url(url: str) -> tuple[object, dict[str, list[str]]]:
    """Return (ParseResult, {param: [value, ...]})."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, qs


def build_url(parsed, qs: dict[str, list[str]]) -> str:
    """
    Rebuild URL from a ParseResult and a {param: [value]} dict.
    Uses only the FIRST value per param (consistent with parse_qs output).
    Bug-fix: original code had double-list wrapping issues here.
    """
    flat = {k: v[0] if isinstance(v, list) else v for k, v in qs.items()}
    query = urlencode(flat)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, query, parsed.fragment,
    ))


# ──────────────────────────────────────────────
# DETECTION HELPERS
# ──────────────────────────────────────────────
def has_sql_error(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    return any(sig.lower() in lower for sig in SQL_ERROR_SIGNATURES)


def content_diff(base: str, test: str) -> tuple[int, float]:
    """Return (absolute_byte_diff, relative_diff_ratio)."""
    lb, lt = len(base), len(test)
    diff = abs(lb - lt)
    ratio = diff / lb if lb else (1.0 if diff else 0.0)
    return diff, ratio


def is_ssl_error(exc: Exception) -> bool:
    """Detect SSL certificate verification failures robustly."""
    if isinstance(exc, requests.exceptions.SSLError):
        return True
    msg = str(exc).lower()
    return "certificate verify failed" in msg or ("ssl" in msg and "cert" in msg)


# ──────────────────────────────────────────────
# HTTP REQUEST
# ──────────────────────────────────────────────
def get(url: str, timeout: int = TIMEOUT) -> requests.Response | Exception:
    try:
        return _SESSION.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return exc


# ──────────────────────────────────────────────
# SINGLE PAYLOAD TEST  (rewritten, all bugs fixed)
# ──────────────────────────────────────────────
_CONTENT_DIFF_THRESHOLD = 0.005   # 0.5% relative change needed (was 0.2% → too noisy)
_CONTENT_ABS_THRESHOLD  = 50      # at least 50 bytes absolute

Finding = dict  # typed alias for readability


def test_payload(
    parsed,
    qs: dict[str, list[str]],
    param: str,
    payload: dict,
    timeout: int,
) -> Finding | None | dict:
    """
    Returns:
      None            → no anomaly
      Finding dict    → anomaly detected
      {'__ssl__': ..} → SSL cert error, caller should abort this URL
      {'__err__': ..} → generic request error
    """
    base_value = qs[param][0] if qs[param] else ""

    # ── baseline request ──────────────────────
    base_qs  = {k: [v[0]] for k, v in qs.items()}
    base_url = build_url(parsed, base_qs)

    r_base = get(base_url, timeout)
    if isinstance(r_base, Exception):
        if is_ssl_error(r_base):
            return {"__ssl__": str(r_base)}
        return {"__err__": str(r_base), "param": param, "payload": payload["label"]}

    base_text   = r_base.text
    base_status = r_base.status_code

    # ── payload request ───────────────────────
    test_qs = {k: [v[0]] for k, v in qs.items()}
    test_qs[param] = [base_value + payload["inj"]]   # Bug-fix: was double-wrapped list
    test_url = build_url(parsed, test_qs)

    time.sleep(PAUSE_BETWEEN_REQUESTS)
    r_test = get(test_url, timeout)
    if isinstance(r_test, Exception):
        if is_ssl_error(r_test):
            return {"__ssl__": str(r_test)}
        return {"__err__": str(r_test), "param": param, "payload": payload["label"]}

    test_text   = r_test.text
    test_status = r_test.status_code

    # ── anomaly detection ─────────────────────
    abs_diff, rel_diff = content_diff(base_text, test_text)
    evidence: list[str] = []
    issue: str | None = None

    if has_sql_error(test_text):
        evidence.append("SQL error signature in response")
        issue = "error-signature"

    if test_status != base_status:
        evidence.append(f"HTTP {base_status} → {test_status}")
        issue = issue or "status-diff"

    if abs_diff >= _CONTENT_ABS_THRESHOLD and rel_diff >= _CONTENT_DIFF_THRESHOLD:
        evidence.append(f"response size {len(base_text)} → {len(test_text)} bytes ({rel_diff:.1%})")
        issue = issue or "content-diff"

    if issue:
        return {
            "param":      param,
            "payload":    payload["label"],
            "method":     payload["method"],
            "issue":      issue,
            "note":       "; ".join(evidence),
            "abs_change": abs_diff,
            "rel_change": rel_diff,
        }
    return None


# ──────────────────────────────────────────────
# PARAM SCANNER  (rewritten)
# ──────────────────────────────────────────────
def scan_param(
    parsed,
    qs: dict[str, list[str]],
    param: str,
    timeout: int,
) -> tuple[list[Finding], str | None]:
    """
    Returns (findings, ssl_error_or_None).
    Strategy: try single-quote payloads first; if they fire, skip double.
    This halves requests for obviously-vulnerable params.
    """
    findings: list[Finding] = []
    ssl_err: str | None = None

    for payload in PAYLOADS:
        result = test_payload(parsed, qs, param, payload, timeout)

        if result is None:
            continue
        if "__ssl__" in result:
            return [], result["__ssl__"]
        if "__err__" in result:
            # request error: log as a warning finding, keep scanning
            findings.append({
                "param": param, "payload": payload["label"],
                "method": payload["method"], "issue": "request-error",
                "note": result["__err__"], "abs_change": 0, "rel_change": 0.0,
            })
            continue

        findings.append(result)

        # Early-exit: if single-quote payloads already fired, skip double
        if payload["method"] == "single" and len(findings) >= 2:
            break

    return findings, None


# ──────────────────────────────────────────────
# CSV  (thread-safe with lock)
# ──────────────────────────────────────────────
def write_csv_header(path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow([
            "url", "param", "payload", "method",
            "issue", "note", "abs_change", "rel_change",
        ])


def append_csv_rows(path: str, url: str, findings: list[Finding]) -> None:
    with _CSV_LOCK:                           # Bug-fix: thread-safe writes
        with open(path, "a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            for f in findings:
                w.writerow([
                    url, f.get("param"), f.get("payload"), f.get("method"),
                    f.get("issue"), f.get("note"),
                    f.get("abs_change", 0), f.get("rel_change", 0.0),
                ])


# ──────────────────────────────────────────────
# URL WORKFLOW
# ──────────────────────────────────────────────
ScanResult = dict  # {url, findings?, error?, details?}


def scan_url(url: str, timeout: int, csv_path: str) -> ScanResult:
    parsed, qs = parse_url(url)
    if not qs:
        return {"url": url, "error": "no-params"}

    all_findings: list[Finding] = []

    for param in qs:
        findings, ssl_err = scan_param(parsed, qs, param, timeout)
        if ssl_err:
            return {"url": url, "error": "ssl-cert", "details": ssl_err}
        all_findings.extend(findings)

    if all_findings:
        append_csv_rows(csv_path, url, all_findings)

    return {"url": url, "findings": all_findings}


# ──────────────────────────────────────────────
# HTML REPORT  (improved escaping + layout)
# ──────────────────────────────────────────────
def generate_html_report(
    results: OrderedDict,
    elapsed: float,
    html_path: str,
) -> str | None:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total_urls = len(results)
    rows_html  = ""
    total_findings = 0
    method_counts: dict[str, int] = {}

    for url, res in results.items():
        if not res or res.get("error"):
            continue
        for f in res.get("findings", []):
            if f.get("issue") == "request-error":
                continue                        # don't count errors as findings
            total_findings += 1
            m = f.get("method", "?")
            method_counts[m] = method_counts.get(m, 0) + 1
            esc = html.escape
            rows_html += (
                f"<tr>"
                f"<td>{esc(url)}</td>"
                f"<td><code>{esc(f.get('param',''))}</code></td>"
                f"<td>{esc(f.get('issue',''))}</td>"
                f"<td>{esc(m)}</td>"
                f"<td>{esc(f.get('note',''))}</td>"
                f"</tr>"
            )

    skipped = sum(1 for r in results.values() if r and r.get("error") == "ssl-cert")
    no_params = sum(1 for r in results.values() if r and r.get("error") == "no-params")

    badge_html = " ".join(
        f'<span class="badge">{html.escape(k)}: {v}</span>'
        for k, v in method_counts.items()
    ) or "—"

    table_html = (
        "<table>"
        "<thead><tr><th>URL</th><th>Param</th><th>Issue</th><th>Method</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rows_html}</tbody></table>"
        if rows_html
        else "<p class='none'>No vulnerabilities found.</p>"
    )

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fast-SQLi Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
a{{color:#58a6ff}}
.wrap{{max-width:1200px;margin:0 auto;padding:32px 16px}}
header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;border-bottom:1px solid #21262d;padding-bottom:16px}}
header h1{{font-size:1.5rem;color:#f0f6fc}}
header a{{font-size:.85rem;background:#21262d;padding:6px 14px;border-radius:6px;text-decoration:none;border:1px solid #30363d}}
header a:hover{{background:#30363d}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;text-align:center}}
.card .val{{font-size:2rem;font-weight:700;color:#f0f6fc}}
.card .lbl{{font-size:.8rem;color:#8b949e;margin-top:4px}}
.card.vuln .val{{color:#f85149}}
.section{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:24px;margin-bottom:24px}}
.section h2{{font-size:1.1rem;color:#f0f6fc;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;font-size:.875rem}}
th{{background:#21262d;color:#c9d1d9;padding:10px 14px;text-align:left;white-space:nowrap}}
td{{padding:9px 14px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-all}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1c2128}}
code{{background:#161b22;border:1px solid #30363d;padding:1px 5px;border-radius:4px;font-size:.85em}}
.badge{{display:inline-block;background:#21262d;border:1px solid #30363d;padding:3px 10px;border-radius:12px;font-size:.8rem;margin:2px}}
.none{{color:#8b949e;padding:16px 0}}
footer{{text-align:center;margin-top:40px;padding-top:20px;border-top:1px solid #21262d;font-size:.8rem;color:#6e7681}}
footer p{{margin:4px 0}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>⚡ Fast-SQLi Report</h1>
    <a href="https://github.com/Am1rX/Fast-SQLi" target="_blank">View on GitHub ↗</a>
  </header>

  <div class="cards">
    <div class="card"><div class="val">{total_urls}</div><div class="lbl">URLs Scanned</div></div>
    <div class="card vuln"><div class="val">{total_findings}</div><div class="lbl">Findings</div></div>
    <div class="card"><div class="val">{elapsed:.1f}s</div><div class="lbl">Scan Time</div></div>
    <div class="card"><div class="val">{skipped}</div><div class="lbl">SSL Skipped</div></div>
    <div class="card"><div class="val">{no_params}</div><div class="lbl">No Params</div></div>
  </div>

  <div class="section">
    <h2>Methods Triggered</h2>
    {badge_html}
  </div>

  <div class="section">
    <h2>Findings</h2>
    {table_html}
  </div>

  <div class="section">
    <h2>Scan Meta</h2>
    <p style="color:#8b949e;font-size:.875rem">Generated: {html.escape(now)}</p>
  </div>

  <footer>
    <p><strong>Disclaimer:</strong> For educational purposes and authorized security testing only.
    Using this tool without explicit permission is illegal. The developer assumes no liability.</p>
    <p><a href="https://github.com/Am1rX/Fast-SQLi">Fast-SQLi</a> — github.com/Am1rX/Fast-SQLi</p>
  </footer>
</div>
</body>
</html>"""

    try:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(doc)
        return html_path
    except OSError as exc:
        error(f"Could not write HTML report: {exc}")
        return None


# ──────────────────────────────────────────────
# PRINT HELPERS
# ──────────────────────────────────────────────
def print_result(res: ScanResult) -> None:
    url = res.get("url", "?")
    print(f"\n{'─'*60}")
    print(f"  URL: {url}")
    print(f"{'─'*60}")

    err = res.get("error")
    if err == "no-params":
        info("No query parameters — nothing to test.")
        return
    if err == "ssl-cert":
        warn(f"Skipped (SSL certificate error): {res.get('details','')}")
        return
    if err:
        error(f"Scan error: {err} — {res.get('details','')}")
        return

    real_findings = [f for f in res.get("findings", []) if f.get("issue") != "request-error"]
    if not real_findings:
        info("No injection evidence found.")
        return

    found(f"{len(real_findings)} potential finding(s):")
    for f in real_findings:
        print(
            f"  {GREEN}✓{RESET} param={_c(BOLD_WHITE, f['param'])}"
            f"  payload={f['payload']}  issue={f['issue']}"
        )
        print(f"    evidence: {f['note']}")


# ──────────────────────────────────────────────
# MODES
# ──────────────────────────────────────────────
def mode_single(timeout: int, csv_path: str, html_path: str) -> None:
    url = input("Target URL (with scheme and query string): ").strip()
    if not url:
        error("No URL provided.")
        return

    info(f"Scanning → {url}")
    write_csv_header(csv_path)

    t0 = time.time()
    res = scan_url(url, timeout, csv_path)
    elapsed = time.time() - t0

    print_result(res)

    html_file = generate_html_report(OrderedDict([(url, res)]), elapsed, html_path)
    if html_file:
        info(f"HTML report: {html_file}")
    info(f"CSV report:  {csv_path}")


def mode_file(timeout: int, csv_path: str, html_path: str) -> None:
    path = input("Path to URL list file (one URL per line): ").strip()
    try:
        with open(path, encoding="utf-8") as fh:
            urls = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError as exc:
        error(f"Cannot read file: {exc}")
        return

    if not urls:
        info("File contains no URLs.")
        return

    try:
        raw = input(f"Threads [{DEFAULT_THREADS}]: ").strip()
        threads = int(raw) if raw else DEFAULT_THREADS
        threads = max(1, min(threads, 50))   # clamp to sane range
    except ValueError:
        threads = DEFAULT_THREADS

    info(f"Loaded {len(urls)} URL(s) — scanning with {threads} thread(s).")
    write_csv_header(csv_path)

    # Bug-fix: preserve input order via OrderedDict
    results: OrderedDict[str, ScanResult] = OrderedDict((u, None) for u in urls)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_url, url, timeout, csv_path): url for url in urls}
        done = 0
        for fut in as_completed(futures):
            url = futures[fut]
            done += 1
            try:
                res = fut.result()
            except Exception as exc:
                res = {"url": url, "error": "exception", "details": str(exc)}
            results[url] = res
            # live progress
            print(f"\r  progress: {done}/{len(urls)}", end="", flush=True)
    print()   # newline after progress

    elapsed = time.time() - t0

    for url in urls:
        print_result(results[url] or {"url": url, "error": "no-result"})

    html_file = generate_html_report(results, elapsed, html_path)
    if html_file:
        info(f"HTML report: {html_file}")
    info(f"CSV  report: {csv_path}")
    info(f"Scan completed in {elapsed:.1f}s")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────
def main() -> None:
    print(
        f"\n{YELLOW}[!] Use only on systems you own or have explicit written permission to test.\n"
        f"    The developer assumes no liability for misuse or damages.{RESET}\n"
    )

    parser = argparse.ArgumentParser(
        description="Fast-SQLi — heuristic SQL injection scanner"
    )
    parser.add_argument("--timeout", type=int, default=TIMEOUT,
                        help=f"HTTP timeout per request in seconds (default: {TIMEOUT})")
    parser.add_argument("--csv",  default=OUTPUT_CSV,
                        help=f"CSV output path (default: {OUTPUT_CSV})")
    parser.add_argument("--html", default=OUTPUT_HTML,
                        help=f"HTML report path (default: {OUTPUT_HTML})")
    parser.add_argument("--url",  default=None,
                        help="Target URL (skips interactive prompt, implies single mode)")
    parser.add_argument("--file", default=None,
                        help="URL list file (skips interactive prompt, implies file mode)")
    args = parser.parse_args()

    # Non-interactive mode (useful for CI / scripting)
    if args.url:
        write_csv_header(args.csv)
        t0 = time.time()
        res = scan_url(args.url, args.timeout, args.csv)
        elapsed = time.time() - t0
        print_result(res)
        generate_html_report(OrderedDict([(args.url, res)]), elapsed, args.html)
        info(f"HTML: {args.html}  CSV: {args.csv}")
        return

    if args.file:
        mode_file(args.timeout, args.csv, args.html)
        return

    # Interactive mode
    info("Select mode:")
    info("  1) Single URL")
    info("  2) URL list from file")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        mode_single(args.timeout, args.csv, args.html)
    elif choice == "2":
        mode_file(args.timeout, args.csv, args.html)
    else:
        error("Invalid selection.")
        sys.exit(1)


if __name__ == "__main__":
    main()
