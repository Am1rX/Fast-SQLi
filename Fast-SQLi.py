from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
import argparse
import sys
import time
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import datetime
import html

# CONFIG
DEFAULT_THREADS = 10
TIMEOUT = 10  # seconds for HTTP requests
PAUSE_BETWEEN_REQUESTS = 0.35  # polite pause between requests to same host
OUTPUT_CSV = "scan-report.csv"
OUTPUT_HTML = "sql-report.html"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
}

SQL_ERRORS = [
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

# Payload definitions (plain then comment)
QUOTE_GROUPS = {
    "single": [
        {"label": "single-quote", "inj": "'"},
        {"label": "single-quote-comment", "inj": "' -- "},
    ],
    "double": [
        {"label": "double-quote", "inj": '"'},
        {"label": "double-quote-comment", "inj": '" -- '},
    ],
}

lock = Lock()

# ANSI color codes
ANSI_BOLD_WHITE = "\x1b[97;1m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_RESET = "\x1b[0m"


def is_ssl_cert_error(exc):
    """Return True if the exception is an SSL certificate verification error we want to ignore.
    We inspect exception type and message to be robust across platforms.
    """
    try:
        # requests' SSL failures often come as requests.exceptions.SSLError
        if isinstance(exc, requests.exceptions.SSLError):
            return True
        msg = str(exc).lower()
        if 'certificate verify failed' in msg or 'ssl' in msg and 'cert' in msg:
            return True
    except Exception:
        pass
    return False


def parse_url_params(url):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    return p, qs


def build_url_with_param(parsed_url, qs_dict):
    query = urlencode({k: v[0] for k, v in qs_dict.items()}, doseq=False)
    return urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, query, parsed_url.fragment))


def looks_like_sql_error(text):
    if not text:
        return False
    lt = text.lower()
    for sig in SQL_ERRORS:
        if sig.lower() in lt:
            return True
    return False


def content_change_amount(a, b):
    if a is None or b is None:
        return 0, 0.0
    la = len(a)
    lb = len(b)
    abs_change = abs(la - lb)
    rel = 1.0 if la == 0 else abs_change / la
    return abs_change, rel


def send_get(url, headers=None, timeout=TIMEOUT):
    try:
        return requests.get(url, headers=headers or HEADERS, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return e


def payload_method_from_label(label):
    if label.startswith('single'):
        return 'single'
    if label.startswith('double'):
        return 'double'
    return 'unknown'


def perform_single_payload_test(parsed_url, base_qs, param_name, base_value, payload, timeout=TIMEOUT):
    qs = {k: [v[0] if isinstance(v, list) else v for v in base_qs.get(k, "")] for k in base_qs}
    qs[param_name] = [base_value]
    baseline_url = build_url_with_param(parsed_url, qs)

    r_base = send_get(baseline_url, timeout=timeout)
    if isinstance(r_base, Exception):
        # If it's an SSL-cert verification error, return a special marker so caller can skip the whole URL
        if is_ssl_cert_error(r_base):
            return {'__ssl_cert__': True, 'error': str(r_base)}
        return {"param": param_name, "payload": "baseline", "issue": "request-error", "note": str(r_base), "abs_change": 0, "rel_change": 0.0, "method": "-"}

    base_text = r_base.text
    base_status = r_base.status_code

    qs_test = dict(qs)
    qs_test[param_name] = [(qs_test.get(param_name, [""])[0] or "") + payload["inj"]]
    test_url = build_url_with_param(parsed_url, qs_test)

    time.sleep(PAUSE_BETWEEN_REQUESTS)
    r = send_get(test_url, timeout=timeout)
    if isinstance(r, Exception):
        if is_ssl_cert_error(r):
            return {'__ssl_cert__': True, 'error': str(r)}
        return {"param": param_name, "payload": payload["label"], "issue": "request-error", "note": str(r), "abs_change": 0, "rel_change": 0.0, "method": payload_method_from_label(payload["label"])}

    text = r.text
    status = r.status_code

    abs_ch, rel_ch = content_change_amount(base_text, text)
    notes = []
    issue = None

    if looks_like_sql_error(text):
        notes.append("SQL error signature detected")
        issue = "error-signature"
    if status != base_status:
        notes.append(f"HTTP status {base_status}->{status}")
        issue = issue or "status-diff"
    if abs_ch > 0 and rel_ch > 0.002:
        notes.append(f"response length {len(base_text)} -> {len(text)}")
        issue = issue or "content-diff"

    if issue:
        return {"param": param_name, "payload": payload["label"], "issue": issue, "note": "; ".join(notes), "abs_change": abs_ch, "rel_change": rel_ch, "method": payload_method_from_label(payload["label"])}
    return None


def scan_param(parsed_url, qs, param, base_val, timeout):
    """
    Returns: (findings_list, primary_tuple_or_None, ssl_error_info_or_None)
    If ssl_error_info_or_None is not None, scanning should stop for that URL and be reported as skipped.
    """
    findings = []

    single_plain = perform_single_payload_test(parsed_url, qs, param, base_val, QUOTE_GROUPS["single"][0], timeout)
    # check SSL marker
    if isinstance(single_plain, dict) and single_plain.get('__ssl_cert__'):
        return [], None, single_plain.get('error')

    single_comment = perform_single_payload_test(parsed_url, qs, param, base_val, QUOTE_GROUPS["single"][1], timeout)
    if isinstance(single_comment, dict) and single_comment.get('__ssl_cert__'):
        return [], None, single_comment.get('error')

    if single_plain:
        findings.append(single_plain)
    if single_comment:
        findings.append(single_comment)

    if findings:
        primary = max(findings, key=lambda x: (x.get("abs_change", 0), x.get("rel_change", 0)))
        return findings, (param, primary["payload"], primary["note"], primary.get("abs_change", 0)), None

    double_plain = perform_single_payload_test(parsed_url, qs, param, base_val, QUOTE_GROUPS["double"][0], timeout)
    if isinstance(double_plain, dict) and double_plain.get('__ssl_cert__'):
        return [], None, double_plain.get('error')

    double_comment = perform_single_payload_test(parsed_url, qs, param, base_val, QUOTE_GROUPS["double"][1], timeout)
    if isinstance(double_comment, dict) and double_comment.get('__ssl_cert__'):
        return [], None, double_comment.get('error')

    double_findings = []
    if double_plain:
        double_findings.append(double_plain)
    if double_comment:
        double_findings.append(double_comment)

    if double_findings:
        primary = max(double_findings, key=lambda x: (x.get("abs_change", 0), x.get("rel_change", 0)))
        return double_findings, (param, primary["payload"], primary["note"], primary.get("abs_change", 0)), None

    return [], None, None


def write_csv_header(path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "param", "payload", "method", "issue", "note", "abs_change", "rel_change"])


def append_csv_row(path, row):
    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(row)


def human_print_info(msg):
    print(f"{ANSI_BOLD_WHITE}[i] {msg}{ANSI_RESET}")


def human_print_detected(msg):
    print(f"{ANSI_GREEN}[+] {msg}{ANSI_RESET}")


def human_print_warning(msg):
    print(f"{ANSI_YELLOW}[!] {msg}{ANSI_RESET}")


def scan_url_workflow(url, timeout, csv_path):
    parsed_url, qs = parse_url_params(url)
    if not qs:
        return {"url": url, "error": "no-params", "details": None}

    params = list(qs.keys())
    url_findings = []
    url_primaries = []

    for p in params:
        base_val = qs.get(p, [""])[0]
        res_findings, primary, ssl_err = scan_param(parsed_url, qs, p, base_val, timeout)
        if ssl_err:
            # skip entire URL and report ssl error
            return {"url": url, "error": "ssl-cert", "details": ssl_err}

        if res_findings:
            for item in res_findings:
                # persist to CSV with url context
                append_csv_row(csv_path, [url, item.get("param"), item.get("payload"), item.get("method"), item.get("issue"), item.get("note"), item.get("abs_change", 0), item.get("rel_change", 0.0)])
                url_findings.append(item)
            url_primaries.append(primary)
    return {"url": url, "findings": url_findings, "primaries": url_primaries}


def generate_html_report(results_map, start_time, end_time, csv_path, html_path):
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    total_urls = len(results_map)
    findings_count = 0
    method_counts = {}
    rows = []

    for url, res in results_map.items():
        if not res:
            continue
        if res.get('error') == 'ssl-cert':
            # do not count SSL-skipped URLs as findings
            continue
        if res.get('error'):
            continue
        for f in res.get('findings', []):
            findings_count += 1
            method = f.get('method', 'unknown')
            method_counts[method] = method_counts.get(method, 0) + 1
            rows.append((url, f.get('param'), method, f.get('note')))

    run_time_seconds = (end_time - start_time)

    # build rows_html
    rows_html = ''
    for url, param, method, note in rows:
        rows_html += '<tr>'
        rows_html += f'<td>{html.escape(url)}</td>'
        rows_html += f'<td>{html.escape(param)}</td>'
        rows_html += f'<td>{html.escape(method)}</td>'
        rows_html += f'<td>{html.escape(note)}</td>'
        rows_html += '</tr>'

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
    .badge{{display:inline-block;padding:4px 10px;border-radius:6px;background:#eee;margin:0 5px 5px 0;font-size:12px}}
    .github-link-top{{position:fixed;top:15px;right:20px;text-decoration:none;font-weight:bold;color:#444;background:#fff;padding:6px 12px;border-radius:5px;box-shadow:0 2px 8px rgba(0,0,0,0.1);border:1px solid #ddd}}
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
        with open(html_path, 'w', encoding='utf-8') as fh:
            fh.write(html_content)
        return html_path
    except Exception:
        return None


def run_single_mode(timeout, csv_path, html_path):
    url = input("Enter target URL (include scheme and query string): ").strip()
    human_print_info(f"Scanning {url} ...")
    write_csv_header(csv_path)
    start = time.time()
    res = scan_url_workflow(url, timeout, csv_path)
    end = time.time()

    results_map = {url: res}
    html_file = generate_html_report(results_map, start, end, csv_path, html_path)

    print("\n=== Result for URL ===")
    if res.get("error") == "no-params":
        human_print_info("No query parameters detected in the given URL. Nothing to test.")
        return

    if res.get('error') == 'ssl-cert':
        human_print_warning(f"Skipped URL due to SSL certificate error: {res.get('details')}")
        human_print_info("This URL was not considered as 'detected'.")
        if html_file:
            human_print_info(f"HTML report written to: {html_file}")
        return

    if not res.get("primaries"):
        human_print_info("No strong evidence of SQL injection found for this URL (with these heuristic checks).")
    else:
        prim = sorted(res["primaries"], key=lambda x: x[3] or 0, reverse=True)
        human_print_detected(f"Potential issues detected: {len(prim)}")
        for p in prim:
            print(f" {ANSI_GREEN}* param={p[0]}, payload={p[1]}, note={p[2]} (abs_change={p[3]}){ANSI_RESET}")

    if html_file:
        human_print_info(f"HTML report written to: {html_file}")
    else:
        human_print_info("Failed to write HTML report.")


def run_file_mode(timeout, csv_path, html_path):
    path = input("Enter path to text file with URLs (one per line): ").strip()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            urls = [line.strip() for line in fh if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        return

    if not urls:
        human_print_info("File contains no URLs.")
        return

    try:
        threads = int(input(f"Enter number of threads to use for scanning URLs (default {DEFAULT_THREADS}): ").strip() or DEFAULT_THREADS)
    except Exception:
        threads = DEFAULT_THREADS

    human_print_info(f"Loaded {len(urls)} URLs — scanning with {threads} threads. Results will be printed in file order.")

    write_csv_header(csv_path)

    results_map = {}

    start = time.time()
    # use ThreadPoolExecutor to scan URLs concurrently but collect results
    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_to_url = {ex.submit(scan_url_workflow, url, timeout, csv_path): url for url in urls}
        for fut in as_completed(future_to_url):
            url = future_to_url[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"url": url, "error": "exception", "details": str(e)}
            results_map[url] = res
    end = time.time()

    # print results in the same order as input
    for url in urls:
        res = results_map.get(url)
        print(f"\n=== Result for URL: {url} ===")
        if not res:
            human_print_info("No result returned (internal error).")
            continue
        if res.get("error") == "no-params":
            human_print_info("No query parameters detected in the given URL. Nothing to test.")
            continue
        if res.get('error') == 'ssl-cert':
            human_print_warning(f"Skipped URL due to SSL certificate error: {res.get('details')}")
            human_print_info("This URL was not considered as 'detected'.")
            continue
        if res.get("findings") and res.get("primaries"):
            prim = sorted(res["primaries"], key=lambda x: x[3] or 0, reverse=True)
            human_print_detected(f"Potential issues detected: {len(prim)}")
            for p in prim:
                print(f" {ANSI_GREEN}* param={p[0]}, payload={p[1]}, note={p[2]} (abs_change={p[3]}){ANSI_RESET}")
            # also list other findings
            for f in res["findings"]:
                print(f"    - payload={f['payload']}, issue={f['issue']}, note={f['note']} (abs_change={f.get('abs_change',0)})")
        else:
            human_print_info("No strong evidence of SQL injection found for this URL (with these heuristic checks).")

    # generate aggregated html report
    html_file = generate_html_report(results_map, start, end, csv_path, html_path)
    if html_file:
        human_print_info(f"HTML report written to: {html_file}")
    else:
        human_print_info("Failed to write HTML report.")

# https://github.com/Am1rX/Fast-SQLi
def main():
    print("[!] Use this tool only on systems you own or have explicit written permission to test.\nThe developer assumes no liability for misuse or damages.\n")
    parser = argparse.ArgumentParser(description="Interactive multi-mode SQLi detector (v5 fixed) with HTML output")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help=f"HTTP timeout seconds (default {TIMEOUT})")
    parser.add_argument("--csv", default=OUTPUT_CSV, help=f"CSV output file (default {OUTPUT_CSV})")
    parser.add_argument("--html", default=OUTPUT_HTML, help=f"HTML report file (default {OUTPUT_HTML})")
    args = parser.parse_args()

    human_print_info("Select mode:")
    human_print_info("  1) Test a single URL")
    human_print_info("  2) Test a list of URLs from a text file")
    mode = input("Enter 1 or 2: ").strip()
    if mode == "1":
        run_single_mode(args.timeout, args.csv, args.html)
    elif mode == "2":
        run_file_mode(args.timeout, args.csv, args.html)
    else:
        print("[!] Invalid selection. Exiting.")


if __name__ == "__main__":
    main()
