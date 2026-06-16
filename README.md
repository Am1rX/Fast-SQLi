<div align="center">

<img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Type-Security%20Tool-red?style=for-the-badge"/>

# ⚡ Fast-SQLi

**A fast, heuristic SQL injection scanner for authorized security testing**

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Output](#-output) · [How It Works](#-how-it-works) · [Disclaimer](#-disclaimer)

</div>

---

## 📌 Overview

**Fast-SQLi** is a lightweight Python tool that probes URL query parameters for SQL injection vulnerabilities using heuristic detection — SQL error signatures, HTTP status changes, and response size anomalies. It supports both single-URL and bulk scanning modes, outputs clean CSV and HTML reports, and is designed to be dead simple to run.

> Built for penetration testers, bug bounty hunters, and developers auditing their own applications.
![Untitled design (1)](https://github.com/user-attachments/assets/59f17aec-aef5-4ea8-8e2b-6a864751e15d)
---

## ✨ Features

- 🔍 **Heuristic detection** — SQL error signatures, status-code diffs, and response-size anomalies
- ⚡ **Multi-threaded bulk scanning** — scan hundreds of URLs concurrently
- 🎯 **Smart early-exit** — skips redundant payloads when a parameter already fires
- 📄 **Dual reports** — structured CSV + dark-themed HTML report
- 🔁 **Auto-retry** — built-in retry logic for flaky connections
- 🔒 **SSL error handling** — gracefully skips URLs with cert issues, keeps scanning the rest
- 🖥️ **CLI & interactive modes** — works with prompts or fully scriptable via flags
- 🧵 **Thread-safe** — concurrent writes protected with locks

---

## 📋 Requirements

- Python 3.8+
- `requests` library

---

## 🚀 Installation

```bash
git clone https://github.com/Am1rX/Fast-SQLi.git
cd Fast-SQLi
pip install requests
```

---

## 🛠️ Usage

### Interactive mode

```bash
python fast_sqli.py
```

You'll be prompted to choose:

```
[i] Select mode:
[i]   1) Single URL
[i]   2) URL list from file
Enter 1 or 2:
```

---

### Single URL (non-interactive)

```bash
python fast_sqli.py --url "https://example.com/page?id=1&cat=news"
```

---

### Bulk scan from file (non-interactive)

```bash
python fast_sqli.py --file urls.txt
```

`urls.txt` — one URL per line, lines starting with `#` are ignored:

```
https://example.com/page?id=1
https://target.com/search?q=test
# https://skip-this.com/page?x=1
```

---

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Single target URL (non-interactive) |
| `--file` | — | Path to URL list file (non-interactive) |
| `--timeout` | `10` | HTTP request timeout in seconds |
| `--csv` | `scan-report.csv` | CSV output file path |
| `--html` | `sql-report.html` | HTML report file path |
| `--threads` | `10` | Concurrent threads for file mode |

---

## 📊 Output

### Terminal

```
────────────────────────────────────────────────────────────
  URL: https://example.com/page?id=1
────────────────────────────────────────────────────────────
[+] 2 potential finding(s):
  ✓ param=id  payload=single-quote  issue=error-signature
    evidence: SQL error signature in response
  ✓ param=id  payload=single-quote-comment  issue=content-diff
    evidence: response size 4821 → 312 bytes (93.5%)
```

### HTML Report

A dark-themed HTML report is generated with:
- Summary cards (total URLs, findings, scan time, skipped)
- Full findings table with URL, parameter, issue type, method, and evidence
- Method breakdown badges

### CSV Report

Machine-readable output with columns:
`url, param, payload, method, issue, note, abs_change, rel_change`

---

## 🔬 How It Works

Fast-SQLi injects quote-based payloads into each query parameter and compares the injected response against a clean baseline request.

**Payloads tested per parameter:**

| Label | Payload | Notes |
|-------|---------|-------|
| `single-quote` | `'` | Basic single-quote break |
| `single-quote-comment` | `' -- ` | Quote + SQL comment |
| `double-quote` | `"` | Double-quote break |
| `double-quote-comment` | `" -- ` | Double-quote + SQL comment |

> If single-quote payloads already trigger a finding, double-quote payloads are skipped — halving the requests for vulnerable parameters.

**Detection triggers:**

| Signal | Meaning |
|--------|---------|
| SQL error signature in body | Database error leaked to the user |
| HTTP status code change | Application behaved differently |
| Response size anomaly ≥ 0.5% and ≥ 50 bytes | Page content changed meaningfully |

---

## ⚙️ Architecture

```
fast_sqli.py
│
├── parse_url()              # URL + query string parsing
├── build_url()              # Safe URL reconstruction (no double-wrapping)
│
├── test_payload()           # Single payload → baseline comparison
├── scan_param()             # All payloads for one parameter (with early-exit)
├── scan_url()               # All parameters for one URL
│
├── mode_single()            # Single-URL interactive/CLI flow
├── mode_file()              # Bulk scan with ThreadPoolExecutor
│
├── write_csv_header()       # CSV init
├── append_csv_rows()        # Thread-safe CSV write (Lock protected)
└── generate_html_report()   # Dark-theme HTML report generator
```

---

## ⚠️ Disclaimer

> **This tool is intended strictly for educational purposes and authorized security testing.**
>
> Running Fast-SQLi against systems you do not own or do not have **explicit written permission** to test is illegal and unethical. The developer assumes **no liability** for any misuse, damage, or legal consequences arising from improper use of this tool.
>
> Always get written authorization before testing any system.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made by [Am1rX](https://github.com/Am1rX) · [⭐ Star this repo](https://github.com/Am1rX/Fast-SQLi) if it helped you

</div>
