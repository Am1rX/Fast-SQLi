# Fast-SQLi

This Python script allows you to test SQL Injection (SQLi) vulnerabilities on URL parameters.

---

## Features

- Test **multiple URLs simultaneously** using 10 threads for faster scanning
- `[info]` messages for tracking the progress of each URL
- `[detected]` messages when a vulnerability is found
- Final list of all vulnerable URLs including the parameter name and method used
- Automatically tests the **last parameter** of the URL even if there are multiple parameters
- ANSI color-coded output for better readability (`[info]`, `[error]`, `[detected]`)

---

## Requirements

- Python 3.x
- Standard Python modules: `requests`

Install `requests` if you don't have it:

```bash
pip install requests

