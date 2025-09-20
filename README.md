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
```
## Usage
1. Run the script
```bash
python sqli_tester.py
```
2. Choose an option

1. Single URL: manually enter a single URL

2. Multi URL: read URLs from a file named urls.txt in the same folder

3. Format for urls.txt:

## Each URL on a separate line:
```bash
http://example.com/page.php?id=1
http://test.com/product.php?item=2
```
## Sample Output
```bash
[info] Testing URL: http://example.com/page.php?id=1
[info] Testing Single-Quote on parameter 'id'...
[detected] http://example.com/page.php?id=1 --> Single-Quote on 'id'
```

## All Detected SQLi URLs:
```bash
http://example.com/page.php?id=1 --> Single-Quote on 'id'
```
## Important Notes

This tool only tests GET parameters.

Use only on your own sites or with permission.

[error] is shown only when the URL has no query parameters.

## License

MIT License
