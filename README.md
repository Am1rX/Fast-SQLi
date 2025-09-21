# FastSQLi: A Smart and Rapid SQL Injection Vulnerability Scanner

FastSQLi is a high-speed, multithreaded SQL Injection vulnerability scanner written in Python. It is designed to quickly scan a large number of URLs and identify potential SQLi vulnerabilities without the complexity of traditional tools. Its primary focus is on detection, providing clear and actionable reports to help security professionals and developers secure their applications.

This tool is a detector, not an exploitation tool. Its job is to find potentially vulnerable entry points; how you use that information is up to your skills and professional responsibility.

^ Example of the generated HTML report

![Untitled design (1)](https://github.com/user-attachments/assets/59f17aec-aef5-4ea8-8e2b-6a864751e15d)


## ✨ Key Features

**High-Speed Scanning:** Utilizes multithreading to test multiple URLs simultaneously, drastically reducing scan time.
**Multiple Detection Techniques:** Employs a variety of methods to identify vulnerabilities:
**Error-Based:** Detects common database error messages.
**Boolean-Based:** Compares content differences between TRUE and FALSE conditions.
**Time-Based:** Identifies blind vulnerabilities by measuring response delays.
**Aggressive Mode (Optional):** Allows for more intensive UNION-Based and Stacked Query tests for deeper analysis.
**Comprehensive Reporting:** Generates three types of reports for clear analysis:
**Interactive HTML Report (sqli_report.html):** A clean, user-friendly report for easy visualization and sharing.
**CSV Report (sqli_findings.csv):** A structured data file, perfect for importing into other tools.
**Per-URL Detailed Logs:** Creates individual log files for every target URL in the /logs directory for in-depth debugging.
**User-Friendly Interface:** A simple command-line prompt to guide you through scan options.

## ⚠️ Ethical Warning & Disclaimer
This tool is intended for educational purposes and authorized security testing only. Using FastSQLi to scan systems for which you do not have explicit, legal permission is illegal and unethical. The author is not responsible for any misuse or damage caused by this program.

### Requirements & Installation
Python 3.x
```
requests library
```
Clone the repository:
```
git clone [https://github.com/Am1rX/Fast-SQLi.git](https://github.com/Am1rX/Fast-SQLi.git)
cd Fast-SQLi
```
Install dependencies:
```
pip install -r requirements.txt
```
## 🚀 Usage
Prepare your targets:

For scanning multiple URLs, create a file named urls.txt in the root directory. Add one URL per line.

[http://example.com/page.php?id=1](http://example.com/page.php?id=1)
[http://test.com/product.php?cat=2&item=5](http://test.com/product.php?cat=2&item=5)

### Run the script:
```
python3 FastSQLi.py
```
### Follow the on-screen prompts:

Choose between scanning a single URL or multiple URLs from urls.txt.

Decide whether to verify SSL certificates (recommended).

Choose whether to enable the aggressive scanning mode.

The scan will begin, showing live progress. Once complete, all reports will be available in the project directory.
```
Sample Output in Terminal
[info] Starting scan with 10 threads...
[info] Testing [http://testphp.vulnweb.com/listproducts.php?cat=1](http://testphp.vulnweb.com/listproducts.php?cat=1)
[info] target -> [http://testphp.vulnweb.com/listproducts.php?cat=1](http://testphp.vulnweb.com/listproducts.php?cat=1) [188.40.75.132]
[info] Testing parameter 'cat'
[info] Basic single_quote on 'cat'
[detected] Immediate: [http://testphp.vulnweb.com/listproducts.php?cat=1](http://testphp.vulnweb.com/listproducts.php?cat=1) --> basic-single_quote-diff on 'cat' (content sim=0.9123)
...
[info] Scan finished.
[info] CSV report saved to sqli_findings.csv
[info] HTML report saved to sqli_report.html
```

## Contributing
FastSQLi is an open-source project, and contributions are welcome! If you have an idea for a new feature, find a bug, or want to improve the code, please feel free to open an Issue or submit a Pull Request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
