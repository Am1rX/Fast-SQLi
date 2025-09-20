import requests
from urllib.parse import urlparse, parse_qs, urlencode
import socket
import os
from concurrent.futures import ThreadPoolExecutor
import threading

WHITE = "\033[1;37m"
GREEN = "\033[1;32m"
RED = "\033[1;31m"
RESET = "\033[0m"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 SQLiTest/1.0'
}

TIMEOUT = 10  # seconds
print_lock = threading.Lock()  # جلوگیری از قاطی شدن print
detected_lock = threading.Lock()  # جلوگیری از قاطی شدن لیست detected
all_detected = []  # لیست کلی detected ها

# ورودی URL
print("Choose option:")
print("1. Single URL")
print("2. Multi URL from urls.txt")
choice = input("Enter choice (1 or 2): ").strip()

if choice == "1":
    urls = [input("Enter the URL (e.g., http://example.com/page.php?id=1): ").strip()]
elif choice == "2":
    if not os.path.isfile("urls.txt"):
        print(f"{RED}[error] urls.txt not found in current directory.{RESET}")
        exit(1)
    with open("urls.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]
else:
    print(f"{RED}[error] Invalid choice.{RESET}")
    exit(1)

def test_sqli(original_url):
    parsed_url = urlparse(original_url)
    query_params = parse_qs(parsed_url.query)
    param_names = list(query_params.keys())

    with print_lock:
        print(f"{WHITE}[info] Testing URL: {original_url}{RESET}")

    if not param_names:
        with print_lock:
            print(f"{RED}[error] URL has no query parameters: {original_url}{RESET}")
        return

    # روی آخرین پارامتر تست SQLi انجام شود
    param_name = param_names[-1]
    original_value = query_params[param_name][0]

    try:
        ip = socket.gethostbyname(parsed_url.netloc)
    except socket.gaierror:
        ip = "Unknown IP"

    base_url = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path

    def build_url(base_url, new_value):
        new_params = query_params.copy()
        new_params[param_name] = [new_value]
        return base_url + '?' + urlencode(new_params, doseq=True)

    try:
        response1 = requests.get(original_url, headers=HEADERS, timeout=TIMEOUT)
        content_length1 = int(response1.headers.get('Content-Length', len(response1.content)))
    except requests.RequestException as e:
        with print_lock:
            print(f"{RED}[error] Failed to request original URL: {e}{RESET}")
        return

    methods = {
        "Single-Quote": "'",
        "Double-Quote": '"',
        "Slash": "/"
    }

    detected_methods = []

    for method, payload in methods.items():
        with print_lock:
            print(f"{WHITE}[info] Testing {method} on parameter '{param_name}'...{RESET}")

        modified_value2 = original_value + payload
        modified_value3 = original_value + payload + " -- "
        url2 = build_url(base_url, modified_value2)
        url3 = build_url(base_url, modified_value3)

        try:
            response2 = requests.get(url2, headers=HEADERS, timeout=TIMEOUT)
            content_length2 = int(response2.headers.get('Content-Length', len(response2.content)))
            response3 = requests.get(url3, headers=HEADERS, timeout=TIMEOUT)
            content_length3 = int(response3.headers.get('Content-Length', len(response3.content)))
        except requests.RequestException:
            continue

        if content_length1 == content_length3 and content_length1 != content_length2:
            with print_lock:
                print(f"{GREEN}[detected] {original_url} --> {method} on '{param_name}'{RESET}")
            detected_methods.append(method)

    if detected_methods:
        with detected_lock:
            for method in detected_methods:
                all_detected.append((original_url, param_name, method))

# اجرای threadها
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(test_sqli, urls)

# چاپ نهایی همه detectedها
if all_detected:
    print(f"\n{GREEN}All Detected SQLi URLs:{RESET}")
    for url, param, method in all_detected:
        print(f"{GREEN}{url} --> {method} on '{param}'{RESET}")
else:
    print(f"\n{RED}No SQLi detected.{RESET}")
