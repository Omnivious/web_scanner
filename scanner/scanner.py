import requests
import argparse
import json
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# SQL Injection Payloads
SQL_PAYLOADS = ["' OR '1'='1' --", '" OR "1"="1"', "' UNION SELECT NULL, NULL --", "'; WAITFOR DELAY '0:0:5' --"]

# XSS Payloads
XSS_PAYLOADS = ['<script>alert("XSS")</script>', '"><img src=x onerror=alert(1)>', 'javascript:alert("XSS")']

# Directory Traversal Payloads
TRAVERSAL_PAYLOADS = ["../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "../../windows/win.ini"]

# Security Headers to check
SECURITY_HEADERS = ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]

# Dictionary to store scan results
scan_results = {"sql_injection": [], "xss": [], "directory_traversal": [], "headers": []}


# SQL Injection Scan
def check_sql_injection(url):
    for payload in SQL_PAYLOADS:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                print(Fore.RED + f"[!] SQL Injection Found: {test_url}" + Style.RESET_ALL)
                scan_results["sql_injection"].append(test_url)
        except requests.RequestException:
            continue


# XSS Scan
def check_xss(url):
    for payload in XSS_PAYLOADS:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                print(Fore.YELLOW + f"[!] XSS Found: {test_url}" + Style.RESET_ALL)
                scan_results["xss"].append(test_url)
        except requests.RequestException:
            continue


# Form Scanning (SQLi & XSS)
def check_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action")
            full_action = urljoin(url, action)
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")

            for payload in SQL_PAYLOADS + XSS_PAYLOADS:
                data = {inp.get("name", "field"): payload for inp in inputs if inp.get("type") != "submit"}

                if method == "post":
                    res = requests.post(full_action, data=data, timeout=5)
                else:
                    res = requests.get(full_action, params=data, timeout=5)

                if any(p in res.text for p in SQL_PAYLOADS):
                    print(Fore.RED + f"[!] SQL Injection Possible in Form: {full_action}" + Style.RESET_ALL)
                    scan_results["sql_injection"].append(full_action)
                if any(p in res.text for p in XSS_PAYLOADS):
                    print(Fore.YELLOW + f"[!] XSS Possible in Form: {full_action}" + Style.RESET_ALL)
                    scan_results["xss"].append(full_action)
    except requests.RequestException:
        pass


# Security Header Check
def check_headers(url):
    try:
        response = requests.get(url, timeout=5)
        missing_headers = [header for header in SECURITY_HEADERS if header not in response.headers]

        if missing_headers:
            print(Fore.BLUE + f"[!] Missing Security Headers at {url}: {missing_headers}" + Style.RESET_ALL)
            scan_results["headers"].append({url: missing_headers})
    except requests.RequestException:
        pass


# Directory Traversal Check
def check_directory_traversal(url):
    for payload in TRAVERSAL_PAYLOADS:
        test_url = urljoin(url, payload)
        try:
            response = requests.get(test_url, timeout=5)
            if "root:x:" in response.text or "Windows Registry Editor" in response.text:
                print(Fore.MAGENTA + f"[!] Directory Traversal Found: {test_url}" + Style.RESET_ALL)
                scan_results["directory_traversal"].append(test_url)
        except requests.RequestException:
            continue


# Crawler to Find Internal Links
def crawl(url, max_depth=2):
    visited = set()
    to_visit = [url]

    for _ in range(max_depth):
        new_links = []
        for link in to_visit:
            if link not in visited:
                visited.add(link)
                try:
                    response = requests.get(link, timeout=5)
                    soup = BeautifulSoup(response.text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        full_url = urljoin(url, a["href"])
                        if urlparse(full_url).netloc == urlparse(url).netloc:
                            new_links.append(full_url)
                except requests.RequestException:
                    continue
        to_visit = new_links

    return visited


# Find Subdomains
def find_subdomains(domain):
    subdomains = set()
    wordlist = ["www", "test", "dev", "api", "admin"]

    for sub in wordlist:
        test_url = f"https://{sub}.{domain}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(Fore.CYAN + f"[+] Found Subdomain: {test_url}" + Style.RESET_ALL)
                subdomains.add(test_url)
        except requests.RequestException:
            continue

    return subdomains


# Save Scan Results to JSON
def save_results():
    with open("scan_results.json", "w") as f:
        json.dump(scan_results, f, indent=4)
    print(Fore.GREEN + "\n[✔] Scan Results Saved in scan_results.json" + Style.RESET_ALL)


# Main Scanner Function
def scan_url(url):
    print(Fore.GREEN + f"\nScanning: {url} ..." + Style.RESET_ALL)
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.submit(check_sql_injection, url)
        executor.submit(check_xss, url)
        executor.submit(check_forms, url)
        executor.submit(check_headers, url)
        executor.submit(check_directory_traversal, url)


# Main Entry Point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Python Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--subdomains", action="store_true", help="Find subdomains of the target")
    parser.add_argument("--crawl", action="store_true", help="Crawl and scan internal links")

    args = parser.parse_args()

    if args.subdomains:
        find_subdomains(urlparse(args.url).netloc)

    urls_to_scan = [args.url]
    if args.crawl:
        urls_to_scan.extend(crawl(args.url))

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scan_url, urls_to_scan)

    save_results()
