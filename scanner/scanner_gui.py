import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QCheckBox, QTextEdit, QVBoxLayout, QHBoxLayout, QProgressBar
)
from PyQt5.QtCore import QThread, pyqtSignal


class ScannerThread(QThread):
    progress_update = pyqtSignal(int)
    log_update = pyqtSignal(str)

    def __init__(self, target_url, crawl_links, find_subdomains):
        super().__init__()
        self.target_url = target_url
        self.crawl_links = crawl_links
        self.find_subdomains = find_subdomains
        self.is_running = True

    def run(self):
        """Main scan logic"""
        self.log_update.emit(f"Starting scan for {self.target_url}")
        self.progress_update.emit(0)

        try:
            # Step 1: Crawl internal links
            if self.crawl_links:
                self.log_update.emit("Crawling internal links...")
                self.crawl_links_function()
                self.progress_update.emit(20)

            # Step 2: Find subdomains
            if self.find_subdomains:
                self.log_update.emit("Finding subdomains...")
                self.find_subdomains_function()
                self.progress_update.emit(40)

            # Step 3: Check for SQL Injection
            self.log_update.emit("Checking for SQL Injection vulnerabilities...")
            self.check_sql_injection()
            self.progress_update.emit(60)

            # Step 4: Check for XSS vulnerabilities
            self.log_update.emit("Checking for XSS vulnerabilities...")
            self.check_xss()
            self.progress_update.emit(80)

            # Step 5: Check for security headers
            self.log_update.emit("Checking security headers...")
            self.check_security_headers()
            self.progress_update.emit(100)

            self.log_update.emit("✅ Scan completed successfully!")
        except Exception as e:
            self.log_update.emit(f"❌ Error occurred: {str(e)}")

    def crawl_links_function(self):
        """Crawl internal links"""
        try:
            response = requests.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [urljoin(self.target_url, link['href'])
                     for link in soup.find_all('a', href=True)]
            self.log_update.emit(f"Found {len(links)} internal links.")
        except Exception as e:
            self.log_update.emit(f"Error while crawling links: {str(e)}")

    def find_subdomains_function(self):
        """Find subdomains using a basic wordlist"""
        subdomains = ['www', 'admin', 'test', 'blog', 'dev']
        found_subdomains = []
        for subdomain in subdomains:
            url = f"http://{subdomain}.{self.target_url.replace('http://', '').replace('https://', '')}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    found_subdomains.append(url)
                    self.log_update.emit(f"Found subdomain: {url}")
            except requests.RequestException:
                pass

        if not found_subdomains:
            self.log_update.emit("No subdomains found.")

    def check_sql_injection(self):
        """Check for SQL Injection"""
        payloads = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a", "' OR 1=1#", "1' OR '1'='1' --"]
        test_url = f"{self.target_url}?id="

        for payload in payloads:
            url = test_url + payload
            try:
                response = requests.get(url)
                if "SQL syntax" in response.text or "mysql_fetch" in response.text:
                    self.log_update.emit(f"❗ SQL Injection vulnerability detected: {url}")
                    return
            except Exception as e:
                self.log_update.emit(f"Error testing SQL Injection: {str(e)}")

        self.log_update.emit("✅ No SQL Injection vulnerabilities found.")

    def check_xss(self):
        """Check for XSS vulnerabilities"""
        payloads = ["<script>alert('XSS')</script>", "\" onerror=\"alert(1)", "'><img src=x onerror=alert(1)>"]
        test_url = f"{self.target_url}?q="

        for payload in payloads:
            url = test_url + payload
            try:
                response = requests.get(url)
                if payload in response.text:
                    self.log_update.emit(f"❗ XSS vulnerability detected: {url}")
                    return
            except Exception as e:
                self.log_update.emit(f"Error testing XSS: {str(e)}")

        self.log_update.emit("✅ No XSS vulnerabilities found.")

    def check_security_headers(self):
        """Check security headers"""
        try:
            response = requests.get(self.target_url)
            headers = response.headers
            required_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy']

            for header in required_headers:
                if header not in headers:
                    self.log_update.emit(f"❗ Missing security header: {header}")
        except Exception as e:
            self.log_update.emit(f"Error checking security headers: {str(e)}")


class WebScannerGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Web Application Vulnerability Scanner")
        self.setGeometry(100, 100, 600, 500)

        # GUI Layout
        layout = QVBoxLayout()

        # URL Input
        self.url_label = QLabel("Target URL:")
        self.url_input = QLineEdit(self)
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)

        # Checkboxes for features
        self.crawl_links_checkbox = QCheckBox("Crawl Internal Links")
        self.subdomains_checkbox = QCheckBox("Find Subdomains")
        layout.addWidget(self.crawl_links_checkbox)
        layout.addWidget(self.subdomains_checkbox)

        # Buttons for Start/Stop
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)

        # Scan Logs
        self.log_label = QLabel("Scan Logs:")
        layout.addWidget(self.log_label)
        self.log_viewer = QTextEdit(self)
        self.log_viewer.setReadOnly(True)
        layout.addWidget(self.log_viewer)

        # Progress Bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)

    def start_scan(self):
        """Start scanning with selected options"""
        target_url = self.url_input.text()
        crawl_links = self.crawl_links_checkbox.isChecked()
        find_subdomains = self.subdomains_checkbox.isChecked()

        if not target_url:
            self.log_viewer.append("❗ Error: Target URL cannot be empty!")
            return

        # Reset progress and logs
        self.progress_bar.setValue(0)
        self.log_viewer.clear()

        # Create and run the scanner thread
        self.scanner_thread = ScannerThread(target_url, crawl_links, find_subdomains)
        self.scanner_thread.progress_update.connect(self.update_progress)
        self.scanner_thread.log_update.connect(self.update_logs)
        self.scanner_thread.start()

    def stop_scan(self):
        """Stop scanning gracefully"""
        if hasattr(self, 'scanner_thread') and self.scanner_thread.isRunning():
            self.log_viewer.append("⏹️ Scan stopped by user.")
            self.scanner_thread.is_running = False

    def update_progress(self, value):
        """Update progress bar value"""
        self.progress_bar.setValue(value)

    def update_logs(self, message):
        """Update log viewer with scan messages"""
        self.log_viewer.append(message)


# Run the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WebScannerGUI()
    window.show()
    sys.exit(app.exec_())
