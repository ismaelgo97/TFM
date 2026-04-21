import socket
import time
import os
import json
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from zapv2 import ZAPv2


class WebScanner:
    def __init__(
        self, target_ip, username, password, zap_addr="127.0.0.1", zap_port="8080"
    ):
        if target_ip.startswith("http"):
            self.base_url = target_ip
        else:
            self.base_url = f"http://{target_ip}"

        self.username = username
        self.password = password
        self.zap_addr = zap_addr
        self.zap_port = zap_port

        if not self.check_zap_status():
            raise Exception(f"ZAP is not running at {zap_addr}:{zap_port}")

        self.zap = ZAPv2(
            proxies={
                "http": f"http://{zap_addr}:{zap_port}",
                "https": f"http://{zap_addr}:{zap_port}",
            }
        )
        self.session = requests.Session()

    def check_zap_status(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((self.zap_addr, int(self.zap_port)))
        sock.close()
        return result == 0

    def login(self):
        print(f"[*] Authenticating to {self.base_url}/login.php...")
        try:
            resp = self.session.get(f"{self.base_url}/login.php")
            soup = BeautifulSoup(resp.text, "html.parser")
            token = soup.find("input", {"name": "user_token"})

            if not token:
                print("[-] Error: CSRF 'user_token' not found on login page.")
                print(
                    f"    (Debug: Page returned {resp.status_code} "
                    f"and length {len(resp.text)})"
                )
                return False

            payload = {
                "username": self.username,
                "password": self.password,
                "Login": "Login",
                "user_token": token["value"],
            }
            post_resp = self.session.post(
                f"{self.base_url}/login.php", data=payload, allow_redirects=True
            )

            if "Login failed" in post_resp.text:
                print(
                    f"[-] Login Failed: The server rejected username '{self.username}'."
                )
                return False

            # DVWA usually redirects to index.php on success.
            # If we are still at login.php, something went wrong.
            if "login.php" in post_resp.url:
                print(
                    "[-] Login Failed: Redirected to login (session not created)."
                )
                return False

            if post_resp.status_code == 200:
                print("[+] Login Successful.")
                # 4. Force Security Low
                return self.set_security_low()

            print(f"[-] Login Failed: Unknown response code {post_resp.status_code}")
            return False

        except Exception as e:
            print(f"[-] Login Exception: {e}")
            return False

    def set_security_low(self):
        print("[*] Setting Security Level to LOW...")
        try:
            resp = self.session.get(f"{self.base_url}/security.php")
            soup = BeautifulSoup(resp.text, "html.parser")
            token = soup.find("input", {"name": "user_token"})

            if not token:
                return False

            payload = {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": token["value"],
            }
            self.session.post(f"{self.base_url}/security.php", data=payload)
            return True
        except Exception as e:
            print(f"[-] Error: {e}")
            return False

    def run_scan(self, seed_routes=None):
        if not self.login():
            print("[-] Critical: Scan aborted because login failed.")
            return

        print("[*] Locking Session for Active Scan...")

        cookie_dict = self.session.cookies.get_dict()
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookie_dict.items()])

        if "security=low" not in cookie_str:
            cookie_str += "; security=low"

        print(f"    [+] Injecting Header: Cookie: {cookie_str}")

        # Tell ZAP to overwrite the 'Cookie' header on EVERY request
        try:
            # Clear old rules first to prevent duplicates
            for rule in self.zap.replacer.rules:
                self.zap.replacer.remove_rule(rule["description"])

            self.zap.replacer.add_rule(
                description="ForceSession",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Cookie",
                replacement=cookie_str,
            )
        except Exception as e:
            print(f"[-] Warning: ZAP Replacer API issue (is ZAP updated?): {e}")

        self.zap.spider.exclude_from_scan(f"{self.base_url}/logout.php")

        seeds = ["/index.php"]
        if seed_routes:
            seeds.extend(seed_routes)

        print(f"[*] Seeding ZAP with {len(seeds)} routes...")
        proxies = {
            "http": f"http://{self.zap_addr}:{self.zap_port}",
            "https": f"http://{self.zap_addr}:{self.zap_port}",
        }

        for route in seeds:
            clean_route = route if route.startswith("/") else f"/{route}"
            try:
                # Just 'touch' the URL so ZAP sees it
                self.session.get(f"{self.base_url}{clean_route}", proxies=proxies)
            except Exception as e:
                print(f"[-] Warning: Failed to seed ZAP with {clean_route}")
                print(f"    Error: {e}")

        # Run Spider
        print("[*] Starting Spider...")
        scan_id = self.zap.spider.scan(self.base_url)
        while int(self.zap.spider.status(scan_id)) < 100:
            time.sleep(1)

        print("[*] Starting Active Scan...")
        scan_id = self.zap.ascan.scan(self.base_url)
        while int(self.zap.ascan.status(scan_id)) < 100:
            status = self.zap.ascan.status(scan_id)
            print(f"    Attack Progress: {status}%", end="\r")
            time.sleep(5)

        self.generate_report()

    def generate_report(self):
        """
        Processes ZAP alerts and saves them to a JSON file in /data/scans/.
        Fulfills TFM Phase 4: Registration and Reports.
        """
        # 1. Define and create the directory
        # Using a path relative to the project root
        report_dir = os.path.join(os.getcwd(), "data", "scans")
        os.makedirs(report_dir, exist_ok=True)

        # 2. Format the filename
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"WEB_SCAN_{timestamp}.json"
        filepath = os.path.join(report_dir, filename)

        # 3. Collect and Sort Alerts
        alerts = self.zap.core.alerts(baseurl=self.base_url)
        unique_alerts = {}
        risk_weights = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}

        if alerts:
            for alert in alerts:
                # Key based on alert type and URL to avoid duplicates
                key = f"{alert['alert']}|{alert['url']}"
                if key not in unique_alerts:
                    unique_alerts[key] = alert

            # Sort alerts by risk (High to Low)
            sorted_alerts = sorted(
                unique_alerts.values(),
                key=lambda x: risk_weights.get(x["risk"], 0),
                reverse=True,
            )

            # 4. Save to JSON File
            report_data = {
                "scan_metadata": {
                    "target": self.base_url,
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": "WEB_SCAN",
                    "total_vulnerabilities": len(sorted_alerts)
                },
                "vulnerabilities": sorted_alerts
            }

            with open(filepath, "w") as f:
                json.dump(report_data, f, indent=4)

            print("\n" + "=" * 60)
            print(f"[+] Scan Complete. Report generated at:")
            print(f"    {filepath}")
            print("=" * 60)
        else:
            print("[-] No vulnerabilities found to report.")

if __name__ == "__main__":
    TARGET = "192.168.122.27/DVWA"

    routes = [
        "/vulnerabilities/sqli/",
        "/vulnerabilities/xss_r/",
        "/vulnerabilities/exec/",
    ]

    scanner = WebScanner(TARGET, "admin", "password")
    scanner.run_scan(seed_routes=routes)
