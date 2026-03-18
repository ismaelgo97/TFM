import os
import json
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch
from utils.ui_utils import Spinner

class ELKMonitor:
    def __init__(self, host="http://localhost:9200"):
        self.es = Elasticsearch([host], request_timeout=30)
        self.index = "*filebeat*"
        self.block_list_path = os.path.join(os.getcwd(), "data", "firewall", "blocked_ips.txt")
        os.makedirs(os.path.dirname(self.block_list_path), exist_ok=True)

    def check_connection(self):
        try:
            return self.es.ping()
        except Exception:
            return False

    def query_alerts(self, interval_minutes=60):
        start_time = (datetime.now(timezone.utc) - timedelta(minutes=interval_minutes)).isoformat()

        query = {
            "query": {
                "bool": {
                    "must": [{"range": {"@timestamp": {"gte": start_time}}}],
                    "should": [
                        {"wildcard": {"url.original": {"value": "*union*", "case_insensitive": True}}},
                        {"wildcard": {"url.original": {"value": "*script*", "case_insensitive": True}}},
                        {"wildcard": {"url.original": {"value": "*../*", "case_insensitive": True}}},
                        {"range": {"http.response.status_code": {"gte": 400}}}
                    ],
                    "minimum_should_match": 1
                }
            }
        }

        spinner = Spinner(message="[*] Querying SIEM for suspicious activity...")
        spinner.start()
        try:
            response = self.es.search(index=self.index, body=query)
            spinner.stop()
            print("\r" + " " * 50 + "\r", end="") 
            return self._process_hits(response['hits']['hits'])
        except Exception as e:
            spinner.stop()
            print(f"[-] ELK Query Error: {e}")
            return []

    def _process_hits(self, hits):
        alerts = []
        for hit in hits:
            source = hit['_source']
            request_str = source.get("url", {}).get("original", "").lower()
            
            attack_type = "Suspected Malicious Traffic"
            risk = "Medium"

            if "union" in request_str or "select" in request_str:
                attack_type = "SQL Injection Attempt"
                risk = "High"
            elif "script" in request_str:
                attack_type = "Cross-Site Scripting (XSS)"
                risk = "High"
            elif "../" in request_str:
                attack_type = "Path Traversal"
                risk = "High"

            alerts.append({
                "timestamp": source.get("@timestamp"),
                "client_ip": source.get("source", {}).get("address", "Unknown"),
                "request": source.get("url", {}).get("original", "Unknown"),
                "status": source.get("http", {}).get("response", {}).get("status_code", "Unknown"),
                "attack_type": attack_type,
                "risk": risk
            })
        return alerts

    def apply_prevention_measures(self, alerts):
        high_risk_ips = {a['client_ip'] for a in alerts if a['risk'] == "High"}
        if not high_risk_ips:
            return 0

        existing_ips = set()
        if os.path.exists(self.block_list_path):
            with open(self.block_list_path, "r") as f:
                existing_ips = {line.strip() for line in f}

        new_blocks = high_risk_ips - existing_ips
        if new_blocks:
            with open(self.block_list_path, "a") as f:
                for ip in new_blocks:
                    f.write(f"{ip}\n")
        return len(new_blocks)

    def generate_detection_report(self, alerts):
        """
        Processes detected alerts by printing a summary to the console 
        and saving a structured JSON report.
        """
        if not alerts:
            print("[*] Monitoring complete. No threats found in the specified interval.")
            return

        print("-" * 60)
        print(f"[*] SECURITY ALERT SUMMARY - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Total Suspicious Events: {len(alerts)}")
        print("-" * 60)
        
        for alert in alerts[:10]:
            print(f"[{alert['timestamp']}] {alert['attack_type']} | IP: {alert['client_ip']} | Status: {alert['status']}")
        
        if len(alerts) > 10:
            print(f"... and {len(alerts) - 10} more events recorded.")

        report_dir = os.path.join(os.getcwd(), "data", "scans")
        os.makedirs(report_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filepath = os.path.join(report_dir, f"DETECTION_{timestamp}.json")

        report_data = {
            "metadata": {
                "target_environment": "DVWA / ELK Stack",
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "total_alerts": len(alerts),
                "mitigation_status": "IPs logged for prevention"
            },
            "alerts": alerts
        }

        try:
            with open(filepath, "w") as f:
                json.dump(report_data, f, indent=4)
            print("-" * 60)
            print(f"[+] Full evidence report saved: {filepath}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")