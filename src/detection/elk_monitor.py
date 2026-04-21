import json
import os
from datetime import UTC, datetime, timedelta

from elasticsearch import Elasticsearch

from detection.anomalies import AnomalyEngine
from detection.correlation import CorrelationEngine
from detection.signatures import SignatureEngine
from utils.ui_utils import Spinner

# Max events pulled from Elasticsearch in one window. 5000 is well below the
# default index.max_result_window of 10000 and is enough for a lab run.
MAX_HITS = 5000


class ELKMonitor:
    """Pulls Apache logs from the SIEM and runs the three detection engines.

    The workflow is straightforward:
        1. fetch every access log from the last N minutes,
        2. flatten the ECS fields we care about,
        3. feed them through signatures, anomalies and correlation,
        4. write a consolidated JSON report and update the block list.
    """

    def __init__(self, host="http://localhost:9200"):
        self.es = Elasticsearch([host], request_timeout=30)
        self.index = "*filebeat*"
        self.block_list_path = os.path.join(
            os.getcwd(), "data", "firewall", "blocked_ips.txt"
        )
        os.makedirs(os.path.dirname(self.block_list_path), exist_ok=True)

        self.signatures = SignatureEngine()
        self.anomalies = AnomalyEngine()
        self.correlation = CorrelationEngine()

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def check_connection(self):
        try:
            return self.es.ping()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def fetch_events(self, interval_minutes):
        """Pulls every Apache access log written to the SIEM in the window."""
        start_time = (
            datetime.now(UTC) - timedelta(minutes=interval_minutes)
        ).isoformat()

        query = {
            "size": MAX_HITS,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "range": {"@timestamp": {"gte": start_time}}
            },
        }

        spinner = Spinner(message="[*] Pulling logs from SIEM...")
        spinner.start()
        try:
            response = self.es.search(index=self.index, body=query)
            spinner.stop()
            print("\r" + " " * 50 + "\r", end="")
            return [self._flatten(h["_source"]) for h in response["hits"]["hits"]]
        except Exception as e:
            spinner.stop()
            print(f"[-] ELK Query Error: {e}")
            return []

    @staticmethod
    def _flatten(source):
        """Reduce an ECS document to the fields the detection engines need."""
        http = source.get("http") or {}
        http_req = http.get("request") or {}
        http_res = http.get("response") or {}
        url = source.get("url") or {}
        src = source.get("source") or {}
        client = source.get("client") or {}
        ua = source.get("user_agent") or {}

        return {
            "timestamp": source.get("@timestamp"),
            "client_ip": (
                src.get("address") or client.get("ip") or "Unknown"
            ),
            "request": url.get("original") or "",
            "status": http_res.get("status_code"),
            "method": http_req.get("method") or "",
            "user_agent": ua.get("original") or "",
        }

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyse(self, events):
        """Runs signatures, anomalies and correlation over the same window."""
        alerts = []
        for ev in events:
            alerts.extend(self.signatures.inspect(ev))
        alerts.extend(self.anomalies.inspect(events))
        alerts.extend(self.correlation.inspect(events, alerts))
        return alerts

    def query_alerts(self, interval_minutes=60):
        events = self.fetch_events(interval_minutes)
        if not events:
            return []
        return self.analyse(events)

    # ------------------------------------------------------------------
    # Prevention
    # ------------------------------------------------------------------

    def apply_prevention_measures(self, alerts):
        """Appends high-risk IPs to the firewall block list."""
        high_risk = {
            a["client_ip"] for a in alerts
            if a.get("risk") == "High"
            and a.get("client_ip") not in (None, "Unknown", "multiple")
        }
        if not high_risk:
            return 0

        existing = set()
        if os.path.exists(self.block_list_path):
            with open(self.block_list_path) as f:
                existing = {line.strip() for line in f}

        new_blocks = high_risk - existing
        if new_blocks:
            with open(self.block_list_path, "a") as f:
                for ip in new_blocks:
                    f.write(f"{ip}\n")
        return len(new_blocks)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_detection_report(self, alerts):
        """Prints a human summary and saves the full JSON evidence file."""
        if not alerts:
            print("[*] Monitoring complete. No threats found in the interval.")
            return

        counts = {"signature": 0, "anomaly": 0, "correlation": 0}
        for a in alerts:
            counts[a.get("source", "signature")] = (
                counts.get(a.get("source", "signature"), 0) + 1
            )

        print("-" * 60)
        print(
            f"[*] SECURITY ALERT SUMMARY - "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(f"[*] Total events raised: {len(alerts)}")
        print(
            f"    Signatures: {counts['signature']} | "
            f"Anomalies: {counts['anomaly']} | "
            f"Correlations: {counts['correlation']}"
        )
        print("-" * 60)

        for alert in alerts[:15]:
            ts = alert.get("timestamp") or "-"
            print(
                f"[{ts}] ({alert['source']}) {alert['attack_type']} | "
                f"IP: {alert['client_ip']} | {alert.get('evidence', '')}"
            )

        if len(alerts) > 15:
            print(f"... and {len(alerts) - 15} more alerts recorded.")

        report_dir = os.path.join(os.getcwd(), "data", "scans")
        os.makedirs(report_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filepath = os.path.join(report_dir, f"DETECTION_{timestamp}.json")

        report_data = {
            "metadata": {
                "target_environment": "DVWA / ELK Stack",
                "analysis_timestamp": datetime.now(UTC).isoformat(),
                "total_alerts": len(alerts),
                "breakdown": counts,
                "mitigation_status": "High-risk IPs logged to firewall block list",
            },
            "alerts": alerts,
        }

        try:
            with open(filepath, "w") as f:
                json.dump(report_data, f, indent=4)
            print("-" * 60)
            print(f"[+] Full evidence report saved: {filepath}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")
