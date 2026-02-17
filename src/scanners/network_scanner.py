import shutil
import os
import json
from datetime import datetime

import nmap

from utils import Spinner


class NetworkScanner:
    def __init__(self, target_ip, vuln_scan=False):
        self.target = target_ip
        self.vuln_scan = vuln_scan
        self.nm = None

    def _is_installed(self):
        return shutil.which("nmap") is not None

    def execute(self):
        """Runs Nmap (-sV -T4, optionally --script vuln), then prints the report."""
        if not self._is_installed():
            print("[-] Error: Nmap binary not found.")
            return

        self.nm = nmap.PortScanner()
        scan_type = "vulnerability" if self.vuln_scan else "basic"
        print(f"[*] Running {scan_type} scan on {self.target}...")

        spinner = Spinner(
            message="[*] Scanning ports and services (this may take a while)..."
        )
        spinner.start()

        try:
            args = "-sV -T4"
            if self.vuln_scan:
                args += " --script vuln"
            self.nm.scan(self.target, arguments=args)
            spinner.stop()
            self._save_report()
        except Exception as e:
            spinner.stop()
            print(f"\n[-] Scan error: {e}")

    def _save_report(self):
        """
        Saves Nmap results (ports, services, and vulns) to a JSON file in /data/scans/.
        Fulfills TFM Phase 4: Registration and Reports.
        """
        if self.target not in self.nm.all_hosts():
            print(f"[-] No live hosts found at {self.target}.")
            return

        # 1. Define and create the directory
        report_dir = os.path.join(os.getcwd(), "data", "scans")
        os.makedirs(report_dir, exist_ok=True)

        # 2. Format the filename as requested
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"NETWORK_SCAN_{timestamp}.json"
        filepath = os.path.join(report_dir, filename)

        # 3. Build the data structure
        scan_results = {
            "scan_metadata": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "tool": "Nmap",
                "status": self.nm[self.target].state()
            },
            "protocols": {}
        }

        for proto in self.nm[self.target].all_protocols():
            scan_results["protocols"][proto] = []
            
            ports = sorted(self.nm[self.target][proto].keys())
            for port in ports:
                port_data = self.nm[self.target][proto][port]
                
                # Capture standard port info
                entry = {
                    "port": port,
                    "state": port_data["state"],
                    "service": port_data.get("name", "unknown"),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                    "vulnerabilities": []
                }

                # Capture Nmap Script Engine (NSE) findings (Phase 1.1)
                if "script" in port_data:
                    for script_id, output in port_data["script"].items():
                        entry["vulnerabilities"].append({
                            "script_id": script_id,
                            "output": output.strip()
                        })
                
                scan_results["protocols"][proto].append(entry)

        # 4. Write to JSON file
        with open(filepath, "w") as f:
            json.dump(scan_results, f, indent=4)

        print("\n" + "=" * 60)
        print(f"[+] Network Scan Complete. Report generated at:")
        print(f"    {filepath}")
        print("=" * 60)

if __name__ == "__main__":
    TARGET = "192.168.122.27"
    scanner = NetworkScanner(TARGET, vuln_scan=False)
    scanner.execute()
