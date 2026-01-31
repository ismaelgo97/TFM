import shutil

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
        """Runs Nmap with service detection and vuln scripts, then prints the report."""
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
            self._print_report()
        except Exception as e:
            spinner.stop()
            print(f"\n[-] Scan error: {e}")

    def _print_report(self):
        """Prints ports, services and vuln script output for classification."""
        if self.target not in self.nm.all_hosts():
            print(f"[-] No live hosts found at {self.target}.")
            return

        print(f"\n[+] Detailed Results for {self.target}:")

        for proto in self.nm[self.target].all_protocols():
            print(f"\nProtocol: {proto.upper()}")

            ports = sorted(self.nm[self.target][proto].keys())
            for port in ports:
                port_data = self.nm[self.target][proto][port]
                state = port_data["state"]
                service = port_data.get("name", "unknown")
                product = port_data.get("product", "")
                version = port_data.get("version", "")

                # Basic port info
                print(f"\n[Port {port}]")
                print(f"  Status:  {state}")
                print(f"  Service: {service} {product} {version}".strip())

                # Extract Script Output (Vulnerabilities)
                if "script" in port_data:
                    print("  Vulnerabilities detected:")
                    for script_id, output in port_data["script"].items():
                        clean_output = output.replace("\n", "\n      ")
                        print(f"    - [{script_id}]: {clean_output}")
