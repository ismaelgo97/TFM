import argparse
from scanners.network_scanner import NetworkScanner
from scanners.web_scanner import WebScanner
from detection.elk_monitor import ELKMonitor

def main():
    # The Main Parser - entry point for the TFM Security Tool
    parser = argparse.ArgumentParser(
        description="TFM Security Tool: Automated Detection & Prevention System\n"
                    "Developed for Master's in Computer Engineering - UMA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples of Use:\n"
            "  1. Network Discovery: uv run tool scan 192.168.122.27 -v\n"
            "  2. Web DAST Scan:      uv run tool web-scan 192.168.122.27/DVWA -u admin -p password\n"
            "\nReports are automatically saved in the /data/scans directory."
        ),
    )
    
    # Subparsers for command-specific logic (Phase 1.1)
    subparsers = parser.add_subparsers(
        dest="command", 
        title="Available Security Commands",
        description="Select a module to execute Phase 1 Vulnerability Analysis",
        help="Use 'command -h' for more info on a specific module"
    )

    # ==========================================
    # 1. Network Scan Command (Nmap-based)
    # ==========================================
    net_parser = subparsers.add_parser("scan", help="Perform Network & Service Discovery")
    net_parser.add_argument("target", help="IP address or range to scan")
    net_parser.add_argument(
        "-v", "--vulnerability",
        action="store_true",
        help="Run NSE scripts to detect service-level vulnerabilities"
    )

    # ==========================================
    # 2. Web Scan Command (ZAP-based)
    # ==========================================
    web_parser = subparsers.add_parser("web-scan", help="Perform Authenticated Web DAST")
    web_parser.add_argument("target", help="Target URL (e.g., 192.168.122.27/DVWA)")
    web_parser.add_argument("-u", "--username", required=True, help="Application login username")
    web_parser.add_argument("-p", "--password", required=True, help="Application login password")
    web_parser.add_argument(
        "-r", "--routes",
        nargs="+",
        help="Custom routes to prioritize during spidering (e.g., /vulnerabilities/sqli/)",
        default=None,
    )

    # ==========================================
    # 3. Intrusion Detection Command (ELK-based)
    # ==========================================
    detect_parser = subparsers.add_parser("detect", help="Query ELK for real-time intrusions")
    detect_parser.add_argument(
        "-H", "--host",
        default="localhost",
        help="Elasticsearch host (default: localhost)"
    )
    detect_parser.add_argument(
        "-i", "--interval", 
        type=int, 
        default=5, 
        help="Minutes of logs to analyze (default: 5)"
    )

    args = parser.parse_args()

    match args.command:
        case "scan":
            print(f"[*] Starting Network Scan on {args.target}...")
            try:
                scanner = NetworkScanner(args.target, vuln_scan=args.vulnerability)
                scanner.execute()
            except Exception as e:
                print(f"[-] Network Scan Failed: {e}")

        case "web-scan":
            print(f"[*] Starting Web Application Scan on {args.target}...")
            try:
                scanner = WebScanner(args.target, args.username, args.password)
                scanner.run_scan(seed_routes=args.routes)
            except Exception as e:
                if "ZAP is not running" in str(e):
                    print("[-] Error: ZAP is not reachable.")
                    print("[*] Please run: zaproxy -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true")
                else:
                    print(f"[-] Web Scan Failed: {e}")

        case "detect":
            elk_url = f"http://{args.host}:9200"
            print(f"[*] Connecting to SIEM at {elk_url}...")
            
            try:
                monitor = ELKMonitor(host=elk_url)
                if not monitor.check_connection():
                    print(f"[-] Error: Could not connect to {elk_url}")
                    return
                
                alerts = monitor.query_alerts(interval_minutes=args.interval)
                
                if alerts:
                    monitor.generate_detection_report(alerts)
                    # Trigger Prevention
                    blocked_count = monitor.apply_prevention_measures(alerts)
                    if blocked_count > 0:
                        print(f"[!] ACTIVE RESPONSE: {blocked_count} malicious IP(s) added to block list.")
                else:
                    print("[*] Monitoring complete. No threats found.")

            except Exception as e:
                print(f"[-] Intrusion Detection Failed: {e}")

        case _:
            parser.print_help()

if __name__ == "__main__":
    main()