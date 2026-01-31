import argparse
import sys
from scanners.network_scanner import NetworkScanner
from scanners.web_scanner import WebScanner

def main():
    parser = argparse.ArgumentParser(description="TFM Security Tool - Detection & Prevention")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    net_parser = subparsers.add_parser("scan", help="Run network scan")
    net_parser.add_argument("target", help="Target IP address")
    net_parser.add_argument("-v", "--vulnerability", action="store_true", help="Enable vulnerability scripts")

    # ==========================================
    # 2. Web Scan Command
    # ==========================================
    web_parser = subparsers.add_parser("web-scan", help="Run web vulnerability scan")
    web_parser.add_argument("target", help="Target IP/URL (e.g., 192.168.1.1/DVWA)")
    web_parser.add_argument("-u", "--username", required=True, help="Login username")
    web_parser.add_argument("-p", "--password", required=True, help="Login password")

    web_parser.add_argument(
        "-r", "--routes", 
        nargs='+', 
        help="List of specific relative routes to seed the scanner with (space separated)",
        default=None
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
                # Pass the list of routes directly to the run_scan method
                scanner.run_scan(seed_routes=args.routes)
            except Exception as e:
                print(f"[-] Web Scan Failed: {e}")

        case _:
            parser.print_help()

if __name__ == "__main__":
    main()