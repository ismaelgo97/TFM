import argparse
import sys
from scanners.network_scanner import NetworkScanner
from scanners.web_scanner import WebScanner

def main():
    parser = argparse.ArgumentParser(description="TFM Security Tool - Detection & Prevention")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Network Scan Command
    net_parser = subparsers.add_parser("scan", help="Run network scan")
    net_parser.add_argument("target", help="Target IP address")
    net_parser.add_argument("-v", "--vulnerability", action="store_true", help="Enable vulnerability scripts")

    # Web Scan Command
    web_parser = subparsers.add_parser("web-scan", help="Run web vulnerability scan")
    web_parser.add_argument("target", help="Target IP/URL")
    web_parser.add_argument("-u", "--username", required=True, help="Login username")
    web_parser.add_argument("-p", "--password", required=True, help="Login password")

    args = parser.parse_args()

    if args.command == "scan":
        scanner = NetworkScanner(args.target, vuln_scan=args.vulnerability)
        scanner.execute()

    elif args.command == "web-scan":
        scanner = WebScanner(args.target, args.username, args.password)
        scanner.execute()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
