import argparse
import sys

from scanners.network_scanner import NetworkScanner


def main():
    """Entry point for the TFM security tool. Handles subcommands (e.g. scan)."""
    parser = argparse.ArgumentParser(
        description="TFM: Automated Security Detection and Prevention System",
        add_help=False,
    )

    parser.add_argument("subcommand", nargs="?", help="Action to perform (e.g., scan)")
    parser.add_argument(
        "extra_args", nargs=argparse.REMAINDER, help="Arguments for the subcommand"
    )

    args = parser.parse_args()

    match args.subcommand:
        case "scan":
            if not args.extra_args:
                print("Usage: uv run tool scan <target_ip>")
                sys.exit(1)

            target_ip = args.extra_args[0]
            scanner = NetworkScanner(target_ip)
            scanner.execute()

        case "help" | None:
            print("\n[!] TFM Security Tool - Available Commands:")
            print("  scan <IP>    Run network & vulnerability scans")
            print("  help         Show this message")

        case _:
            print(f"[-] Error: Unknown command '{args.subcommand}'")
            print("[*] Use 'uv run tool help' for available options.")
            sys.exit(1)


if __name__ == "__main__":
    main()
