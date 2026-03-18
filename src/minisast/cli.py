import argparse
from pathlib import Path

from minisast.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minisast")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path")

    return parser


def print_findings(findings) -> None:
    if not findings:
        print("No findings.")
        return

    for finding in findings:
        print(f"[{finding.severity}] {finding.rule_id}")
        print(f"  File: {finding.file}")
        print(f"  Line: {finding.line}")
        print(f"  Message: {finding.message}")
        print()

    print(f"Total findings: {len(findings)}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        target = Path(args.path)

        if not target.exists():
            print(f"Path does not exist: {target}")
            return 1

        findings = scan_path(target)
        print_findings(findings)

        if findings:
            return 1
        return 0

    parser.print_help()
    return 1
