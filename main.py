import argparse

from scanner.scanner import CodeScanner
from scanner.reporter import ReportGenerator
from scanner.json_reporter import JSONReporter


def main():

    parser = argparse.ArgumentParser(
        description="CodeGuard - Python Static Code Vulnerability Scanner"
    )

    parser.add_argument(
        "file",
        help="Path to the Python file to scan"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate a JSON security report"
    )

    parser.add_argument(
        "--output",
        default="codeguard_report.json",
        help="JSON output filename"
    )

    args = parser.parse_args()

    file_path = args.file

    scanner = CodeScanner()

    if not scanner.validate_file(file_path):
        return

    findings = scanner.scan(file_path)

    reporter = ReportGenerator()
    reporter.generate(findings, file_path)

    if args.json:

        json_reporter = JSONReporter()

        json_reporter.generate(
            findings,
            file_path,
            args.output
        )


if __name__ == "__main__":
    main()