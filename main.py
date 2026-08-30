import argparse
import os

from scanner.scanner import CodeScanner
from scanner.reporter import ReportGenerator
from scanner.json_reporter import JSONReporter


def find_python_files(path):
    if os.path.isfile(path):
        if path.endswith(".py"):
            return [path]
        return []

    python_files = []

    for root, dirs, files in os.walk(path):
        # Ignore Python cache directories
        dirs[:] = [
            directory
            for directory in dirs
            if directory != "__pycache__"
        ]

        for file in files:
            if file.endswith(".py"):
                python_files.append(
                    os.path.join(root, file)
                )

    return python_files


def main():

    parser = argparse.ArgumentParser(
        description="CodeGuard - Python Static Code Vulnerability Scanner"
    )

    parser.add_argument(
        "path",
        help="Path to a Python file or directory to scan"
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

    files = find_python_files(args.path)

    if not files:
        print(f"ERROR: No Python files found in: {args.path}")
        return

    scanner = CodeScanner()

    all_findings = []

    print("\n=======================================================")
    print("             CODEGUARD SECURITY SCAN")
    print("=======================================================")
    print(f"Files found: {len(files)}")

    for file_path in files:

        if not scanner.validate_file(file_path):
            continue

        findings = scanner.scan(file_path)

        all_findings.extend(
            [
                {
                    **finding,
                    "file": file_path
                }
                for finding in findings
            ]
        )

        reporter = ReportGenerator()
        reporter.generate(findings, file_path)

    print("\n=======================================================")
    print("                    SCAN SUMMARY")
    print("=======================================================")

    high = sum(
        1 for finding in all_findings
        if finding["severity"] == "HIGH"
    )

    medium = sum(
        1 for finding in all_findings
        if finding["severity"] == "MEDIUM"
    )

    low = sum(
        1 for finding in all_findings
        if finding["severity"] == "LOW"
    )

    print(f"Files scanned: {len(files)}")
    print(f"Total findings: {len(all_findings)}")
    print(f"HIGH: {high}")
    print(f"MEDIUM: {medium}")
    print(f"LOW: {low}")

    print("=======================================================")

    if args.json:

        json_reporter = JSONReporter()

        json_reporter.generate(
            all_findings,
            args.path,
            args.output
        )


if __name__ == "__main__":
    main()