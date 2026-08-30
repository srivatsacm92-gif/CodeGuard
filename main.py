import sys

from scanner.scanner import CodeScanner
from scanner.reporter import ReportGenerator
from scanner.json_reporter import JSONReporter


if len(sys.argv) != 2:
    print("Usage: python main.py <python_file>")
    sys.exit(1)


file_path = sys.argv[1]

scanner = CodeScanner()

if not scanner.validate_file(file_path):
    sys.exit(1)

findings = scanner.scan(file_path)

reporter = ReportGenerator()
reporter.generate(findings, file_path)

json_reporter = JSONReporter()
json_reporter.generate(
    findings,
    file_path,
    "codeguard_report.json"
)