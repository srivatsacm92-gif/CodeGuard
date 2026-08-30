import unittest

from scanner.scanner import CodeScanner


class TestCodeScanner(unittest.TestCase):

    def test_vulnerable_file(self):
        scanner = CodeScanner()

        findings = scanner.scan("examples/vulnerable.py")

        self.assertGreaterEqual(len(findings), 6)

    def test_eval_detection(self):
        scanner = CodeScanner()

        findings = scanner.scan("examples/vulnerable.py")

        vulnerability_types = [
            finding["type"]
            for finding in findings
        ]

        self.assertIn("Dangerous Function", vulnerability_types)

    def test_secret_detection(self):
        scanner = CodeScanner()

        findings = scanner.scan("examples/vulnerable.py")

        vulnerability_types = [
            finding["type"]
            for finding in findings
        ]

        self.assertIn("Hardcoded Secret", vulnerability_types)

    def test_sql_injection_detection(self):
        scanner = CodeScanner()

        findings = scanner.scan("examples/vulnerable.py")

        vulnerability_types = [
            finding["type"]
            for finding in findings
        ]

        self.assertIn("SQL Injection Risk", vulnerability_types)


if __name__ == "__main__":
    unittest.main()