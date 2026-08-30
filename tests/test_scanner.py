import os
import tempfile
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

    def test_safe_parameterized_query(self):

        safe_code = '''
import sqlite3

connection = sqlite3.connect("users.db")
cursor = connection.cursor()

username = input("Username: ")

query = "SELECT * FROM users WHERE username = ?"

cursor.execute(query, (username,))
'''

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8"
        ) as file:

            file.write(safe_code)
            file_path = file.name

        try:
            scanner = CodeScanner()
            findings = scanner.scan(file_path)

            sql_findings = [
                finding
                for finding in findings
                if finding["type"] == "SQL Injection Risk"
            ]

            self.assertEqual(len(sql_findings), 0)

        finally:
            os.remove(file_path)


if __name__ == "__main__":
    unittest.main()