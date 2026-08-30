import os
import tempfile
import unittest

from scanner.scanner import CodeScanner
from main import find_python_files


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

    def test_directory_scanning(self):

        with tempfile.TemporaryDirectory() as directory:

            file1 = os.path.join(directory, "file1.py")
            file2 = os.path.join(directory, "file2.py")
            text_file = os.path.join(directory, "notes.txt")

            with open(file1, "w", encoding="utf-8") as file:
                file.write("password = 'secret123'\n")

            with open(file2, "w", encoding="utf-8") as file:
                file.write("result = eval('2 + 2')\n")

            with open(text_file, "w", encoding="utf-8") as file:
                file.write("This is not Python.\n")

            python_files = find_python_files(directory)

            self.assertEqual(len(python_files), 2)
            self.assertIn(file1, python_files)
            self.assertIn(file2, python_files)
            self.assertNotIn(text_file, python_files)


if __name__ == "__main__":
    unittest.main()