import ast
import os

from scanner.rules import VulnerabilityRule


class CodeScanner:

    def __init__(self):
        self.findings = []

    def validate_file(self, file_path):

        if not os.path.exists(file_path):
            print(f"ERROR: File not found: {file_path}")
            return False

        if not file_path.endswith(".py"):
            print("ERROR: CodeGuard currently supports Python files only.")
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                source_code = file.read()

            ast.parse(source_code)

        except SyntaxError as error:
            print(
                f"ERROR: Invalid Python syntax at line {error.lineno}: "
                f"{error.msg}"
            )
            return False

        except Exception as error:
            print(f"ERROR: Unable to read file: {error}")
            return False

        return True

    def scan(self, file_path):

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                source_code = file.read()

            tree = ast.parse(source_code)

        except Exception:
            return []

        rule = VulnerabilityRule()
        rule.visit(tree)

        self.findings = rule.findings

        return self.findings