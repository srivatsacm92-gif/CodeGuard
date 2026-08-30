import ast


class VulnerabilityRule(ast.NodeVisitor):

    def __init__(self):
        self.findings = []

    def add_finding(self, vulnerability_type, severity, line, message, recommendation):
        self.findings.append({
            "type": vulnerability_type,
            "severity": severity,
            "line": line,
            "message": message,
            "recommendation": recommendation
        })

    def visit_Call(self, node):

        # Detect eval() and exec()
        if isinstance(node.func, ast.Name):

            if node.func.id in ["eval", "exec"]:
                self.add_finding(
                    "Dangerous Function",
                    "HIGH",
                    node.lineno,
                    f"Use of dangerous function: {node.func.id}()",
                    "Avoid eval() or exec() with untrusted input. Use safer alternatives."
                )

        # Detect os.system()
        if isinstance(node.func, ast.Attribute):

            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "system"
            ):
                self.add_finding(
                    "Command Injection Risk",
                    "HIGH",
                    node.lineno,
                    "Use of os.system() may allow command injection",
                    "Avoid os.system() with user-controlled input. Use safer subprocess methods with validated arguments."
                )

        # Detect weak hashing algorithms
        if isinstance(node.func, ast.Attribute):

            weak_hashes = ["md5", "sha1"]

            if node.func.attr.lower() in weak_hashes:
                self.add_finding(
                    "Weak Cryptography",
                    "MEDIUM",
                    node.lineno,
                    f"Use of weak hash algorithm: {node.func.attr.upper()}",
                    "Use a modern cryptographic algorithm appropriate for the security requirement."
                )

        # Detect possible SQL injection
        if isinstance(node.func, ast.Attribute):

            if node.func.attr in ["execute", "executemany"]:

                if node.args:

                    query = node.args[0]

                    if isinstance(query, ast.Name):
                        self.add_finding(
                            "SQL Injection Risk",
                            "HIGH",
                            node.lineno,
                            "SQL query may contain dynamically constructed user input",
                            "Use parameterized SQL queries instead of constructing queries with user input."
                        )

        self.generic_visit(node)

    def visit_Assign(self, node):

        # Detect hardcoded secrets
        for target in node.targets:

            if isinstance(target, ast.Name):

                variable_name = target.id.lower()

                secret_words = [
                    "password",
                    "passwd",
                    "api_key",
                    "apikey",
                    "secret",
                    "token"
                ]

                if any(word in variable_name for word in secret_words):

                    # Only flag actual string values
                    if isinstance(node.value, ast.Constant):

                        if isinstance(node.value.value, str):

                            self.add_finding(
                                "Hardcoded Secret",
                                "HIGH",
                                node.lineno,
                                f"Possible hardcoded secret in variable: {target.id}",
                                "Store secrets securely using environment variables or a secret-management system."
                            )

        self.generic_visit(node)