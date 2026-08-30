import ast


class VulnerabilityRule(ast.NodeVisitor):

    def __init__(self):
        self.findings = []
        self.user_input_variables = set()
        self.dynamic_query_variables = set()

    def add_finding(
        self,
        vulnerability_type,
        severity,
        line,
        message,
        recommendation
    ):
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

        # Detect input()
        if isinstance(node.func, ast.Name):

            if node.func.id == "input":
                # The assignment visitor records the variable
                pass

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

        # Detect SQL execution
        if isinstance(node.func, ast.Attribute):

            if node.func.attr in ["execute", "executemany"]:

                if node.args:

                    query = node.args[0]

                    # A variable previously identified as a dynamic query
                    if isinstance(query, ast.Name):
                        if query.id in self.dynamic_query_variables:
                            self.add_finding(
                                "SQL Injection Risk",
                                "HIGH",
                                node.lineno,
                                "SQL query is dynamically constructed using user-controlled input",
                                "Use parameterized SQL queries instead of string concatenation."
                            )

                    # Direct string formatting or concatenation
                    if isinstance(query, (ast.BinOp, ast.JoinedStr)):
                        self.add_finding(
                            "SQL Injection Risk",
                            "HIGH",
                            node.lineno,
                            "SQL query is dynamically constructed and may contain user-controlled input",
                            "Use parameterized SQL queries instead of string concatenation or string formatting."
                        )

        self.generic_visit(node)

    def visit_Assign(self, node):

        for target in node.targets:

            if not isinstance(target, ast.Name):
                continue

            variable_name = target.id
            variable_lower = variable_name.lower()

            # Detect hardcoded secrets
            secret_words = [
                "password",
                "passwd",
                "api_key",
                "apikey",
                "secret",
                "token"
            ]

            if any(word in variable_lower for word in secret_words):

                if isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str):
                        self.add_finding(
                            "Hardcoded Secret",
                            "HIGH",
                            node.lineno,
                            f"Possible hardcoded secret in variable: {target.id}",
                            "Store secrets securely using environment variables or a secret-management system."
                        )

            # Detect variables receiving user input
            if isinstance(node.value, ast.Call):

                if (
                    isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "input"
                ):
                    self.user_input_variables.add(variable_name)

            # Detect dynamically constructed SQL queries
            if self.is_dynamic_sql(node.value):
                self.dynamic_query_variables.add(variable_name)

        self.generic_visit(node)

    def is_dynamic_sql(self, node):

        # String concatenation
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):

            names = self.get_names(node)

            if names.intersection(self.user_input_variables):
                return True

        # f-strings
        if isinstance(node, ast.JoinedStr):

            names = self.get_names(node)

            if names.intersection(self.user_input_variables):
                return True

        return False

    def get_names(self, node):

        names = set()

        for child in ast.walk(node):

            if isinstance(child, ast.Name):
                names.add(child.id)

        return names