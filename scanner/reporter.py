class ReportGenerator:

    def generate(self, findings, file_path):

        print("\n" + "=" * 55)
        print("             CODEGUARD SECURITY REPORT")
        print("=" * 55)

        print(f"\nFile: {file_path}\n")

        if not findings:
            print("No security vulnerabilities detected.")
            print("=" * 55)
            return

        high = 0
        medium = 0
        low = 0

        for finding in findings:

            severity = finding["severity"]

            if severity == "HIGH":
                high += 1
            elif severity == "MEDIUM":
                medium += 1
            elif severity == "LOW":
                low += 1

            print(f"[{severity}] {finding['type']}")
            print(f"Line: {finding['line']}")
            print(f"Description: {finding['message']}")
            print(f"Recommendation: {finding['recommendation']}")
            print("-" * 55)

        print("\nSummary")
        print("-" * 55)
        print(f"Total Findings: {len(findings)}")
        print(f"HIGH: {high}")
        print(f"MEDIUM: {medium}")
        print(f"LOW: {low}")

        print("=" * 55)