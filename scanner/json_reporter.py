import json


class JSONReporter:

    def generate(self, findings, file_path, output_file):

        report = {
            "file": file_path,
            "total_findings": len(findings),
            "findings": findings
        }

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(f"\nJSON report saved to: {output_file}")