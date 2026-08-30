\# CodeGuard 🔐



\### Python Static Code Vulnerability Scanner



CodeGuard is a Python-based static code analysis tool that scans Python source code for potentially insecure coding patterns without executing the target program.



The project uses Python's Abstract Syntax Tree (AST) to inspect source code and generate security findings with severity, line numbers, descriptions, and remediation recommendations.



\---



\## 🚀 Features



\- AST-based static code analysis

\- Hardcoded secret detection

\- Dangerous function detection

\- Command injection risk detection

\- SQL injection risk detection

\- Weak cryptography detection

\- Severity classification

\- Exact line-number reporting

\- Security recommendations

\- Command-line file scanning

\- JSON report generation

\- Input validation and error handling

\- Automated unit tests

\- Basic false-positive reduction



\---



\## 🛠️ Technologies



\- \*\*Python\*\*

\- \*\*AST (Abstract Syntax Tree)\*\*

\- \*\*Object-Oriented Programming\*\*

\- \*\*Static Code Analysis\*\*

\- \*\*JSON\*\*

\- \*\*Unit Testing\*\*

\- \*\*Git \& GitHub\*\*



\---



\## 🔍 Vulnerabilities Detected



| Vulnerability | Severity |

|---|---|

| Hardcoded Secrets | HIGH |

| `eval()` / `exec()` | HIGH |

| `os.system()` Command Injection Risk | HIGH |

| SQL Injection Risk | HIGH |

| MD5 / SHA1 Weak Cryptography | MEDIUM |



\---



\## ⚙️ How It Works



```text

Python Source Code

&#x20;       │

&#x20;       ▼

&#x20;  AST Parser

&#x20;       │

&#x20;       ▼

Security Detection Rules

&#x20;       │

&#x20;       ├── Hardcoded Secrets

&#x20;       ├── Dangerous Functions

&#x20;       ├── Command Injection

&#x20;       ├── SQL Injection

&#x20;       └── Weak Cryptography

&#x20;       │

&#x20;       ▼

&#x20;Security Findings

&#x20;       │

&#x20;       ▼

Severity + Line Number

&#x20;       │

&#x20;       ▼

Recommendations

&#x20;       │

&#x20;       ├── Terminal Report

&#x20;       └── JSON Report

