\# CodeGuard



CodeGuard is a Python-based static code vulnerability scanner that analyzes Python source code without executing it.



\## Features



\- AST-based static code analysis

\- Hardcoded secret detection

\- Dangerous function detection

\- Command injection risk detection

\- SQL injection risk detection

\- Weak cryptography detection

\- Severity classification

\- Line-number reporting

\- Security recommendations

\- Terminal security reports

\- JSON report generation

\- Command-line file scanning

\- Automated unit testing

\- Basic false-positive reduction



\## Technologies Used



\- Python

\- Abstract Syntax Tree (AST)

\- Object-Oriented Programming

\- Static Code Analysis

\- JSON

\- Unit Testing



\## How It Works



CodeGuard parses Python source code into an Abstract Syntax Tree (AST).



The scanner analyzes the structure of the code using security rules and identifies potentially vulnerable patterns.



The detected issues are then presented with:



\- Vulnerability type

\- Severity

\- Line number

\- Description

\- Recommended remediation



\## Usage



Run CodeGuard from the project directory:



```bash

python main.py examples\\vulnerable.py

