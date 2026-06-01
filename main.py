import ast
import json

class CodeSecurityAuditor(ast.NodeVisitor):
    """
    AST-Based Code Security Auditor
    Inspects Python abstract syntax trees for dangerous constructs (eval, exec, subprocess, etc.).
    """
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                self.issues.append({
                    "severity": "CRITICAL",
                    "line": node.lineno,
                    "message": f"Use of dangerous built-in '{node.func.id}' detected."
                })
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in ("subprocess", "os"):
                self.issues.append({
                    "severity": "WARNING",
                    "line": node.lineno,
                    "message": f"Import of system interface '{alias.name}' detected. Ensure inputs are sanitized."
                })
        self.generic_visit(node)

if __name__ == "__main__":
    source_code = """
import os
import subprocess

def dangerous_func(user_input):
    eval(user_input)
"""
    tree = ast.parse(source_code)
    auditor = CodeSecurityAuditor()
    auditor.visit(tree)
    print("Auditor Scan Findings:")
    print(json.dumps(auditor.issues, indent=2))
