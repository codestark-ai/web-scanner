import ast
import os
import re
import math
from base.base_scanner import BaseScanner


class ASTSecurityScanner(BaseScanner):
    name = "Next-Level AST Security Review"
    severity = "Critical"
    owasp = "A03:2021"

    DANGEROUS_FUNCTIONS = {
        "eval": "Critical",
        "exec": "Critical",
        "os.system": "High",
        "subprocess.Popen": "High",
        "pickle.loads": "High"
    }

    WEAK_HASH = ["md5", "sha1"]

    def scan(self, directory):
        findings = []
        total_score = 0

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    file_findings = self.scan_file(path)
                    findings.extend(file_findings)
                    for f in file_findings:
                        total_score += f["risk_score"]

        if not findings:
            return None

        return {
            "name": self.name,
            "severity": self.calculate_severity(total_score),
            "owasp": self.owasp,
            "total_risk_score": total_score,
            "total_findings": len(findings),
            "details": findings
        }

    # ---------------- AST FILE SCAN ----------------

    def scan_file(self, file_path):
        results = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=file_path)

            for node in ast.walk(tree):

                # Detect Dangerous Function Calls
                if isinstance(node, ast.Call):
                    func_name = self.get_function_name(node)

                    if func_name in self.DANGEROUS_FUNCTIONS:
                        severity = self.DANGEROUS_FUNCTIONS[func_name]
                        results.append(self.build_finding(
                            file_path,
                            node.lineno,
                            f"Dangerous function call: {func_name}",
                            severity,
                            9 if severity == "Critical" else 7
                        ))

                # Weak Hash Detection
                if isinstance(node, ast.Call):
                    func_name = self.get_function_name(node)
                    if func_name in self.WEAK_HASH:
                        results.append(self.build_finding(
                            file_path,
                            node.lineno,
                            f"Weak hashing algorithm used: {func_name}",
                            "Medium",
                            5
                        ))

                # Hardcoded Secret Detection (AST string analysis)
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if re.search(r"(secret|password|key)", target.id, re.I):
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    results.append(self.build_finding(
                                        file_path,
                                        node.lineno,
                                        f"Hardcoded secret: {target.id}",
                                        "Critical",
                                        10
                                    ))

        except Exception:
            pass

        return results

    # ---------------- UTILITIES ----------------

    def get_function_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else node.func.attr
        return ""

    def build_finding(self, file, line, issue, severity, score):
        return {
            "file": file,
            "line": line,
            "issue": issue,
            "severity": severity,
            "risk_score": score,
            "confidence": "High"
        }

    def calculate_severity(self, score):
        if score >= 40:
            return "Critical"
        elif score >= 25:
            return "High"
        elif score >= 10:
            return "Medium"
        return "Low"
