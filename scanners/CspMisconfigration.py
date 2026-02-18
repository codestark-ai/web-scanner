from base.base_scanner import BaseScanner
from utils.request_handler import send_request

class CSPMisconfigurationScanner(BaseScanner):
    name = "CSP Misconfiguration"
    severity = "Medium"
    owasp = "A05:2021"  # Security Misconfiguration

    def scan(self, url):
        res = send_request(url)
        if not res:
            return None

        csp = res.headers.get("Content-Security-Policy")

        if not csp:
            return {
                "name": "Missing Content-Security-Policy",
                "severity": "Medium",
                "owasp": self.owasp,
                "details": "Content-Security-Policy header is not set."
            }

        issues = []

        # Common weak patterns
        if "unsafe-inline" in csp:
            issues.append("Uses 'unsafe-inline'")

        if "unsafe-eval" in csp:
            issues.append("Uses 'unsafe-eval'")

        if "*" in csp:
            issues.append("Uses wildcard (*) in policy")

        if "http:" in csp:
            issues.append("Allows insecure HTTP sources")

        if "data:" in csp:
            issues.append("Allows data: URI sources")

        if issues:
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": f"Weak CSP configuration detected: {', '.join(issues)}"
            }

        return None
