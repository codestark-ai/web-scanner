<<<<<<< HEAD
from base.base_scanner import BaseScanner
from utils.request_handler import send_request

class MissingSecurityHeadersScanner(BaseScanner):
    name = "Missing Security Headers"
    severity = "Medium"
    owasp = "A05:2021"

    REQUIRED_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    def scan(self, url):
        res = send_request(url)
        if not res:
            return None

        missing = []
        for header in self.REQUIRED_HEADERS:
            if header not in res.headers:
                missing.append(header)

        if missing:
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": f"Missing headers: {', '.join(missing)}"
            }

        return None
=======
from base.base_scanner import BaseScanner
from utils.request_handler import send_request

class MissingSecurityHeadersScanner(BaseScanner):
    name = "Missing Security Headers"
    severity = "Medium"
    owasp = "A05:2021"

    REQUIRED_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "X-Frame-Options"
    ]

    def scan(self, url):
        res = send_request(url)
        if not res:
            return None

        missing = []
        for header in self.REQUIRED_HEADERS:
            if header not in res.headers:
                missing.append(header)

        if missing:
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": f"Missing headers: {', '.join(missing)}"
            }

        return None

>>>>>>> e45baed0a6b96ca70b4f8c0a1652a2b46b788059
