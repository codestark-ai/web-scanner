from base.base_scanner import BaseScanner
from utils.request_handler import send_request

class ClickjackingScanner(BaseScanner):
    name = "Clickjacking"
    severity = "Medium"
    owasp = "A05:2021"

    def scan(self, url):
        res = send_request(url)
        if not res:
            return None

        if "X-Frame-Options" not in res.headers:
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": "X-Frame-Options header missing"
            }
        return None
