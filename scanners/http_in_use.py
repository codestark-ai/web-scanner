from base.base_scanner import BaseScanner
from utils.request_handler import send_request
from urllib.parse import urlparse

class InsecureHTTPScanner(BaseScanner):
    name = "Insecure HTTP Usage"
    severity = "Medium"
    owasp = "A02:2021"   # Cryptographic Failures

    def scan(self, url):
        parsed = urlparse(url)

        # Check if URL uses HTTP instead of HTTPS
        if parsed.scheme.lower() == "http":
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": "Website is accessible over insecure HTTP protocol."
            }

        # Optional: Check if HTTPS automatically redirects to HTTP
        try:
            res = send_request(url)
            if res and res.url.startswith("http://"):
                return {
                    "name": self.name,
                    "severity": self.severity,
                    "owasp": self.owasp,
                    "details": "Website redirects users from HTTPS to insecure HTTP."
                }
        except Exception:
            return None

        return None
