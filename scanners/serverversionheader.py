from base.base_scanner import BaseScanner
from utils.request_handler import send_request

class ServerVersionHeaderScanner(BaseScanner):
    name = "Server Version Disclosure"
    severity = "Low"
    owasp = "A06:2021"

    def scan(self, url):
        res = send_request(url)
        if not res:
            return None

        server = res.headers.get("Server")
        powered_by = res.headers.get("X-Powered-By")

        if server or powered_by:
            details = []
            if server:
                details.append(f"Server: {server}")
            if powered_by:
                details.append(f"X-Powered-By: {powered_by}")

            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": " | ".join(details)
            }

        return None
