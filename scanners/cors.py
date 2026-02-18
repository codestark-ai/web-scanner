<<<<<<< HEAD
from base.base_scanner import BaseScanner
from utils.request_handler import send_request

class CORSScanner(BaseScanner):
    name = "CORS Misconfiguration"
    severity = "High"
    owasp = "A05:2021"

    def scan(self, url):
        res = send_request(url)
        if not res:
            return None

        origin = res.headers.get("Access-Control-Allow-Origin")
        credentials = res.headers.get("Access-Control-Allow-Credentials")

        if origin == "*" and credentials == "true":
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": "Access-Control-Allow-Origin set to '*' with credentials enabled"
            }

        return None
=======
from base.base_scanner import BaseScanner
from utils.request_handler import send_request

class CORSScanner(BaseScanner):
    name = "CORS Misconfiguration"
    severity = "High"
    owasp = "A05:2021"

    def scan(self, url):
        res = send_request(url)
        if not res:
            return None

        origin = res.headers.get("Access-Control-Allow-Origin")
        credentials = res.headers.get("Access-Control-Allow-Credentials")

        if origin == "*" and credentials == "true":
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": "Access-Control-Allow-Origin set to '*' with credentials enabled"
            }

        return None
>>>>>>> e45baed0a6b96ca70b4f8c0a1652a2b46b788059
