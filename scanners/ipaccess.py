from base.base_scanner import BaseScanner
from utils.request_handler import send_request
from urllib.parse import urlparse
import socket

class DirectIPAccessScanner(BaseScanner):
    name = "Direct IP Access"
    severity = "Medium"
    owasp = "A05:2021"

    def scan(self, url):
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return None

        try:
            # Resolve domain to IP
            ip_address = socket.gethostbyname(hostname)

            # Build IP-based URL
            ip_url = url.replace(hostname, ip_address)

            # Send request using IP
            ip_response = send_request(ip_url)

            if not ip_response:
                return None

            # Check if application responds successfully via IP
            if ip_response.status_code < 400:
                return {
                    "name": self.name,
                    "severity": self.severity,
                    "owasp": self.owasp,
                    "details": f"Application accessible directly via IP address: {ip_address}"
                }

        except Exception:
            return None

        return None
