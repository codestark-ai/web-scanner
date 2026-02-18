import socket
from urllib.parse import urlparse
from base.base_scanner import BaseScanner


class HTTPSmugglingScanner(BaseScanner):
    name = "HTTP Request Smuggling"
    severity = "High"
    owasp = "A05:2021"  # Security Misconfiguration

    def scan(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80

        payload = (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 13\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "\r\n"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(payload.encode())

            response = sock.recv(4096).decode(errors="ignore")
            sock.close()

            if "HTTP/1.1 200" in response and "HTTP/1.1 400" not in response:
                return {
                    "name": self.name,
                    "severity": self.severity,
                    "owasp": self.owasp,
                    "details": "Potential HTTP Request Smuggling behavior detected (CL.TE mismatch)."
                }

        except Exception:
            return None

        return None
