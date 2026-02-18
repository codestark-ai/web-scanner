from base.base_scanner import BaseScanner
from urllib.parse import urlparse
import socket
import ssl

class WeakTLSVersionScanner(BaseScanner):
    name = "Weak TLS Version Supported (TLS 1.0 / 1.1)"
    severity = "High"
    owasp = "A02:2021"   # Cryptographic Failures

    def scan(self, url):
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return None

        weak_versions = []

        try:
            # Check TLS 1.0
            context_tls1 = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context_tls1.wrap_socket(sock, server_hostname=hostname):
                    weak_versions.append("TLS 1.0")

        except Exception:
            pass

        try:
            # Check TLS 1.1
            context_tls11 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context_tls11.wrap_socket(sock, server_hostname=hostname):
                    weak_versions.append("TLS 1.1")

        except Exception:
            pass

        if weak_versions:
            return {
                "name": self.name,
                "severity": self.severity,
                "owasp": self.owasp,
                "details": f"Server supports deprecated versions: {', '.join(weak_versions)}"
            }

        return None
