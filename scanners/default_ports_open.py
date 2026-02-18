import socket
from urllib.parse import urlparse
from base.base_scanner import BaseScanner


class DefaultOpenPortScanner(BaseScanner):
    name = "Default Open Ports Detection"
    severity = "Medium"
    owasp = "A05:2021"  # Security Misconfiguration

    DEFAULT_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB"
    }

    def scan(self, url):
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return None

        open_ports = []

        for port, service in self.DEFAULT_PORTS.items():
            if self.is_port_open(host, port):
                open_ports.append(f"{port} ({service})")

        if open_ports:
            return {
                "name": self.name,
                "severity": self.calculate_severity(open_ports),
                "owasp": self.owasp,
                "details": f"Open default ports detected: {', '.join(open_ports)}"
            }

        return None

    def is_port_open(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def calculate_severity(self, open_ports):
        high_risk_ports = ["21 (FTP)", "23 (Telnet)", "3306 (MySQL)", 
                           "6379 (Redis)", "27017 (MongoDB)", "3389 (RDP)"]

        for port in open_ports:
            if port in high_risk_ports:
                return "High"

        return "Medium"
