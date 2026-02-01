class BaseScanner:
    name = ""
    severity = ""
    owasp = ""

    def scan(self, url):
        raise NotImplementedError
