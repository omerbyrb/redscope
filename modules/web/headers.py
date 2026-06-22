import requests
from urllib.parse import urlparse

from core.base_module import BaseModule, ScanResult, Finding

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS not set — site may be vulnerable to protocol downgrade attacks",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP not set — XSS attacks are not mitigated by policy",
        "remediation": "Define a strict Content-Security-Policy header",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "X-Content-Type-Options not set — MIME sniffing attacks possible",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options not set — clickjacking risk",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy not set — sensitive URLs may leak in Referer header",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy not set — browser features not restricted",
        "remediation": "Add a Permissions-Policy header to restrict camera, microphone, etc.",
    },
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


class Module(BaseModule):
    name = "headers"
    description = "HTTP security header analysis"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)

        url = target if target.startswith("http") else f"https://{target}"
        self.log.info(f"Checking security headers for [bold]{url}[/]")

        try:
            resp = requests.get(
                url,
                timeout=self.config["general"]["timeout"],
                allow_redirects=True,
                headers={"User-Agent": self.config["general"]["user_agent"]},
                verify=True,
            )
        except requests.RequestException as e:
            result.add_error(str(e))
            return result

        headers = {k.lower(): v for k, v in resp.headers.items()}
        result.data["status_code"] = resp.status_code
        result.data["headers"] = dict(resp.headers)
        result.data["url"] = resp.url

        # Missing security headers
        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                result.add_finding(Finding(
                    title=f"Missing {header}",
                    severity=meta["severity"],
                    description=meta["description"],
                    remediation=meta["remediation"],
                    tags=["headers", "misconfiguration"],
                ))

        # Information leakage
        for header in LEAKY_HEADERS:
            if header.lower() in headers:
                result.add_finding(Finding(
                    title=f"Information Disclosure via {header}",
                    severity="info",
                    description=f"Server exposes technology via {header}: {headers[header.lower()]}",
                    evidence=f"{header}: {headers[header.lower()]}",
                    remediation=f"Remove or obfuscate the {header} response header",
                    tags=["headers", "info-disclosure"],
                ))

        # HTTPS redirect check
        if target.startswith("http://") or not target.startswith("http"):
            try:
                http_url = f"http://{target.replace('https://','').replace('http://','')}"
                http_resp = requests.get(http_url, timeout=5, allow_redirects=False,
                                         headers={"User-Agent": self.config["general"]["user_agent"]})
                if http_resp.status_code not in (301, 302, 307, 308):
                    result.add_finding(Finding(
                        title="HTTP Not Redirected to HTTPS",
                        severity="high",
                        description="The site does not redirect HTTP requests to HTTPS",
                        evidence=f"HTTP {http_url} returned {http_resp.status_code}",
                        remediation="Configure server to redirect all HTTP traffic to HTTPS (301)",
                        tags=["tls", "redirect"],
                    ))
            except Exception:
                pass

        return result
