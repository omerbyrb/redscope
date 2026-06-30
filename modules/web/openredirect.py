from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode

import requests

from core.base_module import BaseModule, ScanResult, Finding

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnTo", "return_to", "next", "next_url", "url", "target",
    "destination", "dest", "continue", "continue_url", "go", "goto",
    "out", "view", "to", "link", "forward", "forward_url", "callback",
    "checkout_url", "success_url", "data", "ref", "ref_url", "redirect_to",
]

# Payloads cover protocol-relative, @ trick, backslash trick, and direct absolute URL
EVIL_HOST = "evil-redscope-test.com"
PAYLOADS = [
    f"https://{EVIL_HOST}",
    f"http://{EVIL_HOST}",
    f"//{EVIL_HOST}",
    f"\\/\\/{EVIL_HOST}",
    f"////{EVIL_HOST}",
    f"https:{EVIL_HOST}",
    f"/\\/{EVIL_HOST}",
    f"https://trusted.com@{EVIL_HOST}",
    f"https://{EVIL_HOST}#trusted.com",
    f"https://{EVIL_HOST}?trusted.com",
    f"  https://{EVIL_HOST}",
    f"https://{EVIL_HOST}%2f..",
]


class Module(BaseModule):
    name = "openredirect"
    description = "Open redirect scanner — tests redirect/return/url params for unvalidated redirects"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"Open redirect scan on [bold]{url}[/]")

        existing_params = self._extract_params(url)
        base_url = url.split("?")[0] if existing_params else url

        params_to_test = set(existing_params) | set(REDIRECT_PARAMS)
        self.log.info(f"  Testing {len(params_to_test)} parameter names")

        tested = 0
        for param in params_to_test:
            finding = self._test_param(session, base_url, param, timeout)
            tested += 1
            if finding:
                result.add_finding(finding)

        self.log.info(f"Open redirect scan complete — {tested} parameters tested, {len(result.findings)} found")
        return result

    def _test_param(self, session, base_url, param, timeout) -> Optional[Finding]:
        for payload in PAYLOADS:
            try:
                resp = session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False,
                )

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if EVIL_HOST in location:
                        self.log.info(f"  [bold red]OPEN REDIRECT[/] param={param} payload={payload!r}")
                        return Finding(
                            title=f"Open Redirect — parameter: {param}",
                            severity="medium",
                            description=(
                                f"The parameter '{param}' allows redirection to an arbitrary external domain. "
                                f"This can be abused for phishing — victims trust the legitimate domain "
                                f"in the URL while being redirected to an attacker-controlled site."
                            ),
                            evidence=(
                                f"URL: {base_url}?{param}={payload}\n"
                                f"Response: HTTP {resp.status_code}\n"
                                f"Location header: {location}"
                            ),
                            remediation=(
                                "Validate redirect targets against a whitelist of allowed domains/paths. "
                                "Use relative paths only, or an indirection token mapped server-side to a URL."
                            ),
                            tags=["open-redirect", "web", "phishing"],
                        )

                # Also check meta-refresh / JS redirect in body for 200 responses
                elif resp.status_code == 200 and EVIL_HOST in resp.text:
                    body_lower = resp.text.lower()
                    if "meta" in body_lower and "refresh" in body_lower and EVIL_HOST in resp.text:
                        return Finding(
                            title=f"Open Redirect (Meta Refresh) — parameter: {param}",
                            severity="medium",
                            description=f"Parameter '{param}' is reflected into a meta-refresh redirect to an external domain.",
                            evidence=f"URL: {base_url}?{param}={payload}",
                            remediation="Validate redirect targets against a whitelist of allowed domains/paths.",
                            tags=["open-redirect", "web", "phishing"],
                        )
            except requests.RequestException:
                continue
        return None

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
