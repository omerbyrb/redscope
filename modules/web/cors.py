from typing import List, Optional

import requests

from core.base_module import BaseModule, ScanResult, Finding

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://trusted.evil.com",
]


class Module(BaseModule):
    name = "cors"
    description = "CORS misconfiguration checker — origin reflection, wildcard, null origin"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"CORS misconfiguration check on [bold]{url}[/]")

        # Check wildcard CORS
        try:
            resp = session.get(url, timeout=timeout, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                if acac.lower() == "true":
                    result.add_finding(Finding(
                        title="CORS Wildcard with Credentials Allowed",
                        severity="critical",
                        description=(
                            "Server responds with Access-Control-Allow-Origin: * and "
                            "Access-Control-Allow-Credentials: true. "
                            "This is an invalid and dangerous combination that browsers "
                            "may handle inconsistently — credentials can be leaked."
                        ),
                        evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        remediation="Never combine wildcard ACAO with Allow-Credentials: true. Use explicit origins.",
                        tags=["cors", "web", "misconfiguration"],
                    ))
                else:
                    result.add_finding(Finding(
                        title="CORS Wildcard Origin",
                        severity="medium",
                        description="Server allows any origin via wildcard (*). Any website can make cross-origin requests.",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation="Restrict ACAO to a whitelist of trusted origins.",
                        tags=["cors", "web"],
                    ))
        except requests.RequestException as e:
            result.add_error(str(e))
            return result

        # Test origin reflection
        for origin in TEST_ORIGINS:
            finding = self._test_origin(session, url, origin, timeout)
            if finding:
                result.add_finding(finding)

        # Test pre-flight
        self._test_preflight(session, url, timeout, result)

        if not result.findings:
            self.log.info("[dim]No CORS misconfiguration detected[/]")

        return result

    def _test_origin(self, session, url, origin, timeout) -> Optional[Finding]:
        try:
            resp = session.get(
                url,
                headers={"Origin": origin},
                timeout=timeout,
                verify=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == origin:
                with_creds = acac == "true"
                severity = "critical" if with_creds else "high"
                self.log.info(f"  [bold red]CORS VULN[/] origin={origin!r} reflected, credentials={with_creds}")
                return Finding(
                    title=f"CORS — Arbitrary Origin Reflected{' with Credentials' if with_creds else ''}",
                    severity=severity,
                    description=(
                        f"The server reflects the attacker-controlled origin '{origin}' in ACAO header"
                        + (", and also sends Allow-Credentials: true — session cookies can be stolen." if with_creds
                           else ". An attacker can make cross-origin requests from any domain.")
                    ),
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                    ),
                    remediation=(
                        "Validate the Origin header against a strict whitelist. "
                        "Never reflect arbitrary origins. "
                        "If credentials are needed, specify exact trusted origins."
                    ),
                    tags=["cors", "origin-reflection", "web"],
                ))

            if origin == "null" and acao == "null":
                return Finding(
                    title="CORS — Null Origin Accepted",
                    severity="high",
                    description=(
                        "Server accepts 'null' as a valid origin. "
                        "Attackers can send requests with null origin from sandboxed iframes."
                    ),
                    evidence=f"Access-Control-Allow-Origin: null",
                    remediation="Do not whitelist the null origin in production.",
                    tags=["cors", "null-origin", "web"],
                )
        except requests.RequestException:
            pass
        return None

    def _test_preflight(self, session, url, timeout, result: ScanResult) -> None:
        try:
            resp = session.options(
                url,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                },
                timeout=timeout,
                verify=False,
            )
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            acah = resp.headers.get("Access-Control-Allow-Headers", "")
            acao = resp.headers.get("Access-Control-Allow-Origin", "")

            if acao and "PUT" in acam and resp.status_code in (200, 204):
                result.add_finding(Finding(
                    title="CORS Preflight Allows Dangerous Methods from Untrusted Origin",
                    severity="high",
                    description=(
                        "The server's preflight response allows PUT/DELETE from untrusted origins, "
                        "which may allow attackers to modify server-side data cross-origin."
                    ),
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Methods: {acam}\n"
                        f"Access-Control-Allow-Headers: {acah}"
                    ),
                    remediation="Restrict allowed methods and origins in CORS preflight responses.",
                    tags=["cors", "preflight", "web"],
                ))
        except requests.RequestException:
            pass
