import re
import copy
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from core.base_module import BaseModule, ScanResult, Finding

# Common IDOR-prone parameter names
IDOR_PARAMS = [
    "id", "user_id", "userid", "account_id", "accountid", "profile_id",
    "order_id", "orderid", "invoice_id", "ticket_id", "doc_id", "file_id",
    "record_id", "customer_id", "member_id", "employee_id", "patient_id",
    "uid", "pid", "oid", "aid", "rid", "cid", "num", "number", "ref",
    "uuid", "guid", "token", "key", "hash",
]

# Common IDOR-prone API path patterns
API_PATH_PATTERNS = [
    r"/api/v\d+/users?/(\d+)",
    r"/api/v\d+/accounts?/(\d+)",
    r"/api/v\d+/orders?/(\d+)",
    r"/api/v\d+/profiles?/(\d+)",
    r"/api/v\d+/documents?/(\d+)",
    r"/users?/(\d+)",
    r"/accounts?/(\d+)",
    r"/orders?/(\d+)",
    r"/invoices?/(\d+)",
    r"/profiles?/(\d+)",
    r"/admin/users?/(\d+)",
]

INTERESTING_FIELDS = [
    "email", "password", "phone", "address", "ssn", "credit_card",
    "token", "secret", "api_key", "balance", "role", "admin",
    "dob", "birth", "salary", "account_number",
]


class Module(BaseModule):
    name = "idor"
    description = "IDOR checker — parameter tampering and API path enumeration for access control issues"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"IDOR scan on [bold]{url}[/]")

        # Extract existing params
        existing_params = self._extract_params(url)
        base_url = url.split("?")[0]

        # Test 1: Parameter tampering on numeric IDs
        self.log.info("  [1] Testing numeric ID parameter tampering")
        for param, value in existing_params.items():
            if self._is_numeric(value):
                finding = self._test_id_tampering(session, base_url, existing_params, param, value, timeout)
                if finding:
                    result.add_finding(finding)

        # Test 2: Inject IDOR params if none found in URL
        if not any(self._is_numeric(v) for v in existing_params.values()):
            self.log.info("  [2] Injecting common IDOR parameters")
            for param in IDOR_PARAMS[:10]:
                finding = self._test_id_injection(session, base_url, param, timeout)
                if finding:
                    result.add_finding(finding)

        # Test 3: Path-based IDOR in REST APIs
        self.log.info("  [3] Testing path-based IDOR in API endpoints")
        path_findings = self._test_path_idor(session, url, timeout)
        result.findings.extend(path_findings)

        # Test 4: UUID/GUID predictability
        self.log.info("  [4] Checking for sequential/predictable IDs")
        for param, value in existing_params.items():
            finding = self._test_sequential_ids(session, base_url, existing_params, param, value, timeout)
            if finding:
                result.add_finding(finding)

        # Test 5: HTTP method override (PUT/DELETE on other users' resources)
        self.log.info("  [5] Testing HTTP method override")
        method_finding = self._test_method_override(session, url, timeout)
        if method_finding:
            result.add_finding(method_finding)

        if not result.findings:
            self.log.info("[dim]No IDOR vulnerabilities detected[/]")

        return result

    def _test_id_tampering(self, session, base_url, all_params, param, value, timeout) -> Optional[Finding]:
        original_id = int(value)
        test_ids = [original_id - 1, original_id + 1, original_id + 100, 1, 2, 9999]

        try:
            orig_resp = session.get(
                base_url, params=all_params, timeout=timeout, verify=False
            )
        except requests.RequestException:
            return None

        for test_id in test_ids:
            if test_id <= 0:
                continue
            tampered = {**all_params, param: str(test_id)}
            try:
                resp = session.get(
                    base_url, params=tampered, timeout=timeout, verify=False
                )

                if (resp.status_code == 200 and
                        resp.status_code == orig_resp.status_code and
                        len(resp.text) > 50 and
                        resp.text != orig_resp.text):

                    sensitive = self._contains_sensitive_data(resp.text)
                    severity = "high" if sensitive else "medium"

                    self.log.info(
                        f"  [bold red]IDOR POSSIBLE[/] param={param} "
                        f"original={original_id} tampered={test_id} → {resp.status_code}"
                    )
                    return Finding(
                        title=f"Possible IDOR — parameter: {param}",
                        severity=severity,
                        description=(
                            f"Changing '{param}' from {original_id} to {test_id} returned "
                            f"a different 200 OK response with content. "
                            f"This may indicate unauthorized access to another user's data."
                            + (f" Response contains sensitive fields: {sensitive}." if sensitive else "")
                        ),
                        evidence=(
                            f"URL: {base_url}?{param}={test_id}\n"
                            f"Original ID: {original_id} → Status: {orig_resp.status_code}, Size: {len(orig_resp.text)}\n"
                            f"Tampered ID: {test_id} → Status: {resp.status_code}, Size: {len(resp.text)}\n"
                            + (f"Sensitive fields found: {sensitive}" if sensitive else "")
                        ),
                        remediation=(
                            "Implement server-side authorization checks on every resource access. "
                            "Verify the requesting user owns or has permission to access the requested resource. "
                            "Use indirect object references (UUIDs) instead of sequential integers."
                        ),
                        tags=["idor", "broken-access-control", "web"],
                    )
            except requests.RequestException:
                continue
        return None

    def _test_id_injection(self, session, base_url, param, timeout) -> Optional[Finding]:
        for test_id in [1, 2, 100]:
            try:
                resp = session.get(
                    base_url, params={param: test_id}, timeout=timeout, verify=False
                )
                if resp.status_code == 200 and len(resp.text) > 100:
                    sensitive = self._contains_sensitive_data(resp.text)
                    if sensitive:
                        self.log.info(f"  [yellow]IDOR candidate[/] param={param} id={test_id} sensitive={sensitive}")
                        return Finding(
                            title=f"Sensitive Data Accessible via '{param}' Parameter",
                            severity="medium",
                            description=(
                                f"Injecting '{param}={test_id}' returned a 200 response "
                                f"containing sensitive fields: {sensitive}. "
                                "Verify this endpoint enforces proper authorization."
                            ),
                            evidence=f"URL: {base_url}?{param}={test_id}\nSensitive fields: {sensitive}",
                            remediation="Ensure all endpoints verify the authenticated user has access to requested resources.",
                            tags=["idor", "broken-access-control"],
                        )
            except requests.RequestException:
                continue
        return None

    def _test_path_idor(self, session, url, timeout) -> List[Finding]:
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        for pattern in API_PATH_PATTERNS:
            match = re.search(pattern, path)
            if match:
                original_id = int(match.group(1))
                for test_id in [original_id - 1, original_id + 1, 1, 2]:
                    if test_id <= 0:
                        continue
                    new_path = path[:match.start(1)] + str(test_id) + path[match.end(1):]
                    new_url = urlunparse(parsed._replace(path=new_path))
                    try:
                        orig = session.get(url, timeout=timeout, verify=False)
                        resp = session.get(new_url, timeout=timeout, verify=False)
                        if (resp.status_code == 200 and
                                orig.status_code == 200 and
                                resp.text != orig.text and
                                len(resp.text) > 50):
                            self.log.info(f"  [bold red]PATH IDOR[/] {new_url}")
                            findings.append(Finding(
                                title=f"Path-Based IDOR — {new_path}",
                                severity="high",
                                description=(
                                    f"Modifying the ID in the API path from {original_id} to {test_id} "
                                    f"returned a different successful response. "
                                    "This suggests the API does not enforce user-level authorization."
                                ),
                                evidence=(
                                    f"Original: {url} → {orig.status_code} ({len(orig.text)} bytes)\n"
                                    f"Modified: {new_url} → {resp.status_code} ({len(resp.text)} bytes)"
                                ),
                                remediation=(
                                    "Implement resource ownership checks in the API layer. "
                                    "Every API endpoint should verify the authenticated user has access to the requested object."
                                ),
                                tags=["idor", "api", "broken-access-control"],
                            ))
                            break
                    except requests.RequestException:
                        continue
        return findings

    def _test_sequential_ids(self, session, base_url, all_params, param, value, timeout) -> Optional[Finding]:
        if not self._is_numeric(value):
            return None
        id_val = int(value)
        if id_val < 10:
            return Finding(
                title=f"Sequential/Predictable ID Detected: {param}={value}",
                severity="low",
                description=(
                    f"Parameter '{param}' has a very low integer value ({value}), "
                    "suggesting sequential IDs are in use. "
                    "Sequential IDs make IDOR attacks trivial to enumerate."
                ),
                evidence=f"URL parameter: {param}={value}",
                remediation="Use UUIDs or other non-sequential, non-guessable identifiers for resource references.",
                tags=["idor", "predictable-id"],
            )
        return None

    def _test_method_override(self, session, url, timeout) -> Optional[Finding]:
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "PUT"},
            {"X-Method-Override": "DELETE"},
            {"_method": "DELETE"},
        ]
        for headers in override_headers:
            try:
                resp = session.post(url, headers=headers, timeout=timeout, verify=False)
                if resp.status_code in (200, 204):
                    return Finding(
                        title="HTTP Method Override Accepted",
                        severity="medium",
                        description=(
                            f"Server accepted {list(headers.keys())[0]} header for method override. "
                            "This may allow attackers to perform DELETE/PUT on resources by sending POST requests."
                        ),
                        evidence=f"Header: {headers}\nResponse: {resp.status_code}",
                        remediation="Disable HTTP method override headers unless explicitly required.",
                        tags=["idor", "method-override", "broken-access-control"],
                    )
            except requests.RequestException:
                continue
        return None

    def _contains_sensitive_data(self, text: str) -> Optional[str]:
        text_lower = text.lower()
        found = [f for f in INTERESTING_FIELDS if f in text_lower]
        return ", ".join(found) if found else None

    def _is_numeric(self, value: str) -> bool:
        try:
            int(value)
            return True
        except (ValueError, TypeError):
            return False

    def _extract_params(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {k: v[0] for k, v in qs.items()}
