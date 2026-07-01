import base64
import json
import hmac
import hashlib
import time
from typing import Optional, Tuple

import requests

from core.base_module import BaseModule, ScanResult, Finding

WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "letmein", "admin",
    "key", "jwt", "token", "test", "hello", "world", "changeme",
    "supersecret", "secret123", "password123", "jwt_secret",
    "your-256-bit-secret", "your-secret-key", "mysecret",
    "", "null", "undefined", "none",
]

COMMON_JWT_HEADERS = [
    "Authorization",
    "X-Auth-Token",
    "X-Access-Token",
    "X-Token",
    "Token",
]


class Module(BaseModule):
    name = "jwt"
    description = "JWT analyzer — weak secret, alg:none, expired token, and misconfiguration checks"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"

        token = kwargs.get("token")

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"JWT analysis on [bold]{url}[/]")

        # If no token provided, try to harvest from response headers/cookies
        if not token:
            token = self._harvest_token(session, url, timeout)

        if not token:
            self.log.warning("No JWT found — pass a token via --token or target a login endpoint")
            result.add_error("No JWT token found or provided")
            return result

        self.log.info(f"  Analyzing token: [cyan]{token[:40]}...[/]")

        header, payload, signature = self._decode_token(token)
        if not header:
            result.add_error("Invalid JWT format")
            return result

        result.data["header"] = header
        result.data["payload"] = payload

        self.log.info(f"  Algorithm: [cyan]{header.get('alg', 'unknown')}[/]")

        # Check 1: alg:none attack
        finding = self._check_alg_none(header, payload, session, url, timeout)
        if finding:
            result.add_finding(finding)

        # Check 2: weak secret brute force (HS256/HS384/HS512)
        finding = self._check_weak_secret(token, header, payload, signature)
        if finding:
            result.add_finding(finding)

        # Check 3: token expiry
        finding = self._check_expiry(payload)
        if finding:
            result.add_finding(finding)

        # Check 4: sensitive data in payload
        findings = self._check_sensitive_claims(payload)
        result.findings.extend(findings)

        # Check 5: algorithm confusion (RS256 → HS256)
        finding = self._check_alg_confusion(header)
        if finding:
            result.add_finding(finding)

        if not result.findings:
            self.log.info("[dim]No JWT vulnerabilities detected[/]")

        return result

    def _harvest_token(self, session, url, timeout) -> Optional[str]:
        try:
            resp = session.get(url, timeout=timeout, verify=False)
            for header in COMMON_JWT_HEADERS:
                val = resp.headers.get(header, "")
                if val.startswith("Bearer "):
                    val = val[7:]
                if self._looks_like_jwt(val):
                    self.log.info(f"  Found JWT in response header: [cyan]{header}[/]")
                    return val

            for cookie in resp.cookies:
                if self._looks_like_jwt(cookie.value):
                    self.log.info(f"  Found JWT in cookie: [cyan]{cookie.name}[/]")
                    return cookie.value
        except requests.RequestException:
            pass
        return None

    def _looks_like_jwt(self, value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 3 and all(parts)

    def _decode_token(self, token: str) -> Tuple[Optional[dict], Optional[dict], str]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None, ""
            header = json.loads(self._b64decode(parts[0]))
            payload = json.loads(self._b64decode(parts[1]))
            return header, payload, parts[2]
        except Exception:
            return None, None, ""

    def _b64decode(self, data: str) -> bytes:
        data += "=" * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data)

    def _b64encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _check_alg_none(self, header, payload, session, url, timeout) -> Optional[Finding]:
        for none_val in ["none", "None", "NONE", "nOnE"]:
            forged_header = {**header, "alg": none_val}
            forged = (
                self._b64encode(json.dumps(forged_header).encode()) + "." +
                self._b64encode(json.dumps(payload).encode()) + "."
            )
            try:
                resp = session.get(
                    url,
                    headers={"Authorization": f"Bearer {forged}"},
                    timeout=timeout,
                    verify=False,
                )
                if resp.status_code not in (401, 403):
                    self.log.info(f"  [bold red]alg:none ACCEPTED[/] ({none_val}) → HTTP {resp.status_code}")
                    return Finding(
                        title="JWT Algorithm:None Attack Accepted",
                        severity="critical",
                        description=(
                            f"The server accepted a JWT with alg='{none_val}' and no signature. "
                            "This means the server does not validate the signature, "
                            "allowing anyone to forge arbitrary tokens."
                        ),
                        evidence=(
                            f"Forged token: {forged[:80]}...\n"
                            f"Server response: HTTP {resp.status_code}"
                        ),
                        remediation=(
                            "Explicitly reject tokens with alg=none. "
                            "Use a JWT library that enforces a strict algorithm allowlist."
                        ),
                        tags=["jwt", "alg-none", "auth-bypass", "critical"],
                    )
            except requests.RequestException:
                continue
        return None

    def _check_weak_secret(self, token, header, payload, signature) -> Optional[Finding]:
        alg = header.get("alg", "")
        if not alg.startswith("HS"):
            return None

        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_func = hash_map.get(alg, hashlib.sha256)

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()

        for secret in WEAK_SECRETS:
            sig = hmac.new(secret.encode(), signing_input, hash_func).digest()
            if self._b64encode(sig) == signature:
                self.log.info(f"  [bold red]WEAK SECRET[/] cracked: {secret!r}")
                return Finding(
                    title=f"JWT Signed with Weak Secret: '{secret}'",
                    severity="critical",
                    description=(
                        f"The JWT is signed with a trivially guessable secret '{secret}'. "
                        "An attacker can forge tokens for any user, including admin accounts."
                    ),
                    evidence=f"Algorithm: {alg}\nSecret: {secret!r}\nToken: {token[:60]}...",
                    remediation=(
                        "Use a cryptographically random secret of at least 256 bits. "
                        "Rotate all existing tokens immediately. "
                        "Consider switching to RS256 with a key pair."
                    ),
                    tags=["jwt", "weak-secret", "auth-bypass"],
                )
        return None

    def _check_expiry(self, payload) -> Optional[Finding]:
        exp = payload.get("exp")
        iat = payload.get("iat")
        now = int(time.time())

        if not exp:
            return Finding(
                title="JWT Has No Expiration (no 'exp' claim)",
                severity="medium",
                description="Token never expires — if stolen, it is valid forever.",
                evidence=f"Payload: {json.dumps(payload, indent=2)[:200]}",
                remediation="Always include a short-lived 'exp' claim (e.g., 15 minutes for access tokens).",
                tags=["jwt", "no-expiry"],
            )

        if exp < now:
            expired_ago = now - exp
            return Finding(
                title="Expired JWT Still Accepted",
                severity="high",
                description=f"Token expired {expired_ago}s ago but server may still accept it.",
                evidence=f"exp: {exp} (now: {now}, delta: -{expired_ago}s)",
                remediation="Validate the 'exp' claim on every request and reject expired tokens.",
                tags=["jwt", "expired-token"],
            )
        return None

    def _check_sensitive_claims(self, payload) -> list:
        findings = []
        sensitive_keys = ["password", "passwd", "secret", "key", "token", "credit_card", "ssn", "cvv"]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                findings.append(Finding(
                    title=f"Sensitive Data in JWT Payload: '{key}'",
                    severity="medium",
                    description=(
                        f"JWT payload contains sensitive field '{key}'. "
                        "JWT payloads are base64-encoded, not encrypted — anyone with the token can read this."
                    ),
                    evidence=f"Claim: {key} = {str(payload[key])[:50]}",
                    remediation="Never store sensitive data in JWT payload. Use opaque session tokens if needed.",
                    tags=["jwt", "sensitive-data", "information-disclosure"],
                ))
        return findings

    def _check_alg_confusion(self, header) -> Optional[Finding]:
        if header.get("alg") == "RS256":
            return Finding(
                title="JWT Uses RS256 — Verify Algorithm Confusion Protection",
                severity="info",
                description=(
                    "Token uses RS256. Ensure the server explicitly checks that the algorithm is RS256 "
                    "and does not allow an attacker to switch to HS256 using the public key as the HMAC secret."
                ),
                remediation=(
                    "Enforce a strict algorithm allowlist on the server. "
                    "Never accept HS256 on an endpoint that normally uses RS256."
                ),
                tags=["jwt", "alg-confusion"],
            )
        return None
