import ssl
import socket
import datetime
from typing import List, Optional, Tuple

import requests

from core.base_module import BaseModule, ScanResult, Finding

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON",
    "ADH", "AECDH", "PSK", "SRP", "CAMELLIA",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

PROTOCOL_MAP = {
    "SSLv2": ssl.PROTOCOL_TLS_CLIENT,
    "SSLv3": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


class Module(BaseModule):
    name = "ssltls"
    description = "SSL/TLS analyzer — certificate validity, weak ciphers, deprecated protocols"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        port = 443

        self.log.info(f"SSL/TLS analysis on [bold]{host}:{port}[/]")

        # Get certificate info
        cert_info = self._get_cert(host, port)
        if not cert_info:
            result.add_error(f"Could not retrieve SSL certificate from {host}:{port}")
            return result

        result.data["certificate"] = cert_info

        # Check certificate validity
        findings = self._check_cert(host, cert_info)
        result.findings.extend(findings)

        # Check protocol support
        proto_findings = self._check_protocols(host, port)
        result.findings.extend(proto_findings)

        # Check cipher strength
        cipher_finding = self._check_cipher(host, port)
        if cipher_finding:
            result.add_finding(cipher_finding)

        # Check HTTP Strict Transport Security
        hsts_finding = self._check_hsts(host)
        if hsts_finding:
            result.add_finding(hsts_finding)

        if not result.findings:
            self.log.info("[dim]SSL/TLS configuration looks good[/]")
        else:
            self.log.info(f"SSL/TLS scan complete — [bold red]{len(result.findings)} issues found[/]")

        return result

    def _get_cert(self, host: str, port: int) -> Optional[dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": [v for _, v in cert.get("subjectAltName", [])],
                        "serial": cert.get("serialNumber"),
                        "cipher": cipher,
                        "protocol": version,
                    }
        except Exception as e:
            self.log.warning(f"  Certificate retrieval failed: {e}")
            return None

    def _check_cert(self, host: str, cert: dict) -> List[Finding]:
        findings = []
        now = datetime.datetime.utcnow()

        not_after_str = cert.get("not_after", "")
        not_before_str = cert.get("not_before", "")

        try:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_before = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")

            days_left = (not_after - now).days

            self.log.info(f"  Cert valid until: [cyan]{not_after_str}[/] ({days_left} days left)")

            if now > not_after:
                findings.append(Finding(
                    title="SSL Certificate Expired",
                    severity="critical",
                    description=f"Certificate expired on {not_after_str}. All connections show security warnings.",
                    evidence=f"Not After: {not_after_str}",
                    remediation="Renew the SSL certificate immediately.",
                    tags=["ssl", "certificate", "expired"],
                ))
            elif days_left < 14:
                findings.append(Finding(
                    title=f"SSL Certificate Expiring Soon ({days_left} days)",
                    severity="high",
                    description=f"Certificate expires in {days_left} days on {not_after_str}.",
                    evidence=f"Not After: {not_after_str}",
                    remediation="Renew the certificate before it expires.",
                    tags=["ssl", "certificate"],
                ))
            elif days_left < 30:
                findings.append(Finding(
                    title=f"SSL Certificate Expiring in {days_left} Days",
                    severity="medium",
                    description=f"Certificate expires on {not_after_str}.",
                    evidence=f"Not After: {not_after_str}",
                    remediation="Plan certificate renewal soon.",
                    tags=["ssl", "certificate"],
                ))

            # Validity period > 398 days (Apple/browser policy)
            validity_days = (not_after - not_before).days
            if validity_days > 398:
                findings.append(Finding(
                    title="SSL Certificate Validity Period Exceeds 398 Days",
                    severity="low",
                    description=(
                        f"Certificate validity is {validity_days} days. "
                        "Browsers enforce a maximum of 398 days — older long-lived certs may be distrusted."
                    ),
                    evidence=f"Not Before: {not_before_str}\nNot After: {not_after_str}",
                    remediation="Issue certificates with a maximum validity of 398 days.",
                    tags=["ssl", "certificate"],
                ))
        except ValueError:
            pass

        # CN vs host mismatch check
        cn = cert.get("subject", {}).get("commonName", "")
        san = cert.get("san", [])
        if cn and not self._hostname_matches(host, cn, san):
            findings.append(Finding(
                title="SSL Certificate Hostname Mismatch",
                severity="critical",
                description=f"Certificate CN/SAN does not match host '{host}'.",
                evidence=f"CN: {cn}\nSAN: {san}",
                remediation="Obtain a certificate that includes the correct hostname in its SAN.",
                tags=["ssl", "certificate", "hostname"],
            ))

        return findings

    def _check_protocols(self, host: str, port: int) -> List[Finding]:
        findings = []

        for proto_name in ["TLSv1", "TLSv1.1"]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = PROTOCOL_MAP[proto_name]
                ctx.maximum_version = PROTOCOL_MAP[proto_name]
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        self.log.info(f"  [yellow]Weak protocol supported:[/] {proto_name}")
                        findings.append(Finding(
                            title=f"Deprecated Protocol Supported: {proto_name}",
                            severity="high",
                            description=(
                                f"Server supports {proto_name}, which has known vulnerabilities "
                                "(BEAST, POODLE) and is deprecated by RFC 8996."
                            ),
                            evidence=f"Connected successfully using {proto_name}",
                            remediation=f"Disable {proto_name} and enforce TLS 1.2+ only.",
                            tags=["ssl", "weak-protocol", proto_name.lower()],
                        ))
            except Exception:
                self.log.info(f"  [green]{proto_name} not supported[/] ✓")

        return findings

    def _check_cipher(self, host: str, port: int) -> Optional[Finding]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher_name, _, bits = ssock.cipher()
                    self.log.info(f"  Negotiated cipher: [cyan]{cipher_name}[/] ({bits} bits)")

                    for weak in WEAK_CIPHERS:
                        if weak in cipher_name.upper():
                            return Finding(
                                title=f"Weak Cipher Suite in Use: {cipher_name}",
                                severity="high",
                                description=f"Server negotiated weak cipher '{cipher_name}' ({bits} bits).",
                                evidence=f"Cipher: {cipher_name}, Bits: {bits}",
                                remediation="Configure server to prefer ECDHE+AES-GCM or CHACHA20-POLY1305 ciphers.",
                                tags=["ssl", "weak-cipher"],
                            )
                    if bits and int(bits) < 128:
                        return Finding(
                            title=f"Insufficient Key Length: {bits} bits",
                            severity="high",
                            description=f"Cipher key length of {bits} bits is below the recommended 128 bits minimum.",
                            evidence=f"Cipher: {cipher_name}, Bits: {bits}",
                            remediation="Use ciphers with at least 128-bit key length.",
                            tags=["ssl", "weak-cipher"],
                        )
        except Exception:
            pass
        return None

    def _check_hsts(self, host: str) -> Optional[Finding]:
        try:
            resp = requests.get(f"https://{host}", timeout=5, verify=False)
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                return Finding(
                    title="HSTS Header Missing",
                    severity="medium",
                    description="HTTPS site does not set Strict-Transport-Security header.",
                    remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    tags=["ssl", "hsts", "headers"],
                )
            max_age = 0
            for part in hsts.split(";"):
                if "max-age" in part.lower():
                    try:
                        max_age = int(part.split("=")[1].strip())
                    except Exception:
                        pass
            if max_age < 31536000:
                return Finding(
                    title=f"HSTS max-age Too Short ({max_age}s)",
                    severity="low",
                    description=f"HSTS max-age of {max_age}s is below the recommended 1 year (31536000s).",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Set max-age to at least 31536000 (1 year).",
                    tags=["ssl", "hsts"],
                )
        except Exception:
            pass
        return None

    def _hostname_matches(self, host: str, cn: str, san: List[str]) -> bool:
        all_names = san if san else [cn]
        for name in all_names:
            name = name.lower()
            host = host.lower()
            if name == host:
                return True
            if name.startswith("*.") and host.endswith(name[1:]):
                return True
        return False
