import socket
import re
import ftplib
import smtplib
from typing import Optional, Dict, List, Tuple

from core.base_module import BaseModule, ScanResult, Finding

# port -> (service, probe, response_parser)
SERVICE_DEFINITIONS: Dict[int, Dict] = {
    21: {
        "name": "FTP",
        "checks": ["anonymous_login", "banner"],
    },
    22: {
        "name": "SSH",
        "checks": ["banner", "algorithms"],
    },
    25: {
        "name": "SMTP",
        "checks": ["banner", "open_relay", "vrfy", "expn"],
    },
    53: {
        "name": "DNS",
        "checks": ["recursion", "version"],
    },
    110: {
        "name": "POP3",
        "checks": ["banner", "capabilities"],
    },
    143: {
        "name": "IMAP",
        "checks": ["banner", "capabilities"],
    },
    161: {
        "name": "SNMP",
        "checks": ["community_string"],
    },
    445: {
        "name": "SMB",
        "checks": ["signing", "version"],
    },
    3306: {
        "name": "MySQL",
        "checks": ["banner", "anonymous"],
    },
    5432: {
        "name": "PostgreSQL",
        "checks": ["banner"],
    },
    6379: {
        "name": "Redis",
        "checks": ["auth", "info"],
    },
    9200: {
        "name": "Elasticsearch",
        "checks": ["auth", "info"],
    },
    27017: {
        "name": "MongoDB",
        "checks": ["auth", "info"],
    },
    2181: {
        "name": "Zookeeper",
        "checks": ["info"],
    },
    11211: {
        "name": "Memcached",
        "checks": ["stats"],
    },
}


class Module(BaseModule):
    name = "serviceenum"
    description = "Network service enumeration — deep probing of FTP, SSH, SMTP, Redis, MongoDB, Elasticsearch..."
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        timeout = self.config["network"]["banner_grab_timeout"]

        self.log.info(f"Service enumeration on [bold]{host}[/]")

        for port, definition in SERVICE_DEFINITIONS.items():
            if not self._is_open(host, port, timeout):
                continue

            service = definition["name"]
            self.log.info(f"  [green]{port}/tcp[/] {service} — running checks")

            for check in definition["checks"]:
                method = getattr(self, f"_check_{check}", None)
                if method:
                    findings = method(host, port, timeout)
                    for f in (findings if isinstance(findings, list) else [findings]):
                        if f:
                            result.add_finding(f)

        if not result.findings:
            self.log.info("[dim]No service vulnerabilities found[/]")

        return result

    # ── FTP ──────────────────────────────────────────────────────────────────

    def _check_anonymous_login(self, host, port, timeout) -> Optional[Finding]:
        if port != 21:
            return None
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login("anonymous", "redscope@test.com")
            files = ftp.nlst()
            ftp.quit()
            self.log.info(f"  [bold red]FTP ANON LOGIN[/] — {len(files)} files visible")
            return Finding(
                title="FTP Anonymous Login Allowed",
                severity="high",
                description=(
                    f"FTP server at {host}:{port} accepts anonymous login. "
                    f"{len(files)} files/directories are accessible without credentials."
                ),
                evidence=f"Files: {', '.join(files[:10])}{'...' if len(files) > 10 else ''}",
                remediation="Disable anonymous FTP access. If read-only public access is required, use SFTP with key auth.",
                tags=["ftp", "anonymous", "network"],
            )
        except ftplib.error_perm:
            self.log.info("  [dim]FTP anonymous login denied ✓[/]")
        except Exception:
            pass
        return None

    # ── SSH ──────────────────────────────────────────────────────────────────

    def _check_algorithms(self, host, port, timeout) -> Optional[Finding]:
        banner = self._grab_banner(host, port, timeout)
        if not banner:
            return None
        weak = []
        for algo in ["diffie-hellman-group1-sha1", "arcfour", "blowfish-cbc", "3des-cbc", "des-cbc"]:
            if algo in banner.lower():
                weak.append(algo)
        if weak:
            return Finding(
                title="SSH Weak Algorithms Advertised",
                severity="medium",
                description=f"SSH server advertises weak/deprecated algorithms: {', '.join(weak)}",
                evidence=f"Banner: {banner[:200]}",
                remediation="Update sshd_config to disable weak ciphers and key exchange algorithms.",
                tags=["ssh", "weak-algorithm", "network"],
            )
        return None

    # ── SMTP ─────────────────────────────────────────────────────────────────

    def _check_open_relay(self, host, port, timeout) -> Optional[Finding]:
        try:
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(host, port)
            smtp.ehlo("redscope-test.com")
            code, _ = smtp.mail("test@redscope-test.com")
            code2, _ = smtp.rcpt("victim@external-domain.com")
            smtp.quit()
            if code == 250 and code2 == 250:
                self.log.info("  [bold red]SMTP OPEN RELAY[/]")
                return Finding(
                    title="SMTP Open Relay Detected",
                    severity="high",
                    description=f"SMTP server at {host}:{port} relays mail for external domains — can be abused for spam/phishing.",
                    evidence=f"MAIL FROM: test@redscope-test.com → {code}\nRCPT TO: victim@external-domain.com → {code2}",
                    remediation="Restrict SMTP relay to authenticated users and trusted networks only.",
                    tags=["smtp", "open-relay", "network"],
                )
        except Exception:
            self.log.info("  [dim]SMTP relay restricted ✓[/]")
        return None

    def _check_vrfy(self, host, port, timeout) -> Optional[Finding]:
        try:
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(host, port)
            smtp.ehlo("redscope")
            code, msg = smtp.verify("root")
            smtp.quit()
            if code == 250:
                return Finding(
                    title="SMTP VRFY Command Enabled (User Enumeration)",
                    severity="medium",
                    description="SMTP VRFY command is enabled, allowing attackers to enumerate valid email addresses.",
                    evidence=f"VRFY root → {code} {msg}",
                    remediation="Disable VRFY in your MTA configuration.",
                    tags=["smtp", "user-enumeration", "network"],
                )
        except Exception:
            pass
        return None

    def _check_expn(self, host, port, timeout) -> Optional[Finding]:
        try:
            banner = self._raw_send(host, port, b"EXPN root\r\n", timeout)
            if banner and banner.startswith("250"):
                return Finding(
                    title="SMTP EXPN Command Enabled (Mailing List Disclosure)",
                    severity="low",
                    description="SMTP EXPN command reveals mailing list members.",
                    evidence=f"EXPN root → {banner[:100]}",
                    remediation="Disable EXPN in your MTA configuration.",
                    tags=["smtp", "info-disclosure", "network"],
                )
        except Exception:
            pass
        return None

    # ── DNS ──────────────────────────────────────────────────────────────────

    def _check_recursion(self, host, port, timeout) -> Optional[Finding]:
        import dns.resolver, dns.message, dns.query
        try:
            request = dns.message.make_query("google.com", "A", use_edns=False)
            request.flags |= 0x0100  # RD bit
            resp = dns.query.udp(request, host, timeout=timeout, port=port)
            if resp.flags & 0x0080:  # RA bit set = recursion available
                return Finding(
                    title="DNS Open Recursion Enabled",
                    severity="high",
                    description=f"DNS server at {host} allows recursive queries from any source — DDoS amplification risk.",
                    evidence=f"Recursive query for google.com succeeded (RA flag set)",
                    remediation="Restrict recursive queries to internal/trusted IPs only.",
                    tags=["dns", "open-recursion", "amplification", "network"],
                )
            self.log.info("  [dim]DNS recursion restricted ✓[/]")
        except Exception:
            pass
        return None

    def _check_version(self, host, port, timeout) -> Optional[Finding]:
        import dns.resolver, dns.message, dns.query
        try:
            request = dns.message.make_query("version.bind", "TXT", rdclass=dns.rdataclass.CH)
            resp = dns.query.udp(request, host, timeout=timeout, port=port)
            if resp.answer:
                version = str(resp.answer[0][0])
                return Finding(
                    title=f"DNS Version Disclosed: {version}",
                    severity="low",
                    description="DNS server reveals its version via CHAOS TXT query, aiding targeted attacks.",
                    evidence=f"version.bind TXT: {version}",
                    remediation='Hide DNS version: add `version "not disclosed";` to named.conf options.',
                    tags=["dns", "info-disclosure", "version"],
                )
        except Exception:
            pass
        return None

    # ── Redis ────────────────────────────────────────────────────────────────

    def _check_auth(self, host, port, timeout) -> Optional[Finding]:
        if port == 6379:
            return self._check_redis_auth(host, port, timeout)
        if port == 9200:
            return self._check_elastic_auth(host, port, timeout)
        if port == 27017:
            return self._check_mongo_auth(host, port, timeout)
        return None

    def _check_redis_auth(self, host, port, timeout) -> Optional[Finding]:
        try:
            resp = self._raw_send(host, port, b"PING\r\n", timeout)
            if resp and "+PONG" in resp:
                self.log.info("  [bold red]Redis NO AUTH[/]")
                info = self._raw_send(host, port, b"INFO server\r\n", timeout) or ""
                version = re.search(r"redis_version:(\S+)", info)
                return Finding(
                    title="Redis Running Without Authentication",
                    severity="critical",
                    description=(
                        f"Redis at {host}:{port} accepts commands without authentication. "
                        "Full data access and potential RCE via config set + cron/SSH key injection."
                    ),
                    evidence=f"PING → +PONG\nVersion: {version.group(1) if version else 'unknown'}",
                    remediation="Set requirepass in redis.conf. Bind to 127.0.0.1. Use Redis ACL system.",
                    tags=["redis", "no-auth", "critical", "network"],
                )
        except Exception:
            pass
        return None

    def _check_elastic_auth(self, host, port, timeout) -> Optional[Finding]:
        import requests as req
        try:
            resp = req.get(f"http://{host}:{port}/", timeout=timeout, verify=False)
            if resp.status_code == 200 and "cluster_name" in resp.text:
                data = resp.json()
                return Finding(
                    title="Elasticsearch Accessible Without Authentication",
                    severity="critical",
                    description=f"Elasticsearch at {host}:{port} is open — full index access without credentials.",
                    evidence=f"Cluster: {data.get('cluster_name', '?')}, Version: {data.get('version', {}).get('number', '?')}",
                    remediation="Enable X-Pack security. Bind to localhost. Use a reverse proxy with auth.",
                    tags=["elasticsearch", "no-auth", "critical", "network"],
                )
        except Exception:
            pass
        return None

    def _check_mongo_auth(self, host, port, timeout) -> Optional[Finding]:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            # MongoDB wire protocol — OP_QUERY for isMaster
            msg = b"\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
            sock.sendall(msg)
            resp = sock.recv(512)
            sock.close()
            if b"ismaster" in resp.lower() or b"ok" in resp:
                return Finding(
                    title="MongoDB Accessible Without Authentication",
                    severity="critical",
                    description=f"MongoDB at {host}:{port} responds to queries without credentials.",
                    evidence="MongoDB isMaster probe succeeded without authentication",
                    remediation="Enable MongoDB authentication (--auth). Bind to 127.0.0.1. Use firewall rules.",
                    tags=["mongodb", "no-auth", "critical", "network"],
                )
        except Exception:
            pass
        return None

    # ── Memcached ────────────────────────────────────────────────────────────

    def _check_stats(self, host, port, timeout) -> Optional[Finding]:
        try:
            resp = self._raw_send(host, port, b"stats\r\n", timeout)
            if resp and "STAT" in resp:
                return Finding(
                    title="Memcached Accessible Without Authentication",
                    severity="high",
                    description=f"Memcached at {host}:{port} responds to commands without auth — data exposure and DDoS amplification risk.",
                    evidence=f"stats response: {resp[:200]}",
                    remediation="Bind Memcached to 127.0.0.1. Use firewall to block port 11211 from public.",
                    tags=["memcached", "no-auth", "network", "amplification"],
                )
        except Exception:
            pass
        return None

    # ── Zookeeper ────────────────────────────────────────────────────────────

    def _check_info(self, host, port, timeout) -> Optional[Finding]:
        if port == 2181:
            try:
                resp = self._raw_send(host, port, b"mntr\r\n", timeout)
                if resp and "zk_version" in resp:
                    version = re.search(r"zk_version\s+(\S+)", resp)
                    return Finding(
                        title="Zookeeper Accessible Without Authentication",
                        severity="high",
                        description=f"Zookeeper at {host}:{port} exposes cluster info without authentication.",
                        evidence=f"Version: {version.group(1) if version else 'unknown'}\n{resp[:200]}",
                        remediation="Enable Zookeeper auth (SASL/Kerberos). Bind to internal interfaces only.",
                        tags=["zookeeper", "no-auth", "network"],
                    )
            except Exception:
                pass
        return None

    # ── POP3 / IMAP ──────────────────────────────────────────────────────────

    def _check_capabilities(self, host, port, timeout) -> Optional[Finding]:
        try:
            banner = self._grab_banner(host, port, timeout)
            if banner and "starttls" not in banner.lower() and port in (110, 143):
                return Finding(
                    title=f"{'POP3' if port == 110 else 'IMAP'} STARTTLS Not Advertised",
                    severity="medium",
                    description=f"{'POP3' if port==110 else 'IMAP'} at {host}:{port} may transmit credentials in plaintext.",
                    evidence=f"Banner: {banner[:150]}",
                    remediation=f"Enable STARTTLS on {'POP3' if port==110 else 'IMAP'} or migrate to the TLS-only port.",
                    tags=["email", "plaintext", "starttls"],
                )
        except Exception:
            pass
        return None

    # ── SMB ──────────────────────────────────────────────────────────────────

    def _check_signing(self, host, port, timeout) -> Optional[Finding]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                # SMB negotiate request
                smb_neg = (
                    b"\x00\x00\x00\x54"
                    b"\xff\x53\x4d\x42"
                    b"\x72\x00\x00\x00\x00\x18\x53\xc8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\xff\xfe"
                    b"\x00\x00\x00\x00"
                    b"\x31\x00\x02\x4e\x54\x20\x4c\x4d"
                    b"\x20\x30\x2e\x31\x32\x00"
                )
                sock.sendall(smb_neg)
                resp = sock.recv(256)
                if resp and len(resp) > 39:
                    flags2 = struct.unpack("<H", resp[22:24])[0] if len(resp) >= 24 else 0
                    # Bit 15 of SecurityMode in SMB response
                    signing_required = bool(resp[39] & 0x08) if len(resp) > 39 else False
                    if not signing_required:
                        return Finding(
                            title="SMB Signing Not Required",
                            severity="medium",
                            description=(
                                f"SMB at {host}:445 does not require packet signing. "
                                "This enables NTLM relay attacks (e.g., Responder + ntlmrelayx)."
                            ),
                            evidence="SMB negotiate response: SecurityMode signing not required",
                            remediation="Enable SMB signing: Set RequireSecuritySignature=1 in Windows group policy.",
                            tags=["smb", "ntlm-relay", "signing", "network"],
                        )
        except Exception:
            pass
        return None

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_open(self, host: str, port: int, timeout: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def _grab_banner(self, host: str, port: int, timeout: int) -> Optional[str]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                return sock.recv(512).decode("utf-8", errors="ignore").strip()
        except Exception:
            return None

    def _raw_send(self, host: str, port: int, data: bytes, timeout: int) -> Optional[str]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(data)
                return sock.recv(1024).decode("utf-8", errors="ignore")
        except Exception:
            return None
