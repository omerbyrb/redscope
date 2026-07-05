import socket
import re
from typing import Optional, Dict, List

import requests

from core.base_module import BaseModule, ScanResult, Finding

# port -> (service_name, probe_bytes)
SERVICE_PROBES: Dict[int, tuple] = {
    21:   ("FTP",        b""),
    22:   ("SSH",        b""),
    23:   ("Telnet",     b"\r\n"),
    25:   ("SMTP",       b"EHLO redscope\r\n"),
    80:   ("HTTP",       b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    110:  ("POP3",       b""),
    143:  ("IMAP",       b""),
    443:  ("HTTPS",      b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    445:  ("SMB",        b""),
    465:  ("SMTPS",      b""),
    587:  ("SMTP",       b"EHLO redscope\r\n"),
    993:  ("IMAPS",      b""),
    995:  ("POP3S",      b""),
    1433: ("MSSQL",      b""),
    1521: ("Oracle",     b""),
    3306: ("MySQL",      b""),
    3389: ("RDP",        b""),
    5432: ("PostgreSQL", b""),
    5900: ("VNC",        b""),
    6379: ("Redis",      b"INFO server\r\n"),
    8080: ("HTTP-Alt",   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    8443: ("HTTPS-Alt",  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    9200: ("Elasticsearch", b""),
    27017:("MongoDB",    b""),
}

# Version pattern extraction per service
VERSION_PATTERNS = [
    (r"SSH-(\d+\.\d+-\S+)",               "SSH"),
    (r"220[- ].*?(\d+\.\d+[\.\d]*)",      "FTP/SMTP"),
    (r"Apache[/ ](\d+\.\d+[\.\d]*)",      "Apache"),
    (r"nginx[/ ](\d+\.\d+[\.\d]*)",       "nginx"),
    (r"Microsoft-IIS[/ ](\d+\.\d+)",      "IIS"),
    (r"OpenSSH[_ ](\d+\.\d+\w*)",         "OpenSSH"),
    (r"ProFTPD (\d+\.\d+[\.\d]*)",        "ProFTPD"),
    (r"vsftpd (\d+\.\d+[\.\d]*)",         "vsftpd"),
    (r"Postfix",                           "Postfix"),
    (r"Exim (\d+\.\d+[\.\d]*)",           "Exim"),
    (r"MySQL (\d+\.\d+[\.\d]*)",          "MySQL"),
    (r"redis_version:(\S+)",              "Redis"),
    (r"PostgreSQL (\d+\.\d+[\.\d]*)",     "PostgreSQL"),
    (r"MongoDB (\d+\.\d+[\.\d]*)",        "MongoDB"),
    (r"X-Powered-By: (.*)",               "X-Powered-By"),
    (r"Server: (.*)",                      "Server header"),
    (r"PHP[/ ](\d+\.\d+[\.\d]*)",         "PHP"),
    (r"Tomcat[/ ](\d+\.\d+[\.\d]*)",      "Tomcat"),
    (r"JBoss[/ ](\d+\.\d+[\.\d]*)",       "JBoss"),
    (r"WebLogic (\d+[\.\d]*)",            "WebLogic"),
]

# Known EOL/outdated version checks (service_keyword, version_prefix, severity, note)
EOL_CHECKS = [
    ("OpenSSH", "6.",  "high",   "OpenSSH 6.x is EOL — upgrade to 9.x"),
    ("OpenSSH", "7.",  "medium", "OpenSSH 7.x is outdated — upgrade to 9.x"),
    ("OpenSSH", "8.",  "low",    "OpenSSH 8.x — consider upgrading to 9.x"),
    ("Apache",  "2.2", "high",   "Apache 2.2 is EOL since 2017"),
    ("Apache",  "2.4.5", "medium", "Older Apache 2.4 branch — patch to latest"),
    ("nginx",   "1.1", "high",   "nginx 1.1x is EOL"),
    ("nginx",   "1.2", "high",   "nginx 1.2x is EOL"),
    ("IIS",     "6.",  "critical","IIS 6.0 is EOL since 2015 — multiple critical CVEs"),
    ("IIS",     "7.",  "high",   "IIS 7.x is EOL"),
    ("PHP",     "5.",  "critical","PHP 5.x is EOL since 2018 — many unpatched CVEs"),
    ("PHP",     "7.0", "high",   "PHP 7.0 is EOL"),
    ("PHP",     "7.1", "high",   "PHP 7.1 is EOL"),
    ("PHP",     "7.2", "high",   "PHP 7.2 is EOL"),
    ("PHP",     "7.3", "medium", "PHP 7.3 is EOL"),
    ("MySQL",   "5.5", "high",   "MySQL 5.5 is EOL"),
    ("MySQL",   "5.6", "high",   "MySQL 5.6 is EOL"),
    ("Tomcat",  "6.",  "critical","Tomcat 6.x is EOL"),
    ("Tomcat",  "7.",  "high",   "Tomcat 7.x is EOL"),
    ("Exim",    "4.8", "high",   "Exim 4.8x — verify patch level for critical CVEs"),
]


class Module(BaseModule):
    name = "banner"
    description = "Service banner grabber — version fingerprinting and EOL detection"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        ports = kwargs.get("ports", list(SERVICE_PROBES.keys()))
        timeout = self.config["network"]["banner_grab_timeout"]

        self.log.info(f"Banner grabbing on [bold]{host}[/] — {len(ports)} ports")

        banners: List[Dict] = []

        for port in ports:
            banner = self._grab(host, port, timeout)
            if banner:
                service, probe = SERVICE_PROBES.get(port, ("unknown", b""))
                version = self._extract_version(banner)
                entry = {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "version": version,
                }
                banners.append(entry)
                self.log.info(
                    f"  [green]{port}/tcp[/]  {service:<14} {version or ''}"
                    + (f"  [dim]{banner[:60]}[/]" if banner else "")
                )

                # EOL check
                for keyword, prefix, severity, note in EOL_CHECKS:
                    if keyword.lower() in banner.lower() and prefix in (version or ""):
                        result.add_finding(Finding(
                            title=f"EOL/Outdated Software: {keyword} {version}",
                            severity=severity,
                            description=f"{note}. Outdated software may have unpatched critical vulnerabilities.",
                            evidence=f"Port {port}/tcp — Banner: {banner[:150]}",
                            remediation=f"Upgrade {keyword} to the latest stable version.",
                            tags=["banner", "eol", "outdated", keyword.lower()],
                        ))

        result.data["banners"] = banners
        result.data["service_count"] = len(banners)

        if banners:
            result.add_finding(Finding(
                title=f"{len(banners)} Services Fingerprinted",
                severity="info",
                description="\n".join(
                    f"{b['port']}/tcp  {b['service']}  {b['version'] or 'version unknown'}"
                    for b in banners
                ),
                tags=["banner", "recon"],
            ))

        # Check for version disclosure via HTTP headers
        http_finding = self._check_http_version_disclosure(host, timeout)
        if http_finding:
            result.add_finding(http_finding)

        self.log.info(f"Banner grab complete — [bold green]{len(banners)} services fingerprinted[/]")
        return result

    def _grab(self, host: str, port: int, timeout: int) -> Optional[str]:
        try:
            _, probe = SERVICE_PROBES.get(port, ("", b""))
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if probe:
                    sock.sendall(probe)
                data = sock.recv(512)
                return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            return None

    def _extract_version(self, banner: str) -> Optional[str]:
        for pattern, label in VERSION_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                groups = m.groups()
                return groups[0] if groups else m.group(0)
        return None

    def _check_http_version_disclosure(self, host: str, timeout: int) -> Optional[Finding]:
        disclosures = []
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{host}",
                    timeout=timeout,
                    verify=False,
                    headers={"User-Agent": self.config["general"]["user_agent"]},
                )
                for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Drupal-Cache"]:
                    val = resp.headers.get(h)
                    if val:
                        disclosures.append(f"{h}: {val}")
                break
            except requests.RequestException:
                continue

        if disclosures:
            return Finding(
                title="Software Version Disclosed in HTTP Headers",
                severity="low",
                description=(
                    "HTTP response headers reveal software names and versions, "
                    "helping attackers identify targets for known CVEs."
                ),
                evidence="\n".join(disclosures),
                remediation=(
                    "Remove or obfuscate Server, X-Powered-By, and X-AspNet-Version headers. "
                    "In Apache: ServerTokens Prod. In nginx: server_tokens off."
                ),
                tags=["banner", "info-disclosure", "headers"],
            )
        return None
