import re
import time
from typing import List, Optional, Dict

import requests

from core.base_module import BaseModule, ScanResult, Finding

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Static CVE database for offline/fallback use
# format: (keyword, version_prefix, cve_id, cvss, description, severity)
KNOWN_CVES = [
    # OpenSSH
    ("openssh", "8.5", "CVE-2023-38408", 9.8, "Remote code execution via ssh-agent forwarding", "critical"),
    ("openssh", "9.0", "CVE-2023-51767", 6.5, "Authentication bypass in OpenSSH 9.x", "medium"),
    ("openssh", "7.",  "CVE-2018-15473", 5.3, "Username enumeration via timing attack", "medium"),
    ("openssh", "6.",  "CVE-2016-0777",  8.0, "Roaming feature leaks private keys", "high"),
    # Apache
    ("apache",  "2.4.49", "CVE-2021-41773", 9.8, "Path traversal and RCE in Apache 2.4.49", "critical"),
    ("apache",  "2.4.50", "CVE-2021-42013", 9.8, "Path traversal bypass in Apache 2.4.50", "critical"),
    ("apache",  "2.4",    "CVE-2022-31813", 9.8, "Request smuggling via mod_proxy", "critical"),
    ("apache",  "2.2",    "CVE-2017-7679",  9.8, "Buffer overflow in mod_mime (EOL)", "critical"),
    # nginx
    ("nginx",   "1.3",    "CVE-2013-2028",  7.5, "Stack-based buffer overflow in nginx", "high"),
    ("nginx",   "1.9",    "CVE-2016-0742",  5.0, "Invalid pointer dereference in DNS resolver", "medium"),
    # PHP
    ("php",     "5.",     "CVE-2019-11043", 9.8, "RCE in PHP-FPM with nginx misconfiguration", "critical"),
    ("php",     "7.1",    "CVE-2019-11043", 9.8, "RCE in PHP-FPM with nginx misconfiguration", "critical"),
    ("php",     "7.2",    "CVE-2019-11043", 9.8, "RCE in PHP-FPM with nginx misconfiguration", "critical"),
    ("php",     "7.3",    "CVE-2021-21703", 7.0, "Local privilege escalation in PHP-FPM", "high"),
    ("php",     "8.0",    "CVE-2022-31625", 9.8, "Use-after-free in Postgres extension", "critical"),
    # IIS
    ("iis",     "6.",     "CVE-2017-7269",  9.8, "Buffer overflow in WebDAV — IIS 6.0 RCE", "critical"),
    ("iis",     "7.",     "CVE-2010-2730",  9.3, "Remote code execution in IIS 7.5", "critical"),
    # MySQL
    ("mysql",   "5.5",    "CVE-2016-6662",  9.8, "MySQL remote code execution via config injection", "critical"),
    ("mysql",   "5.6",    "CVE-2016-6662",  9.8, "MySQL remote code execution via config injection", "critical"),
    ("mysql",   "5.7",    "CVE-2020-14765", 6.5, "Denial of service in MySQL 5.7", "medium"),
    # Redis
    ("redis",   "6.",     "CVE-2022-0543",  10.0, "Lua sandbox escape — RCE in Redis 6.x (Debian)", "critical"),
    ("redis",   "5.",     "CVE-2019-10192", 7.2, "Heap buffer overflow in Redis 5.x", "high"),
    # MongoDB
    ("mongodb", "4.",     "CVE-2021-20330", 6.5, "Denial of service in MongoDB 4.x", "medium"),
    ("mongodb", "3.",     "CVE-2019-2389",  6.5, "Improper auth check in MongoDB 3.x", "medium"),
    # Tomcat
    ("tomcat",  "6.",     "CVE-2017-12617", 9.8, "JSP upload bypass and RCE — Tomcat 6", "critical"),
    ("tomcat",  "7.",     "CVE-2017-12617", 9.8, "JSP upload bypass and RCE — Tomcat 7", "critical"),
    ("tomcat",  "8.",     "CVE-2020-1938",  9.8, "Ghostcat — AJP file read/RCE in Tomcat 8", "critical"),
    ("tomcat",  "9.",     "CVE-2020-1938",  9.8, "Ghostcat — AJP file read/RCE in Tomcat 9", "critical"),
    # Exim
    ("exim",    "4.",     "CVE-2019-10149", 9.8, "Remote command execution in Exim (The Return of the WIZard)", "critical"),
    # ProFTPD
    ("proftpd", "1.3",    "CVE-2019-12815", 9.8, "Arbitrary file copy via mod_copy in ProFTPD", "critical"),
    # OpenSSL
    ("openssl", "1.0.1",  "CVE-2014-0160",  7.5, "Heartbleed — memory disclosure via heartbeat", "high"),
    ("openssl", "1.0.2",  "CVE-2016-0800",  7.4, "DROWN attack — SSLv2 cross-protocol attack", "high"),
    ("openssl", "1.1.1",  "CVE-2022-0778",  7.5, "Infinite loop in BN_mod_sqrt (DoS)", "high"),
    # vsftpd
    ("vsftpd",  "2.3.4",  "CVE-2011-2523",  10.0, "vsftpd 2.3.4 backdoor — RCE via smiley face payload", "critical"),
]


class Module(BaseModule):
    name = "cvelookup"
    description = "CVE lookup — match detected software versions against known vulnerabilities"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)

        # Accept banners from banner module output or manual input
        banners: List[Dict] = kwargs.get("banners", [])
        software: List[Dict] = kwargs.get("software", [])

        if not banners and not software:
            self.log.warning(
                "No banners provided — run [cyan]banner[/] module first, or pass software= manually.\n"
                "  Example: redscope scan target --modules banner cvelookup"
            )
            # Try to derive from target string directly
            software = self._parse_target_as_software(target)

        items = software or [
            {"name": b.get("service", ""), "version": b.get("version", ""), "port": b.get("port")}
            for b in banners
            if b.get("version")
        ]

        if not items:
            result.add_error("No software/version information to look up")
            return result

        self.log.info(f"CVE lookup for [bold]{len(items)}[/] software items")

        total_cves = 0
        for item in items:
            name = item.get("name", "")
            version = item.get("version", "")
            port = item.get("port")

            if not name or not version:
                continue

            self.log.info(f"  Checking [cyan]{name} {version}[/]")

            # Local database lookup
            local_hits = self._local_lookup(name, version)

            # NVD API lookup (rate-limited: 5 req/30s without API key)
            nvd_hits = self._nvd_lookup(name, version)

            all_hits = {h["cve_id"]: h for h in local_hits + nvd_hits}.values()

            for hit in all_hits:
                total_cves += 1
                self.log.info(
                    f"    [bold red]{hit['cve_id']}[/] CVSS:{hit['cvss']} — {hit['description'][:60]}"
                )
                result.add_finding(Finding(
                    title=f"{hit['cve_id']} — {name} {version}",
                    severity=hit["severity"],
                    description=hit["description"],
                    evidence=(
                        f"Software: {name} {version}"
                        + (f" (port {port})" if port else "") +
                        f"\nCVSS Score: {hit['cvss']}"
                        f"\nCVE: https://nvd.nist.gov/vuln/detail/{hit['cve_id']}"
                    ),
                    cvss=hit["cvss"],
                    cve=hit["cve_id"],
                    remediation=f"Update {name} to the latest patched version. See {hit['cve_id']} for details.",
                    tags=["cve", "vulnerability", name.lower()],
                ))

        result.data["total_cves"] = total_cves
        if total_cves == 0:
            self.log.info("[dim]No known CVEs found for detected versions[/]")
        else:
            self.log.info(f"CVE lookup complete — [bold red]{total_cves} CVEs found[/]")

        return result

    def _local_lookup(self, name: str, version: str) -> List[Dict]:
        hits = []
        name_lower = name.lower()
        for keyword, ver_prefix, cve_id, cvss, description, severity in KNOWN_CVES:
            if keyword in name_lower and version.startswith(ver_prefix):
                hits.append({
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "description": description,
                    "severity": severity,
                })
        return hits

    def _nvd_lookup(self, name: str, version: str) -> List[Dict]:
        hits = []
        try:
            params = {
                "keywordSearch": f"{name} {version}",
                "resultsPerPage": 5,
            }
            resp = requests.get(NVD_API, params=params, timeout=10)
            if resp.status_code != 200:
                return []

            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description available"
                )
                metrics = cve.get("metrics", {})
                cvss = 0.0
                severity = "info"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss = cvss_data.get("baseScore", 0.0)
                        sev = cvss_data.get("baseSeverity", "").lower()
                        severity = sev if sev in ("critical", "high", "medium", "low") else "info"
                        break

                if cvss >= 5.0:
                    hits.append({
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "description": desc[:200],
                        "severity": severity,
                    })

            time.sleep(0.6)  # NVD rate limit: ~5 req/30s without API key
        except Exception:
            pass
        return hits

    def _parse_target_as_software(self, target: str) -> List[Dict]:
        items = []
        patterns = [
            r"(apache)[/ ](\d+\.\d+[\.\d]*)",
            r"(nginx)[/ ](\d+\.\d+[\.\d]*)",
            r"(openssh)[_-](\d+\.\d+\w*)",
            r"(php)[/ ](\d+\.\d+[\.\d]*)",
            r"(mysql) (\d+\.\d+[\.\d]*)",
            r"(redis)_version:(\S+)",
            r"(iis)[/ ](\d+\.\d+)",
        ]
        for pattern in patterns:
            m = re.search(pattern, target, re.IGNORECASE)
            if m:
                items.append({"name": m.group(1), "version": m.group(2)})
        return items
