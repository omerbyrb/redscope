import socket
from typing import Optional, Dict, List

import requests

from core.base_module import BaseModule, ScanResult, Finding

SHODAN_API = "https://api.shodan.io"

# Severity mapping for Shodan vuln CVSS scores
def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"

# Dangerous open ports/services to flag regardless of CVEs
RISKY_PORTS = {
    21:    ("FTP",           "medium", "Unencrypted file transfer"),
    23:    ("Telnet",        "critical","Unencrypted remote shell"),
    445:   ("SMB",          "high",   "Common ransomware/lateral movement vector"),
    3389:  ("RDP",          "high",   "Brute force and exploit target (BlueKeep)"),
    5900:  ("VNC",          "high",   "Often weak/no authentication"),
    6379:  ("Redis",        "critical","Frequently runs without authentication"),
    9200:  ("Elasticsearch","critical","Frequently runs without authentication"),
    27017: ("MongoDB",      "critical","Frequently runs without authentication"),
    11211: ("Memcached",    "high",   "DDoS amplification + data exposure"),
    2375:  ("Docker API",   "critical","Unauthenticated Docker daemon = full host takeover"),
    2376:  ("Docker TLS",   "high",   "Docker daemon with TLS — verify certs"),
    4243:  ("Docker API",   "critical","Unauthenticated Docker daemon"),
    8500:  ("Consul",       "high",   "Consul without ACLs exposes service mesh"),
    4001:  ("etcd",         "critical","etcd without auth = Kubernetes secret exposure"),
    2379:  ("etcd",         "critical","etcd without auth = Kubernetes secret exposure"),
    5601:  ("Kibana",       "high",   "Kibana without auth exposes Elasticsearch data"),
    15672: ("RabbitMQ",     "medium", "RabbitMQ management interface"),
    8080:  ("HTTP-Alt",     "low",    "Alternative HTTP port — verify content"),
    8443:  ("HTTPS-Alt",    "low",    "Alternative HTTPS port — verify content"),
}


class Module(BaseModule):
    name = "shodan"
    description = "Shodan integration — IP intelligence, open ports, CVEs, and exposure analysis"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        api_key = self.config.get("shodan", {}).get("api_key") or kwargs.get("api_key")

        # Resolve to IP
        try:
            ip = socket.gethostbyname(host)
            result.data["ip"] = ip
            self.log.info(f"Resolved [cyan]{host}[/] → [cyan]{ip}[/]")
        except socket.gaierror as e:
            result.add_error(f"DNS resolution failed: {e}")
            return result

        if api_key:
            self.log.info(f"Querying Shodan API for [bold]{ip}[/]")
            shodan_data = self._query_shodan(ip, api_key)
            if shodan_data:
                self._process_shodan_data(ip, host, shodan_data, result)
            else:
                self.log.warning("Shodan API returned no data — falling back to DNS history")
        else:
            self.log.warning(
                "[yellow]No Shodan API key configured.[/]\n"
                "  Add to config: shodan.api_key = 'YOUR_KEY'\n"
                "  Get a free key: https://account.shodan.io\n"
                "  Falling back to Shodan InternetDB (no key required)..."
            )
            self._query_internetdb(ip, host, result)

        return result

    # ── Shodan API (requires key) ─────────────────────────────────────────────

    def _query_shodan(self, ip: str, api_key: str) -> Optional[Dict]:
        try:
            resp = requests.get(
                f"{SHODAN_API}/shodan/host/{ip}",
                params={"key": api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                self.log.info(f"  [dim]IP {ip} not indexed by Shodan[/]")
            else:
                self.log.warning(f"  Shodan API error: {resp.status_code}")
        except requests.RequestException as e:
            self.log.warning(f"  Shodan request failed: {e}")
        return None

    def _process_shodan_data(self, ip: str, host: str, data: Dict, result: ScanResult) -> None:
        org = data.get("org", "unknown")
        isp = data.get("isp", "unknown")
        country = data.get("country_name", "unknown")
        city = data.get("city", "unknown")
        os_info = data.get("os", "unknown")
        hostnames = data.get("hostnames", [])
        domains = data.get("domains", [])
        ports = data.get("ports", [])
        vulns = data.get("vulns", {})
        tags = data.get("tags", [])

        result.data["shodan"] = {
            "org": org, "isp": isp, "country": country, "city": city,
            "os": os_info, "hostnames": hostnames, "domains": domains,
            "ports": ports, "vuln_count": len(vulns), "tags": tags,
        }

        self.log.info(f"  Org: [cyan]{org}[/] | ISP: {isp} | Location: {city}, {country}")
        self.log.info(f"  Open ports: [cyan]{ports}[/]")
        self.log.info(f"  Hostnames: {hostnames}")
        self.log.info(f"  Shodan tags: {tags}")

        # IP intelligence summary
        result.add_finding(Finding(
            title=f"Shodan Intelligence: {ip}",
            severity="info",
            description=(
                f"IP {ip} ({host}) intelligence from Shodan:\n"
                f"Organization: {org}\n"
                f"ISP: {isp}\n"
                f"Location: {city}, {country}\n"
                f"OS: {os_info}\n"
                f"Open ports: {ports}\n"
                f"Hostnames: {', '.join(hostnames) or 'none'}\n"
                f"Tags: {', '.join(tags) or 'none'}"
            ),
            tags=["shodan", "recon", "intelligence"],
        ))

        # Risky port findings
        for port in ports:
            if port in RISKY_PORTS:
                service, severity, reason = RISKY_PORTS[port]
                self.log.info(f"  [yellow]Risky port:[/] {port}/tcp ({service})")
                result.add_finding(Finding(
                    title=f"Risky Service Exposed: {port}/tcp ({service})",
                    severity=severity,
                    description=f"{service} on port {port} is indexed by Shodan — publicly reachable. {reason}.",
                    evidence=f"Shodan confirmed open: {ip}:{port}",
                    remediation=f"Restrict {service} behind a firewall. Only expose it to trusted IPs.",
                    tags=["shodan", "exposure", service.lower()],
                ))

        # CVE findings from Shodan
        for cve_id, cve_data in vulns.items():
            cvss = cve_data.get("cvss", 0.0) if isinstance(cve_data, dict) else 0.0
            severity = cvss_to_severity(cvss)
            summary = cve_data.get("summary", "No description") if isinstance(cve_data, dict) else str(cve_data)
            self.log.info(f"  [bold red]{cve_id}[/] CVSS:{cvss}")
            result.add_finding(Finding(
                title=f"Shodan CVE: {cve_id} on {ip}",
                severity=severity,
                description=summary[:300],
                evidence=f"CVSS: {cvss}\nShodan confirmed this CVE on {ip}",
                cvss=cvss,
                cve=cve_id,
                remediation=f"Patch the affected service. See https://nvd.nist.gov/vuln/detail/{cve_id}",
                tags=["shodan", "cve", "vulnerability"],
            ))

        # Special tags
        if "honeypot" in tags:
            result.add_finding(Finding(
                title="Shodan Tagged as Honeypot",
                severity="info",
                description=f"Shodan has tagged {ip} as a likely honeypot. Scan results may be unreliable.",
                tags=["shodan", "honeypot"],
            ))
        if "self-signed" in tags:
            result.add_finding(Finding(
                title="Self-Signed Certificate Detected",
                severity="low",
                description=f"Shodan reports {ip} uses a self-signed TLS certificate.",
                remediation="Obtain a certificate from a trusted CA (Let's Encrypt).",
                tags=["shodan", "tls", "self-signed"],
            ))

    # ── Shodan InternetDB (no key required) ───────────────────────────────────

    def _query_internetdb(self, ip: str, host: str, result: ScanResult) -> None:
        try:
            resp = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=8,
                headers={"User-Agent": self.config["general"]["user_agent"]},
            )
            if resp.status_code == 404:
                self.log.info(f"  [dim]{ip} not in Shodan InternetDB[/]")
                return
            if resp.status_code != 200:
                result.add_error(f"InternetDB returned {resp.status_code}")
                return

            data = resp.json()
            ports = data.get("ports", [])
            cpes = data.get("cpes", [])
            hostnames = data.get("hostnames", [])
            vulns = data.get("vulns", [])
            tags = data.get("tags", [])

            result.data["internetdb"] = data
            self.log.info(f"  Ports: [cyan]{ports}[/]")
            self.log.info(f"  CPEs: {cpes}")
            self.log.info(f"  Vulns: [red]{vulns}[/]")

            result.add_finding(Finding(
                title=f"Shodan InternetDB: {ip}",
                severity="info",
                description=(
                    f"Public Shodan data for {ip}:\n"
                    f"Open ports: {ports}\n"
                    f"Hostnames: {', '.join(hostnames) or 'none'}\n"
                    f"CPEs: {', '.join(cpes[:5]) or 'none'}\n"
                    f"Tags: {', '.join(tags) or 'none'}"
                ),
                tags=["shodan", "recon"],
            ))

            for port in ports:
                if port in RISKY_PORTS:
                    service, severity, reason = RISKY_PORTS[port]
                    result.add_finding(Finding(
                        title=f"Risky Service Indexed by Shodan: {port}/tcp ({service})",
                        severity=severity,
                        description=f"{reason}. Shodan has indexed this port — it is publicly reachable.",
                        evidence=f"InternetDB: {ip}:{port}",
                        remediation=f"Firewall {service} port {port} from public internet.",
                        tags=["shodan", "exposure", service.lower()],
                    ))

            for cve_id in vulns:
                self.log.info(f"  [bold red]{cve_id}[/] (InternetDB)")
                result.add_finding(Finding(
                    title=f"Shodan CVE: {cve_id} on {ip}",
                    severity="high",
                    description=f"Shodan InternetDB reports {cve_id} on {ip}.",
                    cve=cve_id,
                    remediation=f"See https://nvd.nist.gov/vuln/detail/{cve_id}",
                    tags=["shodan", "cve"],
                ))

        except requests.RequestException as e:
            result.add_error(f"InternetDB request failed: {e}")
