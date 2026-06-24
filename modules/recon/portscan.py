import socket
import concurrent.futures
from typing import Dict, List, Optional

from core.base_module import BaseModule, ScanResult, Finding

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1080, 1433, 1521, 2049, 2181, 3000,
    3306, 3389, 4369, 5432, 5900, 6379, 6443, 7001, 8080, 8443,
    8888, 9000, 9090, 9200, 9300, 11211, 15672, 27017, 28017,
]

SERVICE_BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2181: "Zookeeper",
    3000: "Dev Server", 3306: "MySQL", 3389: "RDP", 4369: "Erlang",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes",
    7001: "WebLogic", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9000: "PHP-FPM/SonarQube", 9090: "Prometheus", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached", 15672: "RabbitMQ",
    27017: "MongoDB", 28017: "MongoDB-Web",
}

DANGEROUS_PORTS = {
    21: ("FTP open", "high", "FTP transmits credentials in plaintext. Disable or replace with SFTP."),
    23: ("Telnet open", "critical", "Telnet is unencrypted. Replace with SSH immediately."),
    135: ("RPC Endpoint Mapper open", "medium", "Windows RPC exposed — common attack vector."),
    139: ("NetBIOS open", "medium", "NetBIOS session service exposed — restrict to internal only."),
    445: ("SMB open", "high", "SMB exposed to internet — EternalBlue and ransomware risk."),
    1433: ("MSSQL open", "high", "Database port exposed publicly — restrict with firewall."),
    1521: ("Oracle DB open", "high", "Oracle DB exposed publicly — restrict with firewall."),
    3306: ("MySQL open", "high", "MySQL exposed publicly — should be behind firewall."),
    3389: ("RDP open", "high", "RDP exposed — brute force and BlueKeep risk."),
    4369: ("Erlang Port Mapper open", "medium", "Erlang EPMD exposed — RabbitMQ/CouchDB attack surface."),
    5432: ("PostgreSQL open", "high", "PostgreSQL exposed publicly — restrict with firewall."),
    5900: ("VNC open", "high", "VNC exposed — often weak or no authentication."),
    6379: ("Redis open", "critical", "Redis with no auth exposed — full server compromise possible."),
    7001: ("WebLogic open", "high", "WebLogic has multiple critical RCE CVEs."),
    8888: ("Jupyter Notebook open", "critical", "Jupyter may allow unauthenticated code execution."),
    9200: ("Elasticsearch open", "high", "Elasticsearch exposed — data leak risk, often no auth."),
    11211: ("Memcached open", "high", "Memcached exposed — data leak and DDoS amplification risk."),
    27017: ("MongoDB open", "critical", "MongoDB exposed — often runs without authentication."),
}


class Module(BaseModule):
    name = "portscan"
    description = "TCP port scanner with service detection and risk assessment"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        ports = kwargs.get("ports", COMMON_PORTS)
        threads = self.config["general"]["threads"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"Port scanning [bold]{host}[/] — {len(ports)} ports, {threads} threads")

        try:
            ip = socket.gethostbyname(host)
            result.data["ip"] = ip
            self.log.info(f"Resolved [cyan]{host}[/] → [cyan]{ip}[/]")
        except socket.gaierror as e:
            result.add_error(f"DNS resolution failed: {e}")
            return result

        open_ports: List[Dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_port, ip, port, timeout): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                port_info = future.result()
                if port_info:
                    open_ports.append(port_info)
                    service = port_info.get("service", "unknown")
                    banner = f" [{port_info['banner']}]" if port_info.get("banner") else ""
                    self.log.info(f"  [green]OPEN[/] {port_info['port']}/tcp  {service}{banner}")

        open_ports.sort(key=lambda x: x["port"])
        result.data["open_ports"] = open_ports
        result.data["open_count"] = len(open_ports)

        if open_ports:
            result.add_finding(Finding(
                title=f"{len(open_ports)} Open Ports Found",
                severity="info",
                description="\n".join(
                    f"{p['port']}/tcp  {p.get('service','?')}  {p.get('banner','')}"
                    for p in open_ports
                ),
                tags=["recon", "portscan"],
            ))

        for port_info in open_ports:
            port = port_info["port"]
            if port in DANGEROUS_PORTS:
                title, severity, remediation = DANGEROUS_PORTS[port]
                result.add_finding(Finding(
                    title=title,
                    severity=severity,
                    description=f"Port {port}/tcp ({port_info.get('service','?')}) is open and publicly reachable on {host}",
                    evidence=port_info.get("banner", ""),
                    remediation=remediation,
                    tags=["recon", "portscan", "exposure"],
                ))

        self.log.info(f"Port scan complete — [bold green]{len(open_ports)} open ports[/]")
        return result

    def _check_port(self, ip: str, port: int, timeout: int) -> Optional[Dict]:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                banner = self._grab_banner(sock, port)
                return {
                    "port": port,
                    "service": SERVICE_BANNERS.get(port, "unknown"),
                    "banner": banner,
                }
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(2)
            if port in (80, 8080, 8443, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass
            else:
                sock.sendall(b"\r\n")
            return sock.recv(256).decode("utf-8", errors="ignore").strip().split("\n")[0][:100]
        except Exception:
            return ""
