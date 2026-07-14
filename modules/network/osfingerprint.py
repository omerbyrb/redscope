import socket
import struct
import re
import time
from typing import Optional, Dict, List

import requests

from core.base_module import BaseModule, ScanResult, Finding

# OS fingerprint signatures from banners and HTTP headers
OS_SIGNATURES: List[Dict] = [
    # Windows
    {"pattern": r"windows\s*(nt\s*)?(\d+\.\d+|xp|vista|7|8|10|11|server)",
     "os": "Windows", "family": "windows"},
    {"pattern": r"IIS/(\d+\.\d+)",
     "os": "Windows (IIS)", "family": "windows"},
    {"pattern": r"Microsoft-HTTPAPI/(\d+\.\d+)",
     "os": "Windows", "family": "windows"},
    {"pattern": r"win32|win64",
     "os": "Windows", "family": "windows"},
    {"pattern": r"NTLM",
     "os": "Windows", "family": "windows"},
    # Linux
    {"pattern": r"ubuntu|debian|centos|fedora|rhel|red hat|kali|arch|alpine",
     "os": "Linux", "family": "linux"},
    {"pattern": r"Linux/(\d+\.\d+[\.\d]*)",
     "os": "Linux", "family": "linux"},
    {"pattern": r"apache.*unix|unix.*apache",
     "os": "Unix/Linux", "family": "linux"},
    {"pattern": r"Debian|Ubuntu|CentOS|Fedora",
     "os": "Linux", "family": "linux"},
    # FreeBSD / BSD
    {"pattern": r"freebsd|openbsd|netbsd",
     "os": "BSD", "family": "bsd"},
    {"pattern": r"FreeBSD/(\d+\.\d+)",
     "os": "FreeBSD", "family": "bsd"},
    # macOS
    {"pattern": r"darwin|macos|mac os x",
     "os": "macOS/Darwin", "family": "macos"},
    # Cisco / Network
    {"pattern": r"cisco|ios\s+(\d+\.\d+)",
     "os": "Cisco IOS", "family": "network"},
    {"pattern": r"junos",
     "os": "Juniper JunOS", "family": "network"},
    # Embedded
    {"pattern": r"mikrotik",
     "os": "MikroTik RouterOS", "family": "embedded"},
    {"pattern": r"dd-wrt",
     "os": "DD-WRT", "family": "embedded"},
    {"pattern": r"openwrt",
     "os": "OpenWrt", "family": "embedded"},
]

# TTL-based OS guessing (from ICMP/TCP responses)
TTL_MAP = [
    (range(60, 65),   "Linux/Unix (TTL~64)"),
    (range(126, 129), "Windows (TTL~128)"),
    (range(253, 256), "Cisco/Solaris (TTL~255)"),
    (range(30, 33),   "Windows 95/98 (TTL~32)"),
]

# Service-to-OS hints
SERVICE_OS_HINTS = {
    "rdp":     ("Windows", "RDP only runs on Windows"),
    "winrm":   ("Windows", "WinRM is Windows Remote Management"),
    "smb":     ("Windows", "SMB/CIFS typically indicates Windows"),
    "netbios": ("Windows", "NetBIOS service indicates Windows"),
    "wmi":     ("Windows", "WMI is Windows-specific"),
}

PORTS_TO_PROBE = [22, 80, 443, 8080, 8443, 21, 25, 3389]


class Module(BaseModule):
    name = "osfingerprint"
    description = "OS fingerprinting — banner analysis, TTL probing, HTTP header heuristics"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"OS fingerprinting on [bold]{host}[/]")

        candidates: Dict[str, int] = {}  # os_family -> confidence score

        # Method 1: HTTP header analysis
        http_os = self._fingerprint_http(host, timeout)
        if http_os:
            self.log.info(f"  [cyan]HTTP headers →[/] {http_os}")
            candidates[http_os] = candidates.get(http_os, 0) + 3

        # Method 2: TCP banner grabbing
        banner_os = self._fingerprint_banners(host, timeout)
        for os_name, score in banner_os.items():
            self.log.info(f"  [cyan]Banner →[/] {os_name} (confidence +{score})")
            candidates[os_name] = candidates.get(os_name, 0) + score

        # Method 3: TTL-based fingerprinting
        ttl_os = self._fingerprint_ttl(host, timeout)
        if ttl_os:
            self.log.info(f"  [cyan]TTL probe →[/] {ttl_os}")
            candidates[ttl_os] = candidates.get(ttl_os, 0) + 2

        # Method 4: Open port heuristics
        port_os = self._fingerprint_ports(host, timeout)
        for os_name, reason in port_os:
            self.log.info(f"  [cyan]Port heuristic →[/] {os_name} ({reason})")
            candidates[os_name] = candidates.get(os_name, 0) + 1

        result.data["candidates"] = candidates

        if not candidates:
            self.log.info("[dim]Could not determine OS[/]")
            return result

        # Pick highest confidence
        best_os = max(candidates, key=candidates.get)
        confidence = candidates[best_os]
        confidence_label = "High" if confidence >= 5 else "Medium" if confidence >= 3 else "Low"

        result.data["os"] = best_os
        result.data["confidence"] = confidence_label

        self.log.info(
            f"  [bold green]OS: {best_os}[/] — confidence: {confidence_label} ({confidence} signals)"
        )

        result.add_finding(Finding(
            title=f"OS Fingerprint: {best_os}",
            severity="info",
            description=(
                f"Operating system identified as [bold]{best_os}[/] "
                f"with {confidence_label} confidence ({confidence} independent signals).\n"
                f"All candidates: " + ", ".join(f"{k} ({v})" for k, v in sorted(candidates.items(), key=lambda x: -x[1]))
            ),
            evidence="\n".join(f"{k}: {v} signals" for k, v in sorted(candidates.items(), key=lambda x: -x[1])),
            remediation="Suppress OS-revealing banners (ServerTokens Prod, server_tokens off) to reduce fingerprinting surface.",
            tags=["osfingerprint", "recon", "info-disclosure"],
        ))

        # OS-specific risk findings
        os_findings = self._os_risk_findings(best_os, host)
        result.findings.extend(os_findings)

        return result

    def _fingerprint_http(self, host: str, timeout: int) -> Optional[str]:
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{host}",
                    timeout=timeout,
                    verify=False,
                    headers={"User-Agent": self.config["general"]["user_agent"]},
                )
                headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
                combined = headers_str + " " + resp.text[:500]

                for sig in OS_SIGNATURES:
                    if re.search(sig["pattern"], combined, re.IGNORECASE):
                        return sig["os"]
                return None
            except requests.RequestException:
                continue
        return None

    def _fingerprint_banners(self, host: str, timeout: int) -> Dict[str, int]:
        found: Dict[str, int] = {}
        for port in PORTS_TO_PROBE:
            try:
                with socket.create_connection((host, port), timeout=3) as sock:
                    sock.settimeout(2)
                    try:
                        if port in (80, 8080, 8443, 443):
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(512).decode("utf-8", errors="ignore")
                        for sig in OS_SIGNATURES:
                            if re.search(sig["pattern"], banner, re.IGNORECASE):
                                os_name = sig["os"]
                                found[os_name] = found.get(os_name, 0) + 1
                    except Exception:
                        pass
            except Exception:
                continue
        return found

    def _fingerprint_ttl(self, host: str, timeout: int) -> Optional[str]:
        # Use socket connect timing as a lightweight TTL proxy
        # Real TTL requires raw sockets (root). We use TCP RST timing heuristic instead.
        try:
            import subprocess, platform
            flag = "-n" if platform.system().lower() == "windows" else "-c"
            count = "-1" if platform.system().lower() == "windows" else "1"
            out = subprocess.run(
                ["ping", flag, count, host],
                capture_output=True, text=True, timeout=5
            ).stdout

            ttl_match = re.search(r"ttl[=\s]+(\d+)", out, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                for ttl_range, os_name in TTL_MAP:
                    if ttl in ttl_range:
                        return f"{os_name} (TTL={ttl})"
        except Exception:
            pass
        return None

    def _fingerprint_ports(self, host: str, timeout: int) -> List[tuple]:
        hints = []
        port_checks = {
            3389: ("rdp",     "Windows", "RDP port open"),
            5985: ("winrm",   "Windows", "WinRM port open"),
            5986: ("winrm",   "Windows", "WinRM SSL port open"),
            445:  ("smb",     "Windows", "SMB port open"),
            139:  ("netbios", "Windows", "NetBIOS port open"),
        }
        for port, (service, os_name, reason) in port_checks.items():
            try:
                with socket.create_connection((host, port), timeout=2):
                    hints.append((os_name, reason))
            except Exception:
                continue
        return hints

    def _os_risk_findings(self, os_name: str, host: str) -> List[Finding]:
        findings = []
        os_lower = os_name.lower()

        if "windows" in os_lower:
            findings.append(Finding(
                title="Windows Host — Verify Patch Level",
                severity="info",
                description=(
                    f"{host} appears to run Windows. "
                    "Ensure the system is fully patched — Windows hosts are frequent targets for "
                    "EternalBlue (MS17-010), PrintNightmare, ZeroLogon, and other critical CVEs."
                ),
                remediation="Run Windows Update, enable automatic updates, and ensure SMB v1 is disabled.",
                tags=["osfingerprint", "windows", "patch-management"],
            ))
        elif "linux" in os_lower:
            findings.append(Finding(
                title="Linux Host — Verify Kernel and Package Versions",
                severity="info",
                description=(
                    f"{host} appears to run Linux. "
                    "Check for unpatched kernel vulnerabilities (Dirty COW, PwnKit, Dirty Pipe) "
                    "and ensure package managers are up to date."
                ),
                remediation="Run apt/yum update regularly. Use unattended-upgrades for automatic security patches.",
                tags=["osfingerprint", "linux", "patch-management"],
            ))
        elif "cisco" in os_lower or "junos" in os_lower:
            findings.append(Finding(
                title="Network Device Detected — Firmware Audit Recommended",
                severity="medium",
                description=(
                    f"A network device ({os_name}) was identified at {host}. "
                    "Network devices are high-value targets — ensure firmware is current and "
                    "management interfaces are not publicly exposed."
                ),
                remediation="Update firmware, disable telnet, enforce SSH with strong ciphers, restrict management access by IP.",
                tags=["osfingerprint", "network-device", "firmware"],
            ))

        return findings
