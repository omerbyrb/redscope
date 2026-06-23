import concurrent.futures
import socket
import random
from pathlib import Path
from typing import List, Set

import dns.resolver
import requests

from core.base_module import BaseModule, ScanResult, Finding


BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "vpn",
    "remote", "portal", "login", "app", "shop", "blog", "forum", "beta",
    "secure", "cloud", "cdn", "static", "media", "images", "assets", "docs",
    "help", "support", "status", "monitoring", "dashboard", "panel", "cpanel",
    "webmail", "smtp", "pop", "imap", "ns1", "ns2", "mx", "mx1", "mx2",
    "git", "gitlab", "github", "jira", "confluence", "jenkins", "ci", "cd",
    "internal", "intranet", "extranet", "corp", "office", "vpn2", "ssh",
    "db", "database", "mysql", "postgres", "redis", "elastic", "kibana",
    "grafana", "prometheus", "backup", "archive", "old", "new", "v2", "v3",
]


class Module(BaseModule):
    name = "subdomain"
    description = "Subdomain enumeration via wordlist brute force + wildcard detection"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.log.info(f"Subdomain enumeration for [bold]{domain}[/]")

        # Wildcard detection
        wildcard_ips = self._detect_wildcard(domain)
        if wildcard_ips:
            self.log.warning(f"[yellow]Wildcard DNS detected[/] → {wildcard_ips}")
            result.data["wildcard"] = list(wildcard_ips)

        # Load wordlist
        wordlist = self._load_wordlist()
        self.log.info(f"Testing [cyan]{len(wordlist)}[/] subdomains with {self.config['general']['threads']} threads")

        found: List[dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["general"]["threads"]) as executor:
            futures = {
                executor.submit(self._resolve, f"{word}.{domain}", wildcard_ips): word
                for word in wordlist
            }
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    found.append(res)
                    self.log.info(f"  [green]FOUND[/] {res['subdomain']} → {res['ips']}")

        found.sort(key=lambda x: x["subdomain"])
        result.data["subdomains"] = found
        result.data["count"] = len(found)

        if found:
            result.add_finding(Finding(
                title=f"{len(found)} Subdomains Discovered",
                severity="info",
                description="\n".join(f"{s['subdomain']} → {', '.join(s['ips'])}" for s in found),
                tags=["recon", "subdomain"],
            ))

        # Check for interesting subdomains
        interesting = ["admin", "vpn", "staging", "dev", "test", "internal", "jenkins", "gitlab", "db"]
        for sub in found:
            name = sub["subdomain"].split(".")[0]
            if name in interesting:
                result.add_finding(Finding(
                    title=f"Sensitive Subdomain Exposed: {sub['subdomain']}",
                    severity="medium",
                    description=f"Potentially sensitive service accessible at {sub['subdomain']}",
                    evidence=f"{sub['subdomain']} resolves to {', '.join(sub['ips'])}",
                    remediation="Ensure this subdomain is not publicly accessible if it hosts internal services.",
                    tags=["recon", "subdomain", "exposure"],
                ))

        self.log.info(f"Subdomain scan complete — [bold green]{len(found)} found[/]")
        return result

    def _resolve(self, subdomain: str, wildcard_ips: Set[str]) -> dict | None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.config["recon"]["dns_resolvers"]
            resolver.lifetime = 3
            answers = resolver.resolve(subdomain, "A")
            ips = {str(r) for r in answers}
            if wildcard_ips and ips.issubset(wildcard_ips):
                return None
            return {"subdomain": subdomain, "ips": list(ips)}
        except Exception:
            return None

    def _detect_wildcard(self, domain: str) -> Set[str]:
        random_sub = f"redscope-{random.randint(100000, 999999)}.{domain}"
        try:
            answers = dns.resolver.resolve(random_sub, "A", lifetime=3)
            return {str(r) for r in answers}
        except Exception:
            return set()

    def _load_wordlist(self) -> List[str]:
        wordlist_path = Path(self.config["recon"]["subdomain_wordlist"])
        if wordlist_path.exists():
            with open(wordlist_path) as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return BUILTIN_WORDLIST
