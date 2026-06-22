import socket
import concurrent.futures
from typing import List, Dict

import dns.resolver
import dns.reversename

from core.base_module import BaseModule, ScanResult, Finding


class Module(BaseModule):
    name = "dns"
    description = "DNS enumeration: A, AAAA, MX, NS, TXT, CNAME, SOA records"
    author = "RedScope"
    version = "1.0.0"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.log.info(f"DNS enumeration for [bold]{domain}[/]")
        records: Dict[str, List[str]] = {}

        for rtype in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
                self.log.info(f"  [cyan]{rtype}[/]: {records[rtype]}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception as e:
                result.add_error(f"{rtype} lookup failed: {e}")

        result.data["records"] = records

        # Check for zone transfer (AXFR)
        ns_records = records.get("NS", [])
        for ns in ns_records:
            ns = ns.rstrip(".")
            try:
                axfr = dns.query.xfr(ns, domain, timeout=5)
                zone_data = list(axfr)
                if zone_data:
                    result.add_finding(Finding(
                        title="DNS Zone Transfer Allowed",
                        severity="critical",
                        description=f"Name server {ns} allows zone transfer (AXFR) for {domain}",
                        evidence="\n".join(str(r) for r in zone_data[:10]),
                        remediation="Restrict AXFR to authorized secondary name servers only.",
                        tags=["dns", "axfr", "misconfiguration"],
                    ))
            except Exception:
                pass

        # Check for dangling CNAME
        cname_records = records.get("CNAME", [])
        for cname in cname_records:
            cname = cname.rstrip(".")
            try:
                socket.gethostbyname(cname)
            except socket.gaierror:
                result.add_finding(Finding(
                    title="Dangling CNAME (Subdomain Takeover Risk)",
                    severity="high",
                    description=f"CNAME target {cname} does not resolve — potential subdomain takeover",
                    evidence=f"CNAME: {domain} → {cname} (unresolved)",
                    remediation="Remove the dangling CNAME record or point it to a valid host.",
                    tags=["dns", "subdomain-takeover", "cname"],
                ))

        # SPF / DMARC checks
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = False
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
            has_dmarc = any("v=DMARC1" in str(r) for r in dmarc)
        except Exception:
            pass

        if not has_spf:
            result.add_finding(Finding(
                title="Missing SPF Record",
                severity="medium",
                description=f"{domain} has no SPF TXT record — email spoofing risk",
                remediation="Add an SPF record like: v=spf1 include:... ~all",
                tags=["dns", "email", "spf"],
            ))
        if not has_dmarc:
            result.add_finding(Finding(
                title="Missing DMARC Record",
                severity="medium",
                description=f"{domain} has no DMARC policy — phishing risk",
                remediation="Add a DMARC record at _dmarc.{domain}",
                tags=["dns", "email", "dmarc"],
            ))

        return result
