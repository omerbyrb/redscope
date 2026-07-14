import re
from typing import Optional, List, Dict

import dns.resolver

from core.base_module import BaseModule, ScanResult, Finding


class Module(BaseModule):
    name = "emailsec"
    description = "Email security auditor — SPF, DKIM, DMARC, MTA-STS, BIMI deep analysis"
    author = "RedScope"
    version = "1.0.0"

    COMMON_DKIM_SELECTORS = [
        "default", "google", "mail", "email", "dkim", "k1", "k2",
        "selector1", "selector2", "smtp", "mta", "key1", "key2",
        "s1", "s2", "zoho", "mandrill", "sendgrid", "mailchimp",
        "amazonses", "protonmail", "outlook", "office365",
    ]

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.log.info(f"Email security audit for [bold]{domain}[/]")

        # SPF
        self._check_spf(domain, result)

        # DMARC
        self._check_dmarc(domain, result)

        # DKIM
        self._check_dkim(domain, result)

        # MTA-STS
        self._check_mta_sts(domain, result)

        # BIMI
        self._check_bimi(domain, result)

        # MX records
        self._check_mx(domain, result)

        if not result.findings:
            self.log.info("[dim]Email security looks good[/]")

        return result

    # ── SPF ──────────────────────────────────────────────────────────────────

    def _check_spf(self, domain: str, result: ScanResult) -> None:
        self.log.info("  Checking SPF...")
        txt_records = self._get_txt(domain)
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            result.add_finding(Finding(
                title="Missing SPF Record",
                severity="high",
                description=f"{domain} has no SPF TXT record. Anyone can send email as @{domain}.",
                remediation=f"Add: v=spf1 include:_spf.google.com ~all  (adjust to your mail provider)",
                tags=["email", "spf", "spoofing"],
            ))
            return

        if len(spf_records) > 1:
            result.add_finding(Finding(
                title="Multiple SPF Records Found",
                severity="high",
                description="Multiple SPF records cause undefined behavior — only one is allowed per RFC 7208.",
                evidence="\n".join(spf_records),
                remediation="Merge all SPF records into a single TXT record.",
                tags=["email", "spf", "misconfiguration"],
            ))

        spf = spf_records[0]
        result.data["spf"] = spf
        self.log.info(f"    SPF: [cyan]{spf}[/]")

        # +all → anyone can send
        if "+all" in spf:
            result.add_finding(Finding(
                title="SPF Record Uses +all (Permits All Senders)",
                severity="critical",
                description="+all means any server can send mail as this domain — SPF provides zero protection.",
                evidence=f"SPF: {spf}",
                remediation="Replace +all with ~all (softfail) or -all (hardfail).",
                tags=["email", "spf", "spoofing"],
            ))

        # ?all → neutral
        elif "?all" in spf:
            result.add_finding(Finding(
                title="SPF Record Uses ?all (Neutral — No Enforcement)",
                severity="medium",
                description="?all is neutral — unauthorized senders are not rejected or flagged.",
                evidence=f"SPF: {spf}",
                remediation="Use ~all or -all for enforcement.",
                tags=["email", "spf"],
            ))

        # ~all without DMARC → softfail not enforced
        elif "~all" in spf:
            self.log.info("    [yellow]SPF uses ~all (softfail)[/] — check DMARC for enforcement")

        # DNS lookup count (max 10 per RFC)
        lookup_count = sum(1 for term in ["include:", "a", "mx", "redirect=", "exists:"] if term in spf)
        if lookup_count > 8:
            result.add_finding(Finding(
                title="SPF Record Approaches DNS Lookup Limit",
                severity="medium",
                description=f"SPF record triggers ~{lookup_count} DNS lookups. RFC 7208 limits to 10 — exceeding causes PermError.",
                evidence=f"SPF: {spf}",
                remediation="Flatten SPF record using a service like dmarcian or MxToolbox SPF flattener.",
                tags=["email", "spf", "dns-limit"],
            ))

    # ── DMARC ────────────────────────────────────────────────────────────────

    def _check_dmarc(self, domain: str, result: ScanResult) -> None:
        self.log.info("  Checking DMARC...")
        records = self._get_txt(f"_dmarc.{domain}")
        dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

        if not dmarc_records:
            result.add_finding(Finding(
                title="Missing DMARC Record",
                severity="high",
                description=(
                    f"No DMARC record at _dmarc.{domain}. "
                    "Without DMARC, SPF/DKIM failures are not enforced and phishing emails pass through."
                ),
                remediation=f"Add TXT record at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
                tags=["email", "dmarc", "phishing"],
            ))
            return

        dmarc = dmarc_records[0]
        result.data["dmarc"] = dmarc
        self.log.info(f"    DMARC: [cyan]{dmarc}[/]")

        # Policy check
        policy_match = re.search(r"p=(\w+)", dmarc)
        policy = policy_match.group(1).lower() if policy_match else "none"

        if policy == "none":
            result.add_finding(Finding(
                title="DMARC Policy Set to 'none' — No Enforcement",
                severity="high",
                description=(
                    "DMARC p=none means failures are only reported, not rejected or quarantined. "
                    "Phishing emails still reach recipients."
                ),
                evidence=f"DMARC: {dmarc}",
                remediation="Upgrade to p=quarantine, then p=reject once reporting confirms legitimate mail flows.",
                tags=["email", "dmarc", "phishing"],
            ))
        elif policy == "quarantine":
            result.add_finding(Finding(
                title="DMARC Policy is 'quarantine' — Consider Upgrading to 'reject'",
                severity="low",
                description="p=quarantine sends suspicious mail to spam. p=reject fully blocks it.",
                evidence=f"DMARC: {dmarc}",
                remediation="After monitoring reports, upgrade to p=reject for full phishing prevention.",
                tags=["email", "dmarc"],
            ))
        else:
            self.log.info("    [green]DMARC p=reject[/] ✓")

        # Subdomain policy
        sp_match = re.search(r"sp=(\w+)", dmarc)
        if not sp_match:
            result.add_finding(Finding(
                title="DMARC Missing Subdomain Policy (sp=)",
                severity="medium",
                description="No sp= tag — subdomains inherit the main policy, which may be weaker than intended.",
                evidence=f"DMARC: {dmarc}",
                remediation=f"Add sp=reject to explicitly protect subdomains: {dmarc}; sp=reject",
                tags=["email", "dmarc", "subdomain"],
            ))

        # Reporting address
        if "rua=" not in dmarc:
            result.add_finding(Finding(
                title="DMARC Missing Aggregate Report Address (rua=)",
                severity="low",
                description="No rua= tag — you will not receive DMARC aggregate reports to monitor mail flow.",
                evidence=f"DMARC: {dmarc}",
                remediation=f"Add rua=mailto:dmarc@{domain} to receive aggregate reports.",
                tags=["email", "dmarc", "reporting"],
            ))

        # Percentage
        pct_match = re.search(r"pct=(\d+)", dmarc)
        if pct_match and int(pct_match.group(1)) < 100:
            result.add_finding(Finding(
                title=f"DMARC Applies to Only {pct_match.group(1)}% of Messages",
                severity="medium",
                description=f"pct={pct_match.group(1)} means policy only applies to {pct_match.group(1)}% of failing emails.",
                evidence=f"DMARC: {dmarc}",
                remediation="Set pct=100 once you are confident in your mail infrastructure.",
                tags=["email", "dmarc"],
            ))

    # ── DKIM ────────────────────────────────────────────────────────────────

    def _check_dkim(self, domain: str, result: ScanResult) -> None:
        self.log.info("  Checking DKIM selectors...")
        found_selectors = []

        for selector in self.COMMON_DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                records = self._get_txt(dkim_domain)
                dkim_records = [r for r in records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]
                if dkim_records:
                    self.log.info(f"    [green]DKIM found:[/] selector={selector}")
                    found_selectors.append({"selector": selector, "record": dkim_records[0]})

                    # Check key length
                    p_match = re.search(r"p=([A-Za-z0-9+/=]+)", dkim_records[0])
                    if p_match:
                        key_b64 = p_match.group(1)
                        key_bits = len(key_b64) * 6 // 8 * 8
                        if key_bits < 1024:
                            result.add_finding(Finding(
                                title=f"DKIM Key Too Short: {key_bits} bits (selector: {selector})",
                                severity="high",
                                description=f"DKIM key for selector '{selector}' is only ~{key_bits} bits. Minimum recommended is 2048 bits.",
                                evidence=f"Selector: {selector}._domainkey.{domain}",
                                remediation="Rotate DKIM key to 2048-bit RSA minimum.",
                                tags=["email", "dkim", "weak-key"],
                            ))
            except Exception:
                continue

        result.data["dkim_selectors"] = found_selectors

        if not found_selectors:
            result.add_finding(Finding(
                title="No DKIM Records Found",
                severity="medium",
                description=f"No DKIM TXT records found for common selectors on {domain}.",
                remediation="Configure DKIM signing on your mail server and publish the public key in DNS.",
                tags=["email", "dkim"],
            ))

    # ── MTA-STS ─────────────────────────────────────────────────────────────

    def _check_mta_sts(self, domain: str, result: ScanResult) -> None:
        self.log.info("  Checking MTA-STS...")
        records = self._get_txt(f"_mta-sts.{domain}")
        sts_records = [r for r in records if "v=STSv1" in r]

        if not sts_records:
            result.add_finding(Finding(
                title="Missing MTA-STS Record",
                severity="low",
                description="MTA-STS not configured — email delivery cannot enforce TLS encryption in transit.",
                remediation=f"Add _mta-sts.{domain} TXT: v=STSv1; id=<timestamp> and serve /.well-known/mta-sts.txt",
                tags=["email", "mta-sts", "tls"],
            ))
        else:
            self.log.info(f"    [green]MTA-STS found[/]: {sts_records[0]}")
            result.data["mta_sts"] = sts_records[0]

    # ── BIMI ────────────────────────────────────────────────────────────────

    def _check_bimi(self, domain: str, result: ScanResult) -> None:
        self.log.info("  Checking BIMI...")
        records = self._get_txt(f"default._bimi.{domain}")
        bimi_records = [r for r in records if "v=BIMI1" in r]

        if bimi_records:
            self.log.info(f"    [green]BIMI found[/]: {bimi_records[0]}")
            result.data["bimi"] = bimi_records[0]
        else:
            result.add_finding(Finding(
                title="BIMI Not Configured (Optional)",
                severity="info",
                description="BIMI (Brand Indicators for Message Identification) not found — brand logo won't show in email clients.",
                remediation=f"After achieving p=reject DMARC, add BIMI at default._bimi.{domain}",
                tags=["email", "bimi"],
            ))

    # ── MX ──────────────────────────────────────────────────────────────────

    def _check_mx(self, domain: str, result: ScanResult) -> None:
        self.log.info("  Checking MX records...")
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=5)
            mx_records = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
            result.data["mx"] = mx_records
            self.log.info(f"    MX records: {mx_records}")

            if len(mx_records) == 1:
                result.add_finding(Finding(
                    title="Single MX Record — No Redundancy",
                    severity="low",
                    description="Only one MX record found. If this server goes down, email delivery will fail.",
                    evidence=f"MX: {mx_records}",
                    remediation="Add a secondary MX record with a higher preference number for redundancy.",
                    tags=["email", "mx", "availability"],
                ))
        except Exception as e:
            result.add_finding(Finding(
                title="No MX Records Found",
                severity="medium",
                description=f"{domain} has no MX records — cannot receive email.",
                tags=["email", "mx"],
            ))

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_txt(self, name: str) -> List[str]:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=5)
            return [b.decode() for r in answers for b in r.strings]
        except Exception:
            return []
