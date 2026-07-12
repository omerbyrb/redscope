import socket
from typing import List, Optional, Dict, Tuple

import dns.resolver
import requests

from core.base_module import BaseModule, ScanResult, Finding

# (service_name, cname_pattern, fingerprint_in_body, severity)
TAKEOVER_SIGNATURES: List[Tuple[str, str, str, str]] = [
    ("GitHub Pages",      "github.io",              "There isn't a GitHub Pages site here",      "high"),
    ("Heroku",            "herokuapp.com",           "No such app",                               "high"),
    ("Heroku",            "herokudns.com",           "No such app",                               "high"),
    ("AWS S3",            "s3.amazonaws.com",        "NoSuchBucket",                              "high"),
    ("AWS S3",            "s3-website",              "NoSuchBucket",                              "high"),
    ("AWS CloudFront",    "cloudfront.net",          "Bad request",                               "medium"),
    ("Fastly",            "fastly.net",              "Fastly error: unknown domain",              "high"),
    ("Pantheon",          "pantheonsite.io",         "The gods are wise",                         "high"),
    ("Shopify",           "myshopify.com",           "Sorry, this shop is currently unavailable", "high"),
    ("Tumblr",            "tumblr.com",              "There's nothing here",                      "medium"),
    ("WP Engine",         "wpengine.com",            "The site you were looking for",             "medium"),
    ("Ghost",             "ghost.io",                "The thing you were looking for",            "medium"),
    ("Surge.sh",          "surge.sh",                "project not found",                         "high"),
    ("Azure",             "azurewebsites.net",       "404 Web Site not found",                    "high"),
    ("Azure",             "cloudapp.net",            "404 Web Site not found",                    "high"),
    ("Azure Traffic Mgr", "trafficmanager.net",      "404 Web Site not found",                    "high"),
    ("Bitbucket",         "bitbucket.io",            "Repository not found",                      "high"),
    ("Zendesk",           "zendesk.com",             "Help Center Closed",                        "medium"),
    ("UserVoice",         "uservoice.com",           "This UserVoice subdomain is currently available", "high"),
    ("Desk.com",          "desk.com",                "Sorry, We Couldn't Find That Page",         "medium"),
    ("Cargo",             "cargocollective.com",     "404 Not Found",                             "medium"),
    ("Squarespace",       "squarespace.com",         "No Such Account",                           "medium"),
    ("Webflow",           "webflow.io",              "The page you are looking for doesn't exist","medium"),
    ("Netlify",           "netlify.app",             "Not found",                                 "high"),
    ("DigitalOcean",      "digitalocean.com",        "domain uses DO Spaces",                     "medium"),
    ("Acquia",            "acquia-sites.com",        "If you are an Acquia Cloud customer",       "medium"),
    ("HubSpot",           "hs-sites.com",            "does not exist in our system",              "medium"),
    ("Intercom",          "intercom.help",           "This page is reserved for artistic content","medium"),
    ("Readme.io",         "readme.io",               "Project doesnt exist",                      "medium"),
    ("Strikingly",        "strikingly.com",          "page not found",                            "medium"),
]


class Module(BaseModule):
    name = "takeover"
    description = "Subdomain takeover detector — dangling CNAMEs and unclaimed cloud services"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        subdomains: List[str] = kwargs.get("subdomains", [])

        if not subdomains:
            self.log.info(f"No subdomains provided — enumerating from DNS for [bold]{domain}[/]")
            subdomains = self._enumerate_subdomains(domain)

        if not subdomains:
            self.log.warning("No subdomains to test — run subdomain module first")
            result.add_error("No subdomains available. Chain with: --modules subdomain takeover")
            return result

        self.log.info(f"Testing [bold]{len(subdomains)}[/] subdomains for takeover")

        for subdomain in subdomains:
            finding = self._check_subdomain(subdomain)
            if finding:
                result.add_finding(finding)

        if not result.findings:
            self.log.info("[dim]No subdomain takeover vulnerabilities found[/]")
        else:
            self.log.info(f"[bold red]{len(result.findings)} takeover vulnerability(ies) found[/]")

        return result

    def _check_subdomain(self, subdomain: str) -> Optional[Finding]:
        # Step 1: Get CNAME chain
        cname = self._resolve_cname(subdomain)
        if not cname:
            return None

        self.log.info(f"  [cyan]{subdomain}[/] → CNAME → {cname}")

        # Step 2: Check if CNAME target resolves
        resolves = self._resolves(cname)

        # Step 3: Match against known takeover signatures
        for service, pattern, fingerprint, severity in TAKEOVER_SIGNATURES:
            if pattern.lower() in cname.lower():
                if not resolves:
                    self.log.info(f"  [bold red]TAKEOVER[/] {subdomain} → {cname} ({service}) — CNAME does not resolve!")
                    return Finding(
                        title=f"Subdomain Takeover — {subdomain} ({service})",
                        severity="critical",
                        description=(
                            f"'{subdomain}' has a CNAME pointing to '{cname}' ({service}), "
                            f"but the target does not resolve. "
                            f"An attacker can register this {service} resource and serve content "
                            f"under the legitimate subdomain."
                        ),
                        evidence=(
                            f"Subdomain: {subdomain}\n"
                            f"CNAME target: {cname}\n"
                            f"Service: {service}\n"
                            f"CNAME resolves: No"
                        ),
                        remediation=(
                            f"Remove the dangling CNAME record for '{subdomain}' immediately. "
                            f"If the {service} resource is still needed, re-provision it first, then update DNS."
                        ),
                        tags=["subdomain-takeover", "cname", "dns", service.lower().replace(" ", "-")],
                    )

                # CNAME resolves — check for fingerprint in body
                body_finding = self._check_body_fingerprint(subdomain, cname, service, fingerprint, severity)
                if body_finding:
                    return body_finding

        return None

    def _check_body_fingerprint(self, subdomain, cname, service, fingerprint, severity) -> Optional[Finding]:
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{subdomain}",
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "RedScope/1.0"},
                )
                if fingerprint.lower() in resp.text.lower():
                    self.log.info(
                        f"  [bold red]TAKEOVER FINGERPRINT[/] {subdomain} → {service} — "
                        f"'{fingerprint[:40]}' found in body"
                    )
                    return Finding(
                        title=f"Subdomain Takeover (Unclaimed Service) — {subdomain}",
                        severity=severity,
                        description=(
                            f"'{subdomain}' points to {service} via CNAME '{cname}', "
                            f"and the response contains the unclaimed service fingerprint. "
                            f"An attacker may be able to claim this resource."
                        ),
                        evidence=(
                            f"Subdomain: {subdomain}\n"
                            f"CNAME: {cname}\n"
                            f"Service: {service}\n"
                            f"Fingerprint: '{fingerprint}'\n"
                            f"HTTP Status: {resp.status_code}"
                        ),
                        remediation=(
                            f"Claim the {service} resource associated with '{cname}', "
                            f"or remove the CNAME DNS record if the service is no longer needed."
                        ),
                        tags=["subdomain-takeover", "unclaimed", service.lower().replace(" ", "-")],
                    )
            except requests.RequestException:
                continue
        return None

    def _resolve_cname(self, subdomain: str) -> Optional[str]:
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=5)
            return str(answers[0].target).rstrip(".")
        except Exception:
            return None

    def _resolves(self, hostname: str) -> bool:
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False

    def _enumerate_subdomains(self, domain: str) -> List[str]:
        from modules.recon.subdomain import BUILTIN_WORDLIST
        import concurrent.futures

        found = []
        def check(word):
            sub = f"{word}.{domain}"
            try:
                dns.resolver.resolve(sub, "A", lifetime=2)
                return sub
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for result in ex.map(check, BUILTIN_WORDLIST):
                if result:
                    found.append(result)
        return found
