# Modules Overview

RedScope is organized into three module categories. Each module is self-contained, testable, and can be run independently or combined in a single scan.

## Recon Modules

Gather information about a target before active testing.

| Module | Command | Description |
|--------|---------|-------------|
| [dns](recon/dns.md) | `--modules dns` | DNS records, zone transfer attempts, dangling CNAMEs |
| [subdomain](recon/subdomain.md) | `--modules subdomain` | Wordlist-based subdomain enumeration with wildcard detection |
| [portscan](recon/portscan.md) | `--modules portscan` | TCP port scan with banner grabbing and service detection |
| [takeover](recon/takeover.md) | `--modules takeover` | Subdomain takeover detection (29 cloud services) |
| [emailsec](recon/emailsec.md) | `--modules emailsec` | SPF, DMARC, DKIM, MTA-STS, BIMI analysis |
| [shodan](recon/shodan.md) | `--modules shodan` | Shodan/InternetDB intelligence — open ports, CVEs, tags |

Run all recon modules:
```bash
redscope scan example.com --all-recon
```

## Web Modules

Test web applications for common vulnerabilities.

| Module | Command | Description |
|--------|---------|-------------|
| [headers](web/headers.md) | `--modules headers` | HTTP security header analysis |
| [dirbrute](web/dirbrute.md) | `--modules dirbrute` | Directory and file brute force |
| [sqli](web/sqli.md) | `--modules sqli` | SQL injection detection (error-based + time-based) |
| [xss](web/xss.md) | `--modules xss` | Reflected XSS detection |
| [cors](web/cors.md) | `--modules cors` | CORS misconfiguration — wildcard, origin reflection, null origin |
| [openredirect](web/openredirect.md) | `--modules openredirect` | Open redirect detection in 28 common parameters |
| [ssrf](web/ssrf.md) | `--modules ssrf` | Server-Side Request Forgery |
| [jwt](web/jwt.md) | `--modules jwt` | JWT analysis — weak secrets, alg:none, expiry |
| [waf](web/waf.md) | `--modules waf` | WAF fingerprinting (14 WAFs) |
| [lfi](web/lfi.md) | `--modules lfi` | Local/Remote File Inclusion |
| [cmdi](web/cmdi.md) | `--modules cmdi` | Command injection |
| [xxe](web/xxe.md) | `--modules xxe` | XML External Entity injection |
| [idor](web/idor.md) | `--modules idor` | Insecure Direct Object Reference |

Run all web modules:
```bash
redscope scan https://example.com --all-web
```

## Network Modules

Deep inspection of network services and infrastructure.

| Module | Command | Description |
|--------|---------|-------------|
| [ssltls](network/ssltls.md) | `--modules ssltls` | Certificate validity, weak protocols/ciphers, HSTS |
| [banner](network/banner.md) | `--modules banner` | Service banner grabbing and version detection |
| [cvelookup](network/cvelookup.md) | `--modules cvelookup` | CVE lookup via NVD API + local knowledge base |
| [serviceenum](network/serviceenum.md) | `--modules serviceenum` | Deep service enumeration (FTP, SSH, SMTP, Redis, etc.) |
| [osfingerprint](network/osfingerprint.md) | `--modules osfingerprint` | OS detection via TTL, banners, and HTTP headers |

## Running Everything

```bash
redscope scan https://example.com --all --save --report html
```

This runs all 24 modules and produces a self-contained HTML report in `output/`.
