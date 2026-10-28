# RedScope 🔴

```
██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║███████╗██║     ██║   ██║██████╔╝█████╗  
██╔══██╗██╔══╝  ██║  ██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
██║  ██║███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

**Modular Penetration Testing Framework**

[![CI](https://github.com/omerbyrb/redscope/actions/workflows/ci.yml/badge.svg)](https://github.com/omerbyrb/redscope/actions/workflows/ci.yml)
[![Docs](https://github.com/omerbyrb/redscope/actions/workflows/docs.yml/badge.svg)](https://omerbyrb.github.io/redscope)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security](https://img.shields.io/badge/security-pip--audit-orange)](https://github.com/pypa/pip-audit)

> ⚠️ **Legal Notice:** Only use RedScope on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal.

---

**RedScope** is an open-source, modular penetration testing framework that automates reconnaissance, vulnerability scanning, and reporting — all from a single CLI.

📖 **[Full Documentation →](https://omerbyrb.github.io/redscope)**

---

## Features

- **24 built-in modules** — recon, web, and network categories
- **Modular plugin system** — drop a `.py` file in `/plugins` and run it instantly
- **Rich CLI output** — color-coded findings ranked by severity
- **Multi-threaded** — fast scanning with configurable thread pools
- **3 report formats** — self-contained HTML (dark theme), JSON, Markdown
- **Web dashboard** — Flask-based UI with real-time scan monitoring
- **Docker ready** — single image with nmap, dnsutils, netcat included
- **CI/CD** — GitHub Actions with lint, test matrix, Docker build, security audit

## Installation

```bash
git clone https://github.com/omerbyrb/redscope
cd redscope
pip install -e .
```

### Docker

```bash
docker build -t redscope .
docker run --rm redscope --version
```

## Quick Start

```bash
# List all modules
redscope list

# DNS recon
redscope scan example.com --modules dns

# HTTP security headers
redscope scan https://example.com --modules headers

# Full recon sweep
redscope scan example.com --all-recon --save

# Full web assessment with HTML report
redscope scan https://example.com --all-web --report html

# Everything
redscope scan https://example.com --all --save --report html
```

## Modules

### Recon

| Module | Description |
|--------|-------------|
| `dns` | DNS records, zone transfer, dangling CNAMEs, SPF/DMARC |
| `subdomain` | Wordlist subdomain enumeration with wildcard detection |
| `portscan` | TCP port scan with banner grabbing (40+ ports) |
| `takeover` | Subdomain takeover detection (29 cloud services) |
| `emailsec` | SPF, DMARC, DKIM (24 selectors), MTA-STS, BIMI |
| `shodan` | Shodan / InternetDB intelligence — open ports, CVEs, tags |

### Web

| Module | Description |
|--------|-------------|
| `headers` | HTTP security header analysis (6 headers + info leakage) |
| `dirbrute` | Directory/file brute force (100+ paths, multi-threaded) |
| `sqli` | SQL injection — error-based + time-based blind |
| `xss` | Reflected XSS with CSP audit |
| `cors` | CORS misconfiguration — wildcard, origin reflection, null origin |
| `openredirect` | Open redirect (28 params, 12 bypass payloads) |
| `ssrf` | SSRF — AWS/GCP/Azure metadata + bypass payloads |
| `jwt` | JWT analysis — weak secrets, alg:none, expiry, sensitive claims |
| `waf` | WAF fingerprinting (14 WAFs) |
| `lfi` | Local/Remote File Inclusion (28 LFI + 4 RFI payloads) |
| `cmdi` | Command injection — output-based + time-based (Unix + Windows) |
| `xxe` | XXE injection (8 payloads, 5 content types) |
| `idor` | IDOR — numeric ID, param injection, path IDOR, sequential |

### Network

| Module | Description |
|--------|-------------|
| `ssltls` | Certificate expiry/validity, weak protocols, weak ciphers, HSTS |
| `banner` | Service banner grabbing + version detection (25 ports) |
| `cvelookup` | CVE lookup — NVD API + 35-entry local knowledge base |
| `serviceenum` | Service enum — FTP anon, SSH algos, SMTP relay, Redis/Mongo no-auth |
| `osfingerprint` | OS detection via TTL, banners, HTTP headers (18 OS signatures) |

## Writing a Plugin

```python
from redscope.core.base_module import BaseModule, Finding, ScanResult

class Module(BaseModule):
    name = "myplugin"
    description = "My custom check"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        result.add_finding(Finding(
            title="Example Finding",
            severity="high",
            description="Something bad was found",
            remediation="How to fix it",
        ))
        return result
```

```bash
redscope plugin plugins/myplugin.py https://target.com
```

## Web Dashboard

```bash
redscope dashboard
# Open http://localhost:5000
```

## Docker

```bash
# Run scan inside Docker
docker run --rm -v $(pwd)/output:/app/output \
  redscope scan https://example.com --all-web --report html

# Launch dashboard
docker run --rm -p 5000:5000 redscope dashboard --host 0.0.0.0

# docker-compose (dashboard profile)
docker compose --profile dashboard up -d
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov

# Lint
black . && isort . && flake8 .

# Build docs locally
mkdocs serve
```

## License

MIT — see [LICENSE](LICENSE)
