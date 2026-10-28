# RedScope

<div align="center">

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
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/omerbyrb/redscope/blob/main/LICENSE)

</div>

---

!!! warning "Legal Notice"
    RedScope is built for **authorized security testing only**. Only use it on systems you own or have explicit written permission to test. Unauthorized scanning is illegal and unethical.

## What is RedScope?

RedScope is an open-source, modular penetration testing framework that automates reconnaissance, vulnerability scanning, and report generation — all from a single CLI.

It is built to be:

- **Extensible** — drop a Python file into `/plugins` and run it instantly
- **Fast** — multi-threaded scanning with configurable thread pools
- **Readable** — color-coded findings ranked by severity
- **Portable** — runs locally or inside Docker with zero config

## Feature Highlights

| Category | Modules |
|----------|---------|
| Recon | DNS records, subdomain enum, port scan, email security (SPF/DMARC/DKIM), Shodan, subdomain takeover |
| Web | HTTP headers, dir brute force, SQLi, XSS, CORS, open redirect, SSRF, JWT, WAF, LFI/RFI, command injection, XXE, IDOR |
| Network | SSL/TLS analysis, banner grabbing, CVE lookup, service enumeration, OS fingerprinting |
| Reporting | HTML (dark theme, self-contained), JSON, Markdown |

## Quick Example

```bash
# Clone and install
git clone https://github.com/omerbyrb/redscope
cd redscope && pip install -e .

# Full recon on a target
redscope scan example.com --all-recon --save --report html

# Web vulnerability assessment
redscope scan https://example.com --all-web --save --report html
```

## Getting Started

<div class="grid cards" markdown>

- :material-download: **[Installation](installation.md)** — Get RedScope running in minutes
- :material-rocket-launch: **[Quick Start](quickstart.md)** — Your first scan in 60 seconds
- :material-puzzle: **[Plugin Dev](plugins.md)** — Build custom modules
- :material-docker: **[Docker](docker.md)** — Run containerized scans

</div>
