# RedScope 🔴

> Modular Penetration Testing Framework — built for security professionals

```
██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║███████╗██║     ██║   ██║██████╔╝█████╗  
██╔══██╗██╔══╝  ██║  ██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
██║  ██║███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

**RedScope** is an open-source, modular penetration testing framework designed to automate reconnaissance, vulnerability scanning, and reporting — all from a single CLI.

> ⚠️ **Legal Notice:** Only use RedScope on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal.

---

## Features

- **Modular architecture** — plug in your own modules with a single Python class
- **Rich CLI output** — color-coded findings by severity
- **Multi-threaded** — fast scanning with configurable thread pools
- **Plugin system** — drop a `.py` file in `/plugins` and run it instantly
- **Structured output** — JSON, HTML, and Markdown reports

## Installation

### Local
```bash
git clone https://github.com/omerbyrb/redscope
cd redscope
pip install -r requirements.txt
```

### Docker
```bash
# Build
docker build -t redscope .

# Run a scan
docker run --rm -v $(pwd)/output:/app/output redscope scan example.com --modules dns headers --report html

# Launch web dashboard
docker run --rm -p 5000:5000 -v $(pwd)/output:/app/output redscope dashboard --host 0.0.0.0

# Using docker-compose (dashboard)
docker compose --profile dashboard up -d
```

## Quick Start

```bash
# List all modules
python cli.py list

# DNS reconnaissance
python cli.py scan example.com --modules dns

# HTTP security header analysis
python cli.py scan https://example.com --modules headers

# Full recon sweep
python cli.py scan example.com --all-recon --save

# Full web assessment
python cli.py scan https://example.com --all-web --save
```

## Modules

| Module | Category | Description |
|--------|----------|-------------|
| `dns` | Recon | DNS records, zone transfer, SPF/DMARC |
| `subdomain` | Recon | Subdomain enumeration via wordlist + APIs |
| `portscan` | Recon | TCP/UDP port scanning with service detection |
| `headers` | Web | HTTP security header analysis |
| `dirbrute` | Web | Directory & file brute forcing |
| `sqli` | Web | SQL injection detection |
| `xss` | Web | Cross-site scripting detection |
| `banner` | Network | Service banner grabbing |

## Writing a Plugin

```python
from core.base_module import BaseModule, ScanResult, Finding

class Module(BaseModule):
    name = "myplugin"
    description = "My custom check"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        # your logic here
        result.add_finding(Finding(
            title="Example Finding",
            severity="high",
            description="Something bad was found",
        ))
        return result
```

Then run it:
```bash
python cli.py plugin plugins/myplugin.py https://target.com
```

## Roadmap

- [ ] Subdomain enumeration (Day 2)
- [ ] Port scanner (Day 3)
- [ ] Directory brute force (Day 4)
- [ ] SQL injection scanner (Day 5)
- [ ] XSS scanner (Day 6)
- [ ] HTML report generation (Day 7)
- [ ] Network banner grabber (Day 8)
- [ ] Service enumeration (Day 9)
- [ ] Shodan integration (Day 10)
- [ ] CVE lookup (Day 11)
- [ ] JWT analyzer (Day 12)
- [ ] CORS misconfiguration checker (Day 13)
- [ ] Open redirect scanner (Day 14)
- [ ] SSRF detector (Day 15)

## License

MIT — see [LICENSE](LICENSE)
