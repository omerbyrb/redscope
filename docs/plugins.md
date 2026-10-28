# Plugin Development

RedScope's plugin system lets you write custom modules in minutes. Drop a `.py` file in the `plugins/` directory and run it with `redscope plugin`.

## Plugin Template

```python
from redscope.core.base_module import BaseModule, Finding, ScanResult


class Module(BaseModule):
    name = "myplugin"
    description = "My custom security check"
    author = "Your Name"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)

        # Your scanning logic here
        if self._check_something(target):
            result.add_finding(
                Finding(
                    title="Vulnerability Found",
                    severity="high",          # critical, high, medium, low, info
                    description="Detailed description of the issue",
                    evidence="What you observed",
                    remediation="How to fix it",
                    cvss=7.5,                 # optional CVSS score
                    cve="CVE-2024-12345",     # optional CVE
                    tags=["web", "custom"],   # optional tags
                )
            )

        result.finish()
        return result

    def _check_something(self, target: str) -> bool:
        # implement your check
        return False
```

## Running a Plugin

```bash
redscope plugin plugins/myplugin.py https://target.com
```

## Finding Severities

| Severity | CVSS Range | Use For |
|----------|-----------|---------|
| `critical` | 9.0–10.0 | Remote code execution, full compromise |
| `high` | 7.0–8.9 | SQLi, XSS, auth bypass |
| `medium` | 4.0–6.9 | Information disclosure, CSRF |
| `low` | 0.1–3.9 | Minor misconfiguration |
| `info` | 0.0 | Informational findings, enumeration results |

## Accessing Config

```python
def run(self, target: str, **kwargs) -> ScanResult:
    timeout = self.config["general"]["timeout"]
    threads = self.config["general"]["threads"]
    user_agent = self.config["general"]["user_agent"]
```

## Making HTTP Requests

```python
import requests

def run(self, target: str, **kwargs) -> ScanResult:
    result = ScanResult(module=self.name, target=target)

    try:
        resp = requests.get(
            target,
            timeout=self.config["general"]["timeout"],
            headers={"User-Agent": self.config["general"]["user_agent"]},
            verify=False,
        )
        # analyze resp.text, resp.headers, resp.status_code
    except requests.RequestException as e:
        result.add_error(str(e))

    return result
```

## Logging

```python
self.log.info("Starting scan on [bold]{target}[/]")
self.log.warning("Suspicious response received")
self.log.error("Connection failed")
```

RedScope uses Rich markup in log messages — `[bold]`, `[red]`, `[green]`, etc.

## Example Plugin: Security.txt Checker

```python
import requests
from redscope.core.base_module import BaseModule, Finding, ScanResult


class Module(BaseModule):
    name = "securitytxt"
    description = "Check for security.txt (RFC 9116)"
    author = "Example"
    version = "1.0.0"

    PATHS = ["/.well-known/security.txt", "/security.txt"]

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        url = target if target.startswith("http") else f"https://{target}"
        timeout = self.config["general"]["timeout"]

        found = False
        for path in self.PATHS:
            try:
                resp = requests.get(f"{url}{path}", timeout=timeout, verify=False)
                if resp.status_code == 200 and "Contact:" in resp.text:
                    found = True
                    result.data["security_txt_url"] = f"{url}{path}"
                    self.log.info(f"  [green]security.txt found at {path}[/]")
                    break
            except requests.RequestException:
                pass

        if not found:
            result.add_finding(
                Finding(
                    title="security.txt Not Found",
                    severity="info",
                    description=(
                        "No security.txt file was found. "
                        "RFC 9116 recommends security researchers how to report vulnerabilities."
                    ),
                    remediation="Add /.well-known/security.txt with Contact: and Expires: fields",
                    tags=["info", "security-txt"],
                )
            )

        result.finish()
        return result
```

Run it:
```bash
redscope plugin plugins/securitytxt.py https://example.com
```
