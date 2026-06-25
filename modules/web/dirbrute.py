import concurrent.futures
from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin

import requests

from core.base_module import BaseModule, ScanResult, Finding

BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel", "cpanel",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    "phpmyadmin", "pma", "mysql", "adminer",
    "backup", "backups", "bak", "old", "archive", "archives",
    "config", "configuration", "settings", "setup", "install",
    "api", "api/v1", "api/v2", "api/v3", "graphql", "swagger",
    "swagger-ui", "swagger-ui.html", "api-docs", "openapi.json",
    ".env", ".git", ".git/HEAD", ".git/config", ".svn",
    ".htaccess", ".htpasswd", "web.config", "robots.txt", "sitemap.xml",
    "server-status", "server-info",
    "test", "testing", "dev", "development", "staging", "beta",
    "debug", "trace", "info", "status", "health", "healthz", "ping",
    "metrics", "actuator", "actuator/health", "actuator/env",
    "actuator/mappings", "actuator/beans",
    "console", "shell", "terminal", "cmd",
    "upload", "uploads", "files", "file", "media", "images", "static",
    "assets", "resources", "public", "private",
    "logs", "log", "error.log", "access.log", "debug.log",
    "tmp", "temp", "cache",
    "user", "users", "account", "accounts", "profile", "profiles",
    "register", "signup", "logout", "auth", "oauth", "sso",
    "forgot", "reset", "password",
    "search", "query",
    "download", "export", "import", "report", "reports",
    "invoice", "billing", "payment",
    "db", "database", "sql", "dump", "backup.sql", "backup.zip",
    "data.json", "users.json", "credentials.json",
    "readme", "README", "README.md", "CHANGELOG", "LICENSE",
    "Makefile", "Dockerfile", "docker-compose.yml",
    "package.json", "composer.json", "requirements.txt",
    ".DS_Store", "thumbs.db",
]

SENSITIVE_PATHS = {
    ".env", ".git", ".git/HEAD", ".git/config", ".svn",
    ".htpasswd", "web.config", "backup", "backups",
    "config", "configuration", "phpmyadmin", "adminer",
    "console", "shell", "terminal", "actuator", "actuator/env",
    "credentials.json", "backup.sql", "backup.zip", "dump",
    "server-status", "server-info", "debug", "trace",
}

STATUS_INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403}


class Module(BaseModule):
    name = "dirbrute"
    description = "Directory and file brute force scanner"
    author = "RedScope"
    version = "1.0.0"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)

        base_url = target if target.startswith("http") else f"https://{target}"
        base_url = base_url.rstrip("/")

        wordlist = self._load_wordlist()
        threads = self.config["general"]["threads"]
        timeout = self.config["general"]["timeout"]

        self.log.info(f"Directory brute force on [bold]{base_url}[/] — {len(wordlist)} paths, {threads} threads")

        session = requests.Session()
        session.headers["User-Agent"] = self.config["general"]["user_agent"]

        found: List[dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._probe, session, base_url, path, timeout): path
                for path in wordlist
            }
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    found.append(res)
                    color = "green" if res["status"] == 200 else "yellow"
                    self.log.info(f"  [{color}]{res['status']}[/]  {res['url']}  ({res['size']} bytes)")

        found.sort(key=lambda x: (x["status"], x["path"]))
        result.data["found"] = found
        result.data["count"] = len(found)

        if found:
            result.add_finding(Finding(
                title=f"{len(found)} Paths Discovered",
                severity="info",
                description="\n".join(f"[{f['status']}] {f['url']}" for f in found),
                tags=["web", "dirbrute"],
            ))

        for item in found:
            path = item["path"].lstrip("/")
            status = item["status"]

            if path in SENSITIVE_PATHS:
                severity = "critical" if path in {".env", ".git/config", "credentials.json", "backup.sql"} else "high"
                result.add_finding(Finding(
                    title=f"Sensitive File/Directory Exposed: /{path}",
                    severity=severity,
                    description=f"/{path} is accessible (HTTP {status}) — may expose credentials or source code",
                    evidence=f"URL: {item['url']} — Status: {status} — Size: {item['size']} bytes",
                    remediation=f"Restrict access to /{path} via server configuration or remove it from the web root.",
                    tags=["web", "exposure", "sensitive"],
                ))

            elif status == 401:
                result.add_finding(Finding(
                    title=f"Password-Protected Area: /{path}",
                    severity="low",
                    description=f"/{path} requires authentication (HTTP 401) — worth investigating",
                    evidence=f"URL: {item['url']}",
                    tags=["web", "auth"],
                ))

            elif status == 403:
                result.add_finding(Finding(
                    title=f"Forbidden Path (Access Denied): /{path}",
                    severity="info",
                    description=f"/{path} exists but returns 403 — may be bypassable",
                    evidence=f"URL: {item['url']}",
                    tags=["web", "403bypass"],
                ))

        self.log.info(f"Dir brute complete — [bold green]{len(found)} paths found[/]")
        return result

    def _probe(self, session: requests.Session, base_url: str, path: str, timeout: int) -> Optional[dict]:
        url = f"{base_url}/{path.lstrip('/')}"
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False, verify=False)
            if resp.status_code in STATUS_INTERESTING:
                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "redirect": resp.headers.get("Location", ""),
                }
        except requests.RequestException:
            pass
        return None

    def _load_wordlist(self) -> List[str]:
        # Try to load from a custom file if it exists alongside the builtins
        custom = Path("wordlists/directories.txt")
        if custom.exists():
            with open(custom) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return BUILTIN_WORDLIST
