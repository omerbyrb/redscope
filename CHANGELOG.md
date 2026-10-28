# Changelog

All notable changes to RedScope are documented here.

## [Unreleased]

### Changed
- **Breaking:** all code now lives in the `redscope` package. Imports change from
  `core.*` / `modules.*` to `redscope.core.*` / `redscope.modules.*`; custom plugins must
  update their imports. Run the CLI with `redscope` or `python -m redscope`.
- Bundled wordlists ship inside the package and are resolved relative to it.

### Added
- Optional `check_id` on `Finding` (`<module>.<check>`, e.g. `ssltls.weak_protocol`): a
  stable identifier that does not change when a finding's title is reworded.
- `module_category()` helper in the plugin loader.

### Fixed
- `pip install` failed because `pyproject.toml` named a non-existent build backend.
- The module registry listed only 11 of 26 modules, so `ssltls`, `emailsec`, `cvelookup`
  and others failed with "Unknown module". `redscope list` now shows every module.

## [1.0.0] — 2026-08-04

### Added — Core Framework (Days 1–3)
- Modular architecture with `BaseModule` ABC, `Finding` and `ScanResult` dataclasses
- Click CLI with `scan`, `list`, `init`, `plugin`, `dashboard` commands
- Rich terminal output with color-coded severity levels
- JSON config system with deep merge and per-scan overrides
- DNS recon module — A/MX/NS/TXT/CNAME/SOA records, AXFR zone transfer, SPF/DMARC audit
- Subdomain enumeration — wordlist brute force, wildcard detection
- TCP port scanner — 40+ ports, banner grabbing, dangerous port detection

### Added — Web Modules (Days 4–9)
- Directory brute force — 100+ paths, multi-threaded, sensitive path detection
- SQL injection scanner — error-based (30+ signatures) + time-based blind
- XSS scanner — 20 payloads, canary-based detection, CSP audit
- HTTP security header analysis — 6 headers, information leakage detection
- CORS misconfiguration checker — wildcard, origin reflection, null origin, preflight
- Open redirect scanner — 28 parameters, 12 bypass payloads

### Added — Advanced Web (Days 10–16)
- SSRF detector — AWS/GCP/Azure metadata, 6 bypass payloads, heuristic timing
- JWT analyzer — weak secrets, alg:none (4 variants), HMAC brute force, expiry
- WAF fingerprinting — 14 WAFs (Cloudflare, ModSecurity, Imperva, etc.)
- LFI/RFI scanner — 28 LFI payloads, PHP wrappers, 4 RFI payloads
- Command injection — 21 payloads, output-based + time-based (Unix + Windows)
- XXE injection — 8 payloads, 5 content types, endpoint discovery
- IDOR detection — numeric ID, param injection, path IDOR, sequential, method override

### Added — Network & Recon (Days 17–23)
- SSL/TLS analysis — certificate expiry, weak protocols (TLSv1/1.1), weak ciphers, HSTS
- Service banner grabbing — 25 ports, 20 version patterns, EOL software detection
- CVE lookup — NVD API integration + 35-entry local knowledge base
- Service enumeration — FTP anon, SSH weak algos, SMTP relay/VRFY/EXPN, Redis/Mongo/Elasticsearch no-auth
- OS fingerprinting — TTL analysis, banner matching, HTTP headers (18 OS signatures)
- Shodan integration with InternetDB fallback — open ports, CVEs, honeypot detection
- Subdomain takeover detection — 29 cloud services (AWS S3, Heroku, GitHub Pages, etc.)
- Email security — SPF, DMARC, DKIM (24 selectors), MTA-STS, BIMI, MX redundancy

### Added — Reports & Dashboard (Days 24–26)
- HTML report — self-contained dark theme, collapsible findings, filter-by-severity
- JSON report — machine-readable with meta/summary/findings structure
- Markdown report — GitHub-flavored with emoji severity icons and CVE links
- Flask web dashboard — real-time scan monitoring, scan history, HTML report download

### Added — Infrastructure (Days 27–30)
- Docker support — `python:3.11-slim` with nmap/dnsutils/netcat, `docker-compose.yml`
- GitHub Actions CI — lint (black/isort/flake8), test matrix (3.10/3.11/3.12), Docker smoke test, pip-audit
- GitHub Actions Docker publish — GHCR on release with semver tags
- Test suite — 16 unit/integration tests for core modules
- MkDocs documentation — 37 pages, Material theme, GitHub Pages auto-deploy
- `pyproject.toml` — modern packaging with dev/docs extras

### Fixed
- `cors.py` syntax error (extra closing parenthesis)
- `lfi.py` invalid escape sequences (`\/`)
- `serviceenum.py` undefined `struct` reference
- `core/config.py` shallow copy bug — `DEFAULT_CONFIG` mutated between calls
- Docker smoke test — `load: true` missing from `build-push-action`
- Docker entrypoint — `--version`/`--help` flags not routed to CLI
- 20+ modules — unused imports cleaned (F401, F841, F541, E741)
