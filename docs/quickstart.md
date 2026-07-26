# Quick Start

## Your First Scan

After [installing RedScope](installation.md), run your first scan:

```bash
# DNS reconnaissance on a domain
python cli.py scan example.com --modules dns

# HTTP security headers on a web app
python cli.py scan https://example.com --modules headers
```

## List Available Modules

```bash
python cli.py list
```

Output:
```
┌─────────────────────────────────────────────────────────────────────┐
│ RedScope Modules                                                     │
├──────────────┬──────────┬────────────────────────────────────────── │
│ Name         │ Category │ Description                                │
├──────────────┼──────────┼────────────────────────────────────────── │
│ dns          │ recon    │ DNS records, zone transfer, SPF/DMARC      │
│ subdomain    │ recon    │ Subdomain enumeration via wordlist          │
│ portscan     │ recon    │ TCP port scanning with banner grabbing      │
│ headers      │ web      │ HTTP security header analysis               │
│ ...          │ ...      │ ...                                         │
└──────────────┴──────────┴────────────────────────────────────────── ┘
```

## Running Module Groups

=== "All Recon"

    ```bash
    python cli.py scan example.com --all-recon --save
    ```
    Runs: `dns`, `subdomain`, `portscan`, `takeover`, `emailsec`, `shodan`

=== "All Web"

    ```bash
    python cli.py scan https://example.com --all-web --save
    ```
    Runs: `headers`, `dirbrute`, `sqli`, `xss`, `cors`, `openredirect`, `ssrf`, `jwt`, `waf`, `lfi`, `cmdi`, `xxe`, `idor`

=== "Full Scan"

    ```bash
    python cli.py scan https://example.com --all --save --report html
    ```
    Runs all recon + all web modules and generates an HTML report.

## Saving Results

```bash
# Save JSON results
python cli.py scan example.com --modules dns portscan --save

# Generate HTML report
python cli.py scan https://example.com --all-web --report html

# Save JSON + generate HTML
python cli.py scan https://example.com --all-web --save --report html
```

Results are saved to `output/<target>/<timestamp>/`.

## Running Specific Modules

```bash
# Multiple modules in one run
python cli.py scan https://example.com --modules sqli xss cors jwt

# Recon + web combo
python cli.py scan https://example.com --modules dns headers portscan sqli
```

## Scan Options

```
Options:
  --modules TEXT    Comma-separated list of modules to run
  --all-recon       Run all recon modules
  --all-web         Run all web modules
  --all             Run every module
  --save            Save JSON results to output/
  --report TEXT     Generate report: html, markdown, json
  --threads INT     Number of threads (default: 10)
  --timeout INT     Request timeout in seconds (default: 10)
  --quiet           Suppress banner
  -h, --help        Show this help
```

## Next Steps

- [Configuration](configuration.md) — customize threads, timeout, wordlists
- [Modules](modules/index.md) — deep-dive into each module
- [Plugin Development](plugins.md) — write your own modules
- [Docker](docker.md) — run scans inside Docker
