# Configuration

RedScope loads its configuration from `~/.redscope/config.json`. If this file doesn't exist, built-in defaults are used.

## Initialize Config

```bash
python cli.py init
```

This creates `~/.redscope/config.json` with all default values.

## Default Configuration

```json
{
  "general": {
    "output_dir": "output",
    "log_level": "INFO",
    "threads": 10,
    "timeout": 10,
    "user_agent": "RedScope/1.0 (Security Research)"
  },
  "recon": {
    "dns_resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    "subdomain_wordlist": "wordlists/subdomains.txt",
    "port_scan_top": 1000
  },
  "web": {
    "follow_redirects": true,
    "max_depth": 3,
    "exclude_extensions": [".jpg", ".png", ".gif", ".css", ".ico", ".woff"]
  },
  "network": {
    "banner_grab_timeout": 5
  },
  "report": {
    "format": "html",
    "include_evidence": true
  }
}
```

## Per-Scan Overrides

You can override config values at runtime:

```bash
# Use more threads
python cli.py --threads 20 scan example.com --all-recon

# Longer timeout for slow targets
python cli.py --timeout 30 scan https://example.com --modules sqli

# Custom config file
python cli.py --config /path/to/myconfig.json scan example.com --all
```

## Custom Wordlists

RedScope ships with built-in wordlists for subdomain and directory brute forcing.
To use custom wordlists, set them in the config:

```json
{
  "recon": {
    "subdomain_wordlist": "/path/to/your/subdomains.txt"
  },
  "web": {
    "dirbrute_wordlist": "/path/to/your/dirs.txt"
  }
}
```

Built-in wordlists are in `wordlists/`:

- `wordlists/subdomains.txt` — 100+ common subdomains
- `wordlists/directories.txt` — 100+ common web paths

## Shodan API Key

To enable Shodan integration, add your API key to the config:

```json
{
  "shodan": {
    "api_key": "your-shodan-api-key"
  }
}
```

Or set it as an environment variable:

```bash
export SHODAN_API_KEY="your-shodan-api-key"
```

Without a key, the `shodan` module falls back to the free [InternetDB](https://internetdb.shodan.io/) API.

## Log Level

```json
{
  "general": {
    "log_level": "DEBUG"
  }
}
```

Available levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`
