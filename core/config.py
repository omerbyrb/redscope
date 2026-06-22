import os
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


DEFAULT_CONFIG = {
    "general": {
        "output_dir": "output",
        "log_level": "INFO",
        "threads": 10,
        "timeout": 10,
        "user_agent": "RedScope/1.0 (Security Research)",
    },
    "recon": {
        "dns_resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
        "subdomain_wordlist": "wordlists/subdomains.txt",
        "port_scan_top": 1000,
    },
    "web": {
        "follow_redirects": True,
        "max_depth": 3,
        "exclude_extensions": [".jpg", ".png", ".gif", ".css", ".ico", ".woff"],
        "sqli_payloads": "wordlists/sqli.txt",
        "xss_payloads": "wordlists/xss.txt",
    },
    "network": {
        "banner_grab_timeout": 5,
    },
    "report": {
        "format": "html",
        "include_evidence": True,
    },
}

CONFIG_PATH = Path.home() / ".redscope" / "config.json"


def load_config(path: Optional[Path] = None) -> dict:
    config_file = path or CONFIG_PATH
    if config_file.exists():
        with open(config_file) as f:
            user_config = json.load(f)
        return _deep_merge(DEFAULT_CONFIG, user_config)
    return DEFAULT_CONFIG.copy()


def save_config(config: dict, path: Optional[Path] = None) -> None:
    config_file = path or CONFIG_PATH
    config_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)


def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
