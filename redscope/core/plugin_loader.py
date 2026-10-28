import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from redscope.core.base_module import BaseModule
from redscope.core.logger import log

_BUILTIN_MODULES: Dict[str, str] = {
    # recon
    "dns": "redscope.modules.recon.dns",
    "subdomain": "redscope.modules.recon.subdomain",
    "portscan": "redscope.modules.recon.portscan",
    "emailsec": "redscope.modules.recon.emailsec",
    "takeover": "redscope.modules.recon.takeover",
    "shodan": "redscope.modules.recon.shodan",
    # web
    "headers": "redscope.modules.web.headers",
    "dirbrute": "redscope.modules.web.dirbrute",
    "sqli": "redscope.modules.web.sqli",
    "xss": "redscope.modules.web.xss",
    "cors": "redscope.modules.web.cors",
    "openredirect": "redscope.modules.web.openredirect",
    "ssrf": "redscope.modules.web.ssrf",
    "jwt": "redscope.modules.web.jwt",
    "lfi": "redscope.modules.web.lfi",
    "cmdi": "redscope.modules.web.cmdi",
    "xxe": "redscope.modules.web.xxe",
    "idor": "redscope.modules.web.idor",
    "waf": "redscope.modules.web.waf",
    # network
    "ssltls": "redscope.modules.network.ssltls",
    "banner": "redscope.modules.network.banner",
    "cvelookup": "redscope.modules.network.cvelookup",
    "serviceenum": "redscope.modules.network.serviceenum",
    "osfingerprint": "redscope.modules.network.osfingerprint",
    # report
    "htmlreport": "redscope.modules.report.html",
    "jsonreport": "redscope.modules.report.json_report",
}


def list_modules() -> List[str]:
    return list(_BUILTIN_MODULES.keys())


def module_category(name: str) -> str:
    """Category of a built-in module, taken from its package path (recon, web, network, report)."""
    return _BUILTIN_MODULES[name].split(".")[2]


def load_module(name: str, config: dict) -> Optional[BaseModule]:
    module_path = _BUILTIN_MODULES.get(name)
    if not module_path:
        log.error(f"Unknown module: [bold red]{name}[/]")
        return None
    try:
        mod = importlib.import_module(module_path)
        cls: Type[BaseModule] = getattr(mod, "Module")
        return cls(config)
    except (ImportError, AttributeError) as e:
        log.warning(f"Module [yellow]{name}[/] not yet implemented: {e}")
        return None


def load_plugin(plugin_path: Path, config: dict) -> Optional[BaseModule]:
    spec = importlib.util.spec_from_file_location("plugin", plugin_path)
    if not spec or not spec.loader:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["plugin"] = mod
    spec.loader.exec_module(mod)
    cls: Type[BaseModule] = getattr(mod, "Module", None)
    if not cls:
        log.error(f"Plugin {plugin_path} has no 'Module' class")
        return None
    return cls(config)
