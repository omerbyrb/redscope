import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from core.base_module import BaseModule
from core.logger import log

_BUILTIN_MODULES: Dict[str, str] = {
    # recon
    "subdomain": "modules.recon.subdomain",
    "portscan": "modules.recon.portscan",
    "dns": "modules.recon.dns",
    # web
    "sqli": "modules.web.sqli",
    "xss": "modules.web.xss",
    "dirbrute": "modules.web.dirbrute",
    "headers": "modules.web.headers",
    # network
    "banner": "modules.network.banner",
    "serviceenum": "modules.network.serviceenum",
    # report
    "htmlreport": "modules.report.html",
    "jsonreport": "modules.report.json_report",
}


def list_modules() -> List[str]:
    return list(_BUILTIN_MODULES.keys())


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
