import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from redscope.core.base_module import BaseModule
from redscope.core.logger import log

_BUILTIN_MODULES: Dict[str, str] = {
    # recon
    "subdomain": "redscope.modules.recon.subdomain",
    "portscan": "redscope.modules.recon.portscan",
    "dns": "redscope.modules.recon.dns",
    # web
    "sqli": "redscope.modules.web.sqli",
    "xss": "redscope.modules.web.xss",
    "dirbrute": "redscope.modules.web.dirbrute",
    "headers": "redscope.modules.web.headers",
    # network
    "banner": "redscope.modules.network.banner",
    "serviceenum": "redscope.modules.network.serviceenum",
    # report
    "htmlreport": "redscope.modules.report.html",
    "jsonreport": "redscope.modules.report.json_report",
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
