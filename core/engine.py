import json
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.base_module import ScanResult
from core.config import load_config
from core.logger import log
from core.plugin_loader import load_module, load_plugin

console = Console()

SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class Engine:
    def __init__(self, config_path: Optional[Path] = None):
        self.config = load_config(config_path)
        self.results: List[ScanResult] = []

    def run_module(self, module_name: str, target: str, **kwargs) -> Optional[ScanResult]:
        module = load_module(module_name, self.config)
        if not module:
            return None

        log.info(f"Running [bold cyan]{module_name}[/] against [bold]{target}[/]")
        try:
            result = module.run(target, **kwargs)
            result.finish()
            self.results.append(result)
            self._print_result(result)
            return result
        except Exception as e:
            log.error(f"Module {module_name} crashed: {e}")
            return None

    def run_plugin(self, plugin_path: Path, target: str, **kwargs) -> Optional[ScanResult]:
        module = load_plugin(plugin_path, self.config)
        if not module:
            return None
        result = module.run(target, **kwargs)
        result.finish()
        self.results.append(result)
        self._print_result(result)
        return result

    def save_results(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = [r.to_dict() for r in self.results]
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        log.info(f"Results saved to [green]{output_path}[/]")

    def _print_result(self, result: ScanResult) -> None:
        if not result.findings:
            log.info(f"[dim]No findings for {result.module}[/]")
            return

        table = Table(
            title=f"[bold]{result.module}[/] — {result.target}",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Title", style="bold white")
        table.add_column("Description")

        for finding in result.findings:
            color = SEVERITY_COLOR.get(finding.severity, "white")
            table.add_row(
                f"[{color}]{finding.severity.upper()}[/]",
                finding.title,
                finding.description[:80] + ("…" if len(finding.description) > 80 else ""),
            )

        console.print(table)
