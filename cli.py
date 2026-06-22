#!/usr/bin/env python3
"""
RedScope — Modular Penetration Testing Framework
"""
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from core.engine import Engine
from core.config import load_config, save_config, CONFIG_PATH
from core.logger import log
from core.plugin_loader import list_modules

console = Console()

BANNER = """
██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║███████╗██║     ██║   ██║██████╔╝█████╗
██╔══██╗██╔══╝  ██║  ██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
██║  ██║███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
"""


def print_banner():
    console.print(Text(BANNER, style="bold red"))
    console.print(
        Panel(
            "[bold cyan]Modular Penetration Testing Framework[/]\n"
            "[dim]Use responsibly. Only test systems you are authorized to test.[/]",
            border_style="red",
            expand=False,
        )
    )


@click.group()
@click.version_option("1.0.0", prog_name="RedScope")
@click.option("--config", "-c", type=click.Path(), default=None, help="Path to config file")
@click.option("--output", "-o", default="output", help="Output directory")
@click.option("--threads", "-t", type=int, default=None, help="Number of threads")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner")
@click.pass_context
def cli(ctx, config, output, threads, quiet):
    ctx.ensure_object(dict)
    if not quiet:
        print_banner()

    cfg = load_config(Path(config) if config else None)
    if threads:
        cfg["general"]["threads"] = threads
    cfg["general"]["output_dir"] = output

    ctx.obj["config"] = cfg
    ctx.obj["engine"] = Engine()
    ctx.obj["engine"].config = cfg
    ctx.obj["output"] = output


@cli.command()
@click.argument("target")
@click.option("--modules", "-m", multiple=True, help="Modules to run (can specify multiple)")
@click.option("--all-recon", is_flag=True, help="Run all recon modules")
@click.option("--all-web", is_flag=True, help="Run all web modules")
@click.option("--save", "-s", is_flag=True, help="Save results to JSON")
@click.pass_context
def scan(ctx, target, modules, all_recon, all_web, save):
    """Run one or more modules against a target."""
    engine: Engine = ctx.obj["engine"]

    run_modules = list(modules)

    if all_recon:
        run_modules.extend(["dns", "subdomain", "portscan"])
    if all_web:
        run_modules.extend(["headers", "dirbrute", "sqli", "xss"])

    if not run_modules:
        log.error("No modules specified. Use --modules or --all-recon / --all-web")
        raise click.Abort()

    for mod in run_modules:
        engine.run_module(mod, target)

    if save:
        out = Path(ctx.obj["output"]) / f"scan_{target.replace('://', '_').replace('/', '_')}.json"
        engine.save_results(out)


@cli.command("list")
def list_cmd():
    """List all available modules."""
    from rich.table import Table
    from rich import box

    table = Table(title="Available Modules", box=box.ROUNDED)
    table.add_column("Name", style="bold cyan")
    table.add_column("Category")

    modules = {
        "dns": "recon", "subdomain": "recon", "portscan": "recon",
        "headers": "web", "dirbrute": "web", "sqli": "web", "xss": "web",
        "banner": "network", "serviceenum": "network",
        "htmlreport": "report", "jsonreport": "report",
    }
    for name, category in modules.items():
        color = {"recon": "green", "web": "yellow", "network": "cyan", "report": "blue"}.get(category, "white")
        table.add_row(name, f"[{color}]{category}[/]")

    console.print(table)


@cli.command()
@click.pass_context
def init(ctx):
    """Initialize RedScope config in ~/.redscope/config.json"""
    save_config(ctx.obj["config"])
    log.info(f"Config saved to [green]{CONFIG_PATH}[/]")


@cli.command()
@click.argument("plugin_path", type=click.Path(exists=True))
@click.argument("target")
@click.pass_context
def plugin(ctx, plugin_path, target):
    """Run a custom plugin against a target."""
    engine: Engine = ctx.obj["engine"]
    engine.run_plugin(Path(plugin_path), target)


if __name__ == "__main__":
    cli(obj={})
