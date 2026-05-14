"""Typer command-line interface for CloudRift."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cloudrift.core.config import ScanConfig
from cloudrift.core.engine import CloudRiftEngine
from cloudrift.models.enums import CloudProvider
from cloudrift.output.json import report_to_json, write_json_report
from cloudrift.output.render import render_report

app = typer.Typer(
    name="cloudrift",
    help="Cloud storage exposure intelligence for authorized security assessments.",
    no_args_is_help=True,
)
console = Console()


def scan_command(
    target: Annotated[str, typer.Argument(help="Target domain, URL, or organization name.")],
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON instead of Rich TUI output.")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write JSON report to a file.")] = None,
    provider: Annotated[CloudProvider | None, typer.Option("--provider", help="Limit checks to one provider.")] = None,
    wordlist: Annotated[Path | None, typer.Option("--wordlist", help="Custom bucket keyword wordlist.")] = None,
    threads: Annotated[int, typer.Option("--threads", min=1, max=200, help="Concurrent validation workers.")] = 25,
    timeout: Annotated[float, typer.Option("--timeout", help="HTTP timeout in seconds.")] = 8.0,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP proxy URL.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose execution hints.")] = False,
    js_analysis: Annotated[bool, typer.Option("--js-analysis", help="Fetch frontend JS and extract storage references.")] = False,
    sourcemaps: Annotated[bool, typer.Option("--sourcemaps", help="Include source map URLs during JS analysis.")] = False,
    passive_only: Annotated[bool, typer.Option("--passive-only", help="Generate intelligence without validating endpoints.")] = False,
) -> None:
    """Run a CloudRift scan."""

    config = ScanConfig(
        provider=provider,
        wordlist=wordlist,
        concurrency=threads,
        timeout=timeout,
        proxy=proxy,
        verbose=verbose,
        js_analysis=js_analysis,
        sourcemaps=sourcemaps,
        passive_only=passive_only,
    )
    report = asyncio.run(_run_scan(target, config, json_output))
    if output:
        write_json_report(report, output)
        console.print(f"[green]Report written to[/] {output}")
    if json_output:
        console.print_json(report_to_json(report))
    else:
        render_report(console, report)


@app.command("scan", help="Cloud storage exposure intelligence scan.")
def scan_subcommand(
    target: Annotated[str, typer.Argument(help="Target domain, URL, or organization name.")],
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON instead of Rich TUI output.")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write JSON report to a file.")] = None,
    provider: Annotated[CloudProvider | None, typer.Option("--provider", help="Limit checks to one provider.")] = None,
    wordlist: Annotated[Path | None, typer.Option("--wordlist", help="Custom bucket keyword wordlist.")] = None,
    threads: Annotated[int, typer.Option("--threads", min=1, max=200, help="Concurrent validation workers.")] = 25,
    timeout: Annotated[float, typer.Option("--timeout", help="HTTP timeout in seconds.")] = 8.0,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP proxy URL.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose execution hints.")] = False,
    js_analysis: Annotated[bool, typer.Option("--js-analysis", help="Fetch frontend JS and extract storage references.")] = False,
    sourcemaps: Annotated[bool, typer.Option("--sourcemaps", help="Include source map URLs during JS analysis.")] = False,
    passive_only: Annotated[bool, typer.Option("--passive-only", help="Generate intelligence without validating endpoints.")] = False,
) -> None:
    """Run a CloudRift scan as a subcommand."""

    scan_command(
        target=target,
        json_output=json_output,
        output=output,
        provider=provider,
        wordlist=wordlist,
        threads=threads,
        timeout=timeout,
        proxy=proxy,
        verbose=verbose,
        js_analysis=js_analysis,
        sourcemaps=sourcemaps,
        passive_only=passive_only,
    )


def main() -> None:
    """Single-command entrypoint used by the installed ``cloudrift`` command."""

    typer.run(scan_command)


async def _run_scan(target: str, config: ScanConfig, quiet: bool) -> object:
    """Execute the async engine with optional Rich progress."""

    engine = CloudRiftEngine(config)
    if quiet:
        return await engine.scan(target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Generating candidates, validating providers, and correlating exposure intelligence", total=None)
        return await engine.scan(target)
