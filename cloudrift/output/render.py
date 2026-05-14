"""Rich terminal rendering for CloudRift reports."""

from __future__ import annotations

from collections import defaultdict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from cloudrift.models.enums import RiskLevel
from cloudrift.models.report import IntelligenceReport

RISK_STYLES = {
    RiskLevel.HIGH: "bold red",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.LOW: "bold cyan",
    RiskLevel.INFO: "dim",
}


def render_banner(console: Console) -> None:
    """Render the CloudRift banner."""

    title = Text("CloudRift", style="bold bright_cyan")
    subtitle = Text("Cloud Storage Exposure Intelligence\nBuilt by Arghya Sikdar", style="bright_white")
    console.print(Panel.fit(subtitle, title=title, border_style="cyan", box=box.ROUNDED))


def render_report(console: Console, report: IntelligenceReport) -> None:
    """Render an intelligence report in the terminal."""

    render_banner(console)
    console.print(_stats_panel(report))
    console.print(_risk_table(report))
    console.print(_bucket_tree(report))
    console.print(_relationship_tree(report))


def _stats_panel(report: IntelligenceReport) -> Panel:
    stats = report.statistics
    grid = Table.grid(expand=True)
    grid.add_column(style="cyan")
    grid.add_column(style="white")
    grid.add_row("Target", report.target)
    grid.add_row("Highest Risk", f"[{RISK_STYLES[report.highest_risk]}]{report.highest_risk.value}[/]")
    grid.add_row("Candidates", str(stats.candidates_generated))
    grid.add_row("Validated", str(stats.buckets_validated))
    grid.add_row("Public/Listable", str(stats.public_buckets))
    grid.add_row("Sensitive Files", str(stats.sensitive_files))
    return Panel(grid, title="Intelligence Summary", border_style="bright_blue", box=box.ROUNDED)


def _risk_table(report: IntelligenceReport) -> Table:
    table = Table(title="Correlated Findings", box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Provider")
    table.add_column("Bucket")
    table.add_column("Finding")
    table.add_column("Confidence", justify="right")
    risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2, RiskLevel.INFO: 3}
    for finding in sorted(report.findings, key=lambda item: risk_order[item.risk]):
        style = RISK_STYLES[finding.risk]
        table.add_row(
            f"[{style}]{finding.risk.value}[/]",
            finding.provider.value,
            finding.bucket,
            finding.title,
            f"{finding.confidence:.0%}",
        )
        for exposed_file in finding.exposed_files:
            table.add_row(
                f"[{style}]{exposed_file.risk.value}[/]",
                finding.provider.value,
                finding.bucket,
                f"  {exposed_file.path} ({exposed_file.category})",
                f"{exposed_file.confidence:.0%}",
            )
    if not report.findings:
        table.add_row("[dim]INFO[/]", "-", "-", "No exposed storage findings confirmed", "0%")
    return table


def _bucket_tree(report: IntelligenceReport) -> Tree:
    tree = Tree(f"[bold cyan]{report.target}[/] bucket intelligence")
    grouped: dict[str, list[str]] = defaultdict(list)
    for observation in report.observations:
        label = f"{observation.candidate.name} [{observation.exposure.value}]"
        grouped[observation.provider.value].append(label)
    for provider, buckets in sorted(grouped.items()):
        branch = tree.add(f"[bright_white]{provider}[/]")
        for bucket in sorted(buckets):
            branch.add(bucket)
    if not grouped:
        tree.add("[dim]No active validations were performed[/]")
    return tree


def _relationship_tree(report: IntelligenceReport) -> Tree:
    tree = Tree("[bold cyan]Relationship Map[/]")
    grouped: dict[str, list[str]] = defaultdict(list)
    for relationship in report.relationships:
        grouped[relationship.source].append(f"{relationship.target} ({relationship.relation}, {relationship.confidence:.0%})")
    for source, targets in sorted(grouped.items()):
        branch = tree.add(source)
        for target in sorted(set(targets)):
            branch.add(target)
    return tree
