"""Table formatting utilities for the terminal UI."""
from __future__ import annotations

from rich.console import Console
from rich.table import Table


def make_findings_table(findings: list[dict]) -> Table:
    """Render a rich table of security findings."""
    table = Table(title="Security Findings", show_lines=True)
    table.add_column("Severity", style="bold red", no_wrap=True)
    table.add_column("Title", style="bold white")
    table.add_column("Asset", style="cyan")
    table.add_column("Confidence", style="yellow")

    severity_styles = {
        "critical": "[bold red]",
        "high": "[red]",
        "medium": "[yellow]",
        "low": "[green]",
        "info": "[dim]",
    }

    for f in findings:
        sev = f.get("severity", "info").lower()
        style = severity_styles.get(sev, "")
        table.add_row(
            f"{style}{sev.upper()}[/]",
            f.get("title", ""),
            f.get("affected_asset", ""),
            f.get("confidence", ""),
        )

    return table


def make_summary_table(stats: dict) -> Table:
    """Render a scan summary statistics table."""
    table = Table(title="Scan Summary", show_header=True)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", style="bold white")

    for key, val in stats.items():
        table.add_row(str(key), str(val))

    return table
