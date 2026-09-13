"""Diff formatting for scan comparison output."""
from __future__ import annotations

from rich.console import Console
from rich.table import Table


def format_diff(diff: dict, console: Console) -> None:
    """Pretty-print scan differences to the Rich console."""
    
    def _section(title: str, items: list, color: str, prefix: str) -> None:
        if not items:
            return
        table = Table(title=title, show_lines=False)
        table.add_column("Change", style=color)
        for item in items:
            table.add_row(f"{prefix} {item}")
        console.print(table)

    _section("New Subdomains", diff.get("new_subdomains", []), "bold green", "+")
    _section("Removed Subdomains", diff.get("removed_subdomains", []), "bold red", "-")
    _section("New Open Ports", diff.get("new_ports", []), "bold green", "+")
    _section("Closed Ports", diff.get("closed_ports", []), "bold red", "-")
    _section("New Findings", diff.get("new_findings", []), "bold yellow", "!")
    _section("Resolved Findings", diff.get("resolved_findings", []), "bold dim", "~")
