"""Rich-based console output for ReconAI.

Provides a unified interface for all terminal output:
- Status messages with timestamps
- Module progress indicators
- Findings display
- Summary tables
- Banners and headers
"""
from __future__ import annotations

import sys
from datetime import datetime
from typing import Any

# Ensure stdout and stderr handle UTF-8 cleanly on Windows terminals
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ── Custom Theme ────────────────────────────────────────────
RECONAI_THEME = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "module": "bold magenta",
    "target": "bold white",
    "dim": "dim",
    "header": "bold cyan",
    "finding.critical": "bold red",
    "finding.high": "red",
    "finding.medium": "yellow",
    "finding.low": "blue",
    "finding.info": "dim cyan",
})


class ReconConsole:
    """Unified terminal output for ReconAI.

    All output goes through this class to ensure consistent formatting,
    timestamps, and module attribution.
    """

    def __init__(self, verbose: bool = False, debug: bool = False):
        self._console = Console(theme=RECONAI_THEME)
        self._verbose = verbose
        self._debug = debug

    @property
    def console(self) -> Console:
        return self._console

    def banner(self) -> None:
        """Display the ReconAI banner."""
        banner_text = Text()
        banner_text.append("╔═══════════════════════════════════════════════════════════╗\n", style="bold cyan")
        banner_text.append("║                                                           ║\n", style="bold cyan")
        banner_text.append("║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██╗  ║\n", style="bold cyan")
        banner_text.append("║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║  ║\n", style="bold cyan")
        banner_text.append("║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██║  ║\n", style="bold cyan")
        banner_text.append("║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║  ║\n", style="bold cyan")
        banner_text.append("║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║  ║\n", style="bold cyan")
        banner_text.append("║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ║\n", style="bold cyan")
        banner_text.append("║                                                           ║\n", style="bold cyan")
        banner_text.append("║   Modular Reconnaissance & Attack-Surface Intelligence    ║\n", style="dim cyan")
        banner_text.append("║   v1.0.0                                                  ║\n", style="dim")
        banner_text.append("╚═══════════════════════════════════════════════════════════╝", style="bold cyan")
        try:
            self._console.print(banner_text)
        except (UnicodeEncodeError, Exception):
            ascii_fallback = (
                "+-----------------------------------------------------------+\n"
                "|   RECONAI - Attack Surface Intelligence Platform          |\n"
                "|   Modular Reconnaissance & Attack-Surface Intelligence    |\n"
                "|   v1.0.0                                                  |\n"
                "+-----------------------------------------------------------+"
            )
            self._console.print(ascii_fallback, style="bold cyan")
        self._console.print()

    def _timestamp(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def info(self, message: str, module: str = "") -> None:
        prefix = f"[dim][{self._timestamp()}][/dim]"
        if module:
            prefix += f" [module][{module}][/module]"
        self._console.print(f"{prefix} {message}")

    def success(self, message: str, module: str = "") -> None:
        prefix = f"[dim][{self._timestamp()}][/dim]"
        if module:
            prefix += f" [module][{module}][/module]"
        self._console.print(f"{prefix} [success]✓[/success] {message}")

    def warning(self, message: str, module: str = "") -> None:
        prefix = f"[dim][{self._timestamp()}][/dim]"
        if module:
            prefix += f" [module][{module}][/module]"
        self._console.print(f"{prefix} [warning]![/warning] {message}")

    def error(self, message: str, module: str = "") -> None:
        prefix = f"[dim][{self._timestamp()}][/dim]"
        if module:
            prefix += f" [module][{module}][/module]"
        self._console.print(f"{prefix} [error]✗[/error] {message}")

    def debug(self, message: str, module: str = "") -> None:
        if not self._debug:
            return
        prefix = f"[dim][{self._timestamp()}][/dim]"
        if module:
            prefix += f" [module][{module}][/module]"
        self._console.print(f"{prefix} [dim]DEBUG:[/dim] {message}")

    def target(self, target_str: str) -> None:
        self._console.print(f"\n[header]Target:[/header] [target]{target_str}[/target]\n")

    def scope_info(self, scope_summary: dict) -> None:
        """Display scope information."""
        table = Table(title="Scope", show_header=False, border_style="cyan")
        table.add_column("Key", style="dim")
        table.add_column("Value")
        for key, value in scope_summary.items():
            table.add_row(str(key), str(value))
        self._console.print(table)
        self._console.print()

    def module_status(self, modules: list[dict[str, str]]) -> None:
        """Display module status table."""
        table = Table(title="Module Status", border_style="cyan")
        table.add_column("Category", style="dim")
        table.add_column("Module")
        table.add_column("Status")
        table.add_column("Duration", justify="right")

        status_styles = {
            "RUNNING": "yellow",
            "DONE": "green",
            "FAILED": "red",
            "SKIPPED": "dim",
            "TIMEOUT": "red",
        }

        for m in modules:
            style = status_styles.get(m.get("status", ""), "white")
            table.add_row(
                m.get("category", ""),
                m.get("name", ""),
                f"[{style}]{m.get('status', '')}[/{style}]",
                m.get("duration", ""),
            )
        self._console.print(table)
        self._console.print()

    def tool_availability(self, tools: dict[str, tuple[bool, str]]) -> None:
        """Display tool availability table."""
        table = Table(title="Tool Availability", border_style="cyan")
        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Version", style="dim")

        for tool, (available, version) in tools.items():
            if available:
                table.add_row(tool, "[success]✓ Available[/success]", version)
            else:
                table.add_row(tool, "[warning]✗ Not found[/warning]", "—")

        self._console.print(table)
        self._console.print()

    def finding(self, title: str, severity: str, confidence: str, affected: str, description: str = "") -> None:
        """Display a security finding."""
        sev_style = {
            "critical": "finding.critical",
            "high": "finding.high",
            "medium": "finding.medium",
            "low": "finding.low",
            "info": "finding.info",
        }.get(severity.lower(), "white")

        panel_content = f"[{sev_style}]Severity: {severity}[/{sev_style}]  |  Confidence: {confidence}\n"
        panel_content += f"Affected: {affected}\n"
        if description:
            panel_content += f"\n{description}"

        self._console.print(Panel(panel_content, title=f"Finding: {title}", border_style=sev_style))

    def summary(self, stats: dict[str, Any], warnings: list[str], report_path: str = "") -> None:
        """Display the final scan summary."""
        self._console.print()
        self._console.rule("[bold cyan]RECONAI SUMMARY[/bold cyan]", style="cyan")
        self._console.print()

        table = Table(show_header=False, border_style="cyan", padding=(0, 2))
        table.add_column("Metric", style="dim", min_width=25)
        table.add_column("Value", style="bold")

        for key, value in stats.items():
            table.add_row(key, str(value))

        self._console.print(table)

        if warnings:
            self._console.print()
            self._console.print("[warning]Warnings:[/warning]")
            for w in warnings:
                self._console.print(f"  [warning]![/warning] {w}")

        if report_path:
            self._console.print()
            self._console.print(f"[header]Report:[/header] {report_path}")

        self._console.print()
        self._console.rule(style="cyan")

    def dry_run(self, modules: list[dict], commands: list[str]) -> None:
        """Display dry-run information."""
        self._console.print(Panel("[bold]DRY RUN — No commands will be executed[/bold]", border_style="yellow"))
        self._console.print()

        self._console.print("[header]Modules that would execute:[/header]")
        for m in modules:
            self._console.print(f"  [success]✓[/success] {m.get('name', '')} — {m.get('description', '')}")

        if commands:
            self._console.print()
            self._console.print("[header]Commands that would run:[/header]")
            for cmd in commands:
                self._console.print(f"  [dim]$[/dim] {cmd}")

    def output_line(self, line: str) -> None:
        """Print a raw output line (used as callback for streaming)."""
        self._console.print(line)
