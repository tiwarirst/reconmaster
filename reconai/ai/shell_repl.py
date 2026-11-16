"""ReconAI Interactive AI Shell — REPL for the NaturalLanguageShellAgent.

Provides a rich terminal experience with:
  - Streaming status updates while tools run
  - Colour-coded findings by severity
  - Persistent conversation history
  - Tab-completion hints
  - /help, /tools, /history, /clear, /save commands
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich import box

from reconai.ai.shell_agent import NaturalLanguageShellAgent, AgentTask, TOOL_CATALOGUE

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

BANNER = """
[bold cyan]
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
[/bold cyan]
[bold white]  AI SHELL — Natural Language Security Operator[/bold white]
[dim]  Type your task in plain English. Type /help for commands.[/dim]
"""

HELP_TEXT = """
[bold cyan]AI Shell Commands:[/bold cyan]

  [bold]/help[/bold]           Show this help message
  [bold]/tools[/bold]          List available & missing Kali tools
  [bold]/history[/bold]        Show conversation history
  [bold]/clear[/bold]          Clear conversation history
  [bold]/save [file][/bold]    Save last report to file (default: report.md)
  [bold]/exit[/bold]           Exit the AI Shell

[bold cyan]Example Tasks:[/bold cyan]

  [green]>[/green] scan example.com for open ports
  [green]>[/green] find all subdomains of target.com
  [green]>[/green] check if https://target.com is behind a WAF
  [green]>[/green] look for XSS on https://target.com/search?q=test
  [green]>[/green] what technologies does google.com use?
  [green]>[/green] enumerate DNS records for example.com
  [green]>[/green] check for CVE-2023-44487 on 192.168.1.1
  [green]>[/green] run full recon on evil.corp
  [green]>[/green] find hidden directories on https://target.com
  [green]>[/green] is there any secret exposure on target.com?
  [green]>[/green] check WHOIS for domain.com
  [green]>[/green] crawl https://target.com and list all endpoints
"""


class AIShell:
    """Interactive REPL for the NaturalLanguageShellAgent."""

    def __init__(self, agent: NaturalLanguageShellAgent) -> None:
        self.agent = agent
        self.console = Console()
        self._last_task: AgentTask | None = None
        self._session_tasks: list[AgentTask] = []

    async def run(self) -> None:
        """Start the interactive shell loop."""
        self.console.print(BANNER)
        self._print_tool_status()

        while True:
            try:
                user_input = await asyncio.get_event_loop().run_in_executor(
                    None, self._prompt
                )
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[dim]Exiting AI Shell...[/dim]")
                break

            user_input = user_input.strip()
            if not user_input:
                continue

            # Handle built-in commands
            if user_input.startswith("/"):
                if await self._handle_command(user_input):
                    continue
                else:
                    break  # /exit
            else:
                await self._handle_task(user_input)

    def _prompt(self) -> str:
        """Display the shell prompt and read user input."""
        try:
            return input("\n[AI Shell]> ")
        except EOFError:
            raise

    async def _handle_command(self, cmd: str) -> bool:
        """Handle /commands. Returns False to exit."""
        parts = cmd.split(maxsplit=1)
        base = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if base in ("/exit", "/quit", "/q"):
            self.console.print("[dim]Goodbye.[/dim]")
            return False

        elif base == "/help":
            self.console.print(Markdown(HELP_TEXT.replace("[bold cyan]", "## ").replace("[/bold cyan]", "")))
            self.console.print(Panel(HELP_TEXT, title="AI Shell Help", border_style="cyan"))

        elif base == "/tools":
            self._print_tool_status(verbose=True)

        elif base == "/history":
            self._print_history()

        elif base == "/clear":
            self.agent.clear_history()
            self._session_tasks.clear()
            self._last_task = None
            self.console.print("[green]✓[/green] Conversation history cleared.")

        elif base == "/save":
            filename = arg.strip() or "ai_shell_report.md"
            self._save_report(filename)

        else:
            self.console.print(f"[red]Unknown command:[/red] {base}. Type /help for available commands.")

        return True

    async def _handle_task(self, user_input: str) -> None:
        """Process a natural language task."""
        if user_input.lower() in ("hi", "hello", "hey", "help", "start"):
            self.console.print(
                "\n[bold cyan]👋 Hello! I am your AI Security Shell.[/bold cyan]\n"
                "[white]Give me a security task with a target, for example:[/white]\n"
                "  • [green]scan rru.ac.in for open ports[/green]\n"
                "  • [green]find all subdomains of rru.ac.in[/green]\n"
                "  • [green]what technologies does rru.ac.in use?[/green]\n"
                "  • [green]run full recon on 192.168.1.1[/green]\n"
                "\n[dim]Type [cyan]/help[/cyan] for built-in shell commands, or [cyan]/tools[/cyan] to see installed tools.[/dim]"
            )
            return

        self.console.print()
        self.console.rule("[bold cyan]Processing Task[/bold cyan]", style="cyan")

        task: AgentTask | None = None

        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            pid = progress.add_task("Parsing intent with AI...", total=None)

            # We need to intercept tool execution to show progress
            # Run the full task but show status
            progress.update(pid, description="[bold cyan]Reasoning: identifying target & tools...")

            # Step 1: parse intent
            agent_task = await self.agent._parse_intent(user_input)

            if agent_task.target == "UNKNOWN":
                self.console.print(
                    "[yellow]⚠[/yellow] Could not identify a target from your request. "
                    "Please include a hostname, IP, or URL."
                )
                return

            progress.update(
                pid,
                description=f"[bold cyan]Target: [white]{agent_task.target}[/white] | "
                            f"Tools: [white]{', '.join(agent_task.tools_planned) or 'none'}[/white]",
            )

            if not agent_task.tools_planned:
                self.console.print(
                    "[yellow]⚠[/yellow] No suitable tools found for this task, "
                    "or the required tools are not installed. Run /tools to check."
                )
                return

            # Step 2: execute tools one by one
            import time as _time
            t0 = _time.monotonic()
            for tool_name in agent_task.tools_planned:
                progress.update(pid, description=f"[bold cyan]Running [white]{tool_name}[/white] on [white]{agent_task.target}[/white]...")
                result = await self.agent._execute_tool(tool_name, agent_task.target, user_input)
                agent_task.results.append(result)

            # Step 3: synthesise
            progress.update(pid, description="[bold cyan]Synthesizing findings with AI...")
            agent_task.ai_synthesis = await self.agent._synthesize(agent_task)
            agent_task.findings = self.agent._extract_findings(agent_task.ai_synthesis)
            agent_task.elapsed = _time.monotonic() - t0

            # update agent history
            self.agent._history.append({"role": "user", "content": user_input})
            self.agent._history.append({"role": "assistant", "content": agent_task.ai_synthesis})

            task = agent_task

        if task is None:
            return

        self._last_task = task
        self._session_tasks.append(task)

        # ── Print Results ──────────────────────────────────────────────────
        self._print_task_header(task)
        self._print_tool_results(task)
        self._print_findings(task)
        self._print_synthesis(task)

    def _print_task_header(self, task: AgentTask) -> None:
        self.console.print()
        self.console.print(Panel(
            f"[bold white]Target:[/bold white] [cyan]{task.target}[/cyan]\n"
            f"[bold white]Intent:[/bold white] {task.intent}\n"
            f"[bold white]Tools:[/bold white] {', '.join(task.tools_planned)}\n"
            f"[bold white]Elapsed:[/bold white] {task.elapsed:.1f}s",
            title="[bold cyan] Task Execution Summary[/bold cyan]",
            border_style="cyan",
        ))

    def _print_tool_results(self, task: AgentTask) -> None:
        if not task.results:
            return
        self.console.print()
        tbl = Table(
            title="Tool Execution Log",
            box=box.ROUNDED,
            border_style="dim",
            show_header=True,
            header_style="bold white",
        )
        tbl.add_column("Tool", style="cyan", width=14)
        tbl.add_column("Status", width=10)
        tbl.add_column("Time", width=8)
        tbl.add_column("Lines", width=8)
        tbl.add_column("Command", style="dim", overflow="fold")

        for r in task.results:
            status = "[green]✓ OK[/green]" if r.success else "[red]✗ FAIL[/red]"
            if r.return_code == 124:
                status = "[yellow]⏱ TIMEOUT[/yellow]"
            elif r.return_code == 127:
                status = "[red]✗ NOT FOUND[/red]"
            lines = len([l for l in r.stdout.splitlines() if l.strip()])
            tbl.add_row(r.tool, status, f"{r.duration:.1f}s", str(lines), r.command[:80])

        self.console.print(tbl)

    def _print_findings(self, task: AgentTask) -> None:
        if not task.findings:
            return
        self.console.print()
        self.console.rule("[bold yellow] Structured Findings[/bold yellow]", style="yellow")
        for f in task.findings:
            color = SEVERITY_COLORS.get(f["severity"], "white")
            self.console.print(Panel(
                f"[bold white]What:[/bold white] {f.get('what', '-')}\n"
                f"[bold white]Where:[/bold white] {f.get('where', '-')}\n"
                f"[bold white]Risk:[/bold white] {f.get('risk', '-')}\n"
                f"[bold white]Action:[/bold white] {f.get('action', '-')}",
                title=f"[{color}][{f['severity']}] {f['title']}[/{color}]",
                border_style=color.replace("bold ", ""),
            ))

    def _print_synthesis(self, task: AgentTask) -> None:
        self.console.print()
        self.console.rule("[bold cyan] AI Analysis Report[/bold cyan]", style="cyan")
        self.console.print(Markdown(task.ai_synthesis))

    def _print_tool_status(self, verbose: bool = False) -> None:
        available = self.agent.get_available_tools()
        missing = self.agent.get_missing_tools()

        if verbose:
            tbl = Table(title="Kali Tool Status", box=box.ROUNDED, border_style="dim")
            tbl.add_column("Tool", style="cyan", width=16)
            tbl.add_column("Status", width=14)
            tbl.add_column("Description", style="dim")
            for name, info in TOOL_CATALOGUE.items():
                avail = self.agent._available_tools.get(name, False)
                status = "[green]✓ Available[/green]" if avail else "[red]✗ Missing[/red]"
                tbl.add_row(name, status, info["description"])
            self.console.print(tbl)
        else:
            self.console.print(
                f"[dim]Tools available: [green]{len(available)}[/green] | "
                f"Missing: [red]{len(missing)}[/red] "
                f"(run [cyan]/tools[/cyan] for details)[/dim]"
            )

    def _print_history(self) -> None:
        if self._session_tasks:
            self.console.print(f"\n[cyan]Session tasks ({len(self._session_tasks)}):[/cyan]")
            for i, t in enumerate(self._session_tasks, 1):
                self.console.print(
                    f"  {i}. [{t.elapsed:.1f}s] {t.intent} → target: {t.target} | "
                    f"findings: {len(t.findings)}"
                )
        else:
            self.console.print("[dim]No tasks in this session yet.[/dim]")

    def _save_report(self, filename: str) -> None:
        if not self._last_task:
            self.console.print("[yellow]No report to save yet.[/yellow]")
            return
        task = self._last_task
        content = (
            f"# ReconAI Shell Report\n\n"
            f"**Target:** {task.target}  \n"
            f"**Task:** {task.intent}  \n"
            f"**Tools:** {', '.join(task.tools_planned)}  \n"
            f"**Elapsed:** {task.elapsed:.1f}s\n\n"
            f"---\n\n"
            f"{task.ai_synthesis}\n\n"
            f"---\n\n"
            f"## Raw Tool Outputs\n\n"
        )
        for r in task.results:
            content += (
                f"### {r.tool}\n"
                f"```\n{r.command}\n```\n"
                f"```\n{r.stdout[:5000] or r.stderr or '(no output)'}\n```\n\n"
            )
        try:
            Path(filename).write_text(content, encoding="utf-8")
            self.console.print(f"[green]✓[/green] Report saved to: [cyan]{filename}[/cyan]")
        except Exception as exc:
            self.console.print(f"[red]✗[/red] Failed to save: {exc}")
