"""NEXUS Shell — The Revolutionary AI Security Operations Terminal.

A stunning, future-tech terminal interface that feels like nothing else in
the cybersecurity tooling landscape.

Features:
  • Cinematic ASCII banner with system status
  • Three-pane cognitive workflow: Mission | Execution | Intelligence
  • Real-time streaming progress with live tool output
  • Colour-coded findings by severity with MITRE ATT&CK mapping
  • Persistent mission intelligence panel
  • Natural conversation mode: ask anything
  • Full mission report export
  • Context-aware command suggestions
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from reconai.ai.nexus_agent import (
    ExecutedStep, Mission, NexusAgent, OperationMode, ProposedStep
)
from reconai.ai.tool_discovery import KaliToolDiscovery

NEXUS_BANNER = r"""
███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

SEVERITY_STYLE = {
    "CRITICAL": ("bold white on red", "💀"),
    "HIGH": ("bold red", "🔴"),
    "MEDIUM": ("bold yellow", "🟡"),
    "LOW": ("bold cyan", "🔵"),
    "INFO": ("dim white", "⚪"),
}

MODE_STYLES = {
    OperationMode.AUTOPILOT: ("bold magenta", "🤖 AUTOPILOT"),
    OperationMode.COPILOT: ("bold cyan", "🧠 COPILOT"),
    OperationMode.MANUAL: ("bold green", "🕹  MANUAL+AI"),
}

HELP = """
## NEXUS Commands

### Mission Control
| Command | Description |
|---------|-------------|
| `mission <goal>` | Create a new mission from natural language |
| `target <host>` | Set/change current mission target |
| `mode autopilot` | Switch to full AI autopilot mode |
| `mode copilot` | Switch to AI-guided copilot mode |
| `mode manual` | Switch to manual + AI analysis mode |
| `run` | Start/continue current mission execution |

### Tool Execution
| Command | Description |
|---------|-------------|
| `exec <command>` | Run any Kali tool command (AI analyses output) |
| `analyse <text>` | Paste output for AI analysis |
| `next` | Get AI's next recommended step (Copilot) |
| `approve` | Approve and execute the current AI proposal |
| `skip` | Skip current proposal, get a different one |

### Intelligence & Reporting
| Command | Description |
|---------|-------------|
| `intel` | Show all gathered intelligence |
| `findings` | Show all security findings |
| `chain` | Generate/show attack kill chain |
| `report` | Generate and show full mission report |
| `save [file]` | Save full report to markdown file |

### Information
| Command | Description |
|---------|-------------|
| `tools` | Show all available Kali tools by category |
| `ask <question>` | Ask AI anything (security Q&A) |
| `status` | Show current mission status |
| `history` | Show execution history |
| `clear` | Clear screen |
| `exit` | Exit NEXUS |
"""


class NexusShell:
    """The NEXUS interactive terminal shell."""

    def __init__(
        self,
        agent: NexusAgent,
        discovery: KaliToolDiscovery,
    ) -> None:
        self.agent = agent
        self.discovery = discovery
        self.console = Console()
        self._mission: Mission | None = None
        self._current_proposal: ProposedStep | None = None
        self._step_counter = 0
        self._session_log: list[str] = []

    async def run(self) -> None:
        """Main NEXUS shell loop."""
        self._print_banner()
        self._print_status_bar()

        while True:
            try:
                raw = await asyncio.get_event_loop().run_in_executor(
                    None, self._prompt
                )
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[dim]NEXUS session terminated.[/dim]")
                break

            line = raw.strip()
            if not line:
                continue

            should_exit = await self._dispatch(line)
            if should_exit:
                break

    def _prompt(self) -> str:
        mode_str = MODE_STYLES.get(self.agent.mode, ("white", "?"))[1]
        target_str = self._mission.target if self._mission else "no-target"
        try:
            return input(f"\n\033[1;35mNEXUS\033[0m[\033[36m{mode_str}\033[0m]"
                         f"[\033[33m{target_str}\033[0m]> ")
        except EOFError:
            raise

    # ── Command Dispatcher ────────────────────────────────────────────────────

    async def _dispatch(self, line: str) -> bool:
        """Route command to handler. Returns True to exit."""
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        handlers = {
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "q": self._cmd_exit,
            "help": self._cmd_help,
            "?": self._cmd_help,
            "mission": self._cmd_mission,
            "target": self._cmd_target,
            "mode": self._cmd_mode,
            "run": self._cmd_run,
            "exec": self._cmd_exec,
            "analyse": self._cmd_analyse,
            "analyze": self._cmd_analyse,
            "next": self._cmd_next,
            "approve": self._cmd_approve,
            "skip": self._cmd_skip,
            "intel": self._cmd_intel,
            "findings": self._cmd_findings,
            "chain": self._cmd_chain,
            "report": self._cmd_report,
            "save": self._cmd_save,
            "tools": self._cmd_tools,
            "ask": self._cmd_ask,
            "status": self._cmd_status,
            "history": self._cmd_history,
            "clear": self._cmd_clear,
        }

        handler = handlers.get(cmd)
        if handler:
            result = await handler(arg)
            return result is True
        else:
            # Unknown command — treat as ask/chat
            await self._cmd_ask(line)
            return False

    # ── Command Handlers ──────────────────────────────────────────────────────

    async def _cmd_exit(self, _: str) -> bool:
        self.console.print("[dim cyan]NEXUS session ended. Stay sharp.[/dim cyan]")
        return True

    async def _cmd_help(self, _: str) -> None:
        self.console.print(Panel(Markdown(HELP), title="[bold cyan] NEXUS Help[/bold cyan]",
                                 border_style="cyan", padding=(1, 2)))

    async def _cmd_mission(self, goal: str) -> None:
        if not goal:
            self.console.print("[yellow]Usage: mission <your goal in plain English>[/yellow]")
            return

        with self.console.status("[bold cyan]Planning mission...", spinner="dots"):
            self._mission = await self.agent.create_mission(goal)

        self._print_mission_briefing(self._mission)

    async def _cmd_target(self, target: str) -> None:
        if not target:
            cur = self._mission.target if self._mission else "None"
            self.console.print(f"[cyan]Current target:[/cyan] {cur}")
            return
        if self._mission:
            self._mission.target = target
            self.console.print(f"[green]✓[/green] Target updated: [bold cyan]{target}[/bold cyan]")
        else:
            # Create a blank mission with this target
            self._mission = await self.agent.create_mission(
                f"Security assessment of {target}", target
            )
            self._print_mission_briefing(self._mission)

    async def _cmd_mode(self, mode_str: str) -> None:
        modes = {
            "autopilot": OperationMode.AUTOPILOT,
            "auto": OperationMode.AUTOPILOT,
            "copilot": OperationMode.COPILOT,
            "manual": OperationMode.MANUAL,
        }
        if mode_str.lower() not in modes:
            self.console.print("[yellow]Modes: autopilot | copilot | manual[/yellow]")
            return
        self.agent.mode = modes[mode_str.lower()]
        style, label = MODE_STYLES[self.agent.mode]
        self.console.print(f"[green]✓[/green] Switched to [{style}]{label}[/{style}] mode")

        if self.agent.mode == OperationMode.AUTOPILOT:
            self.console.print(Panel(
                "[yellow]AUTOPILOT MODE:[/yellow] AI will plan and execute all steps autonomously.\n"
                "Run [cyan]run[/cyan] to start. Critical-risk tools will pause for confirmation.",
                border_style="yellow",
            ))
        elif self.agent.mode == OperationMode.COPILOT:
            self.console.print(Panel(
                "[cyan]COPILOT MODE:[/cyan] AI suggests each step. You review and approve.\n"
                "Run [cyan]next[/cyan] to get AI's recommendation.",
                border_style="cyan",
            ))
        else:
            self.console.print(Panel(
                "[green]MANUAL+AI MODE:[/green] Run any command with [cyan]exec <cmd>[/cyan].\n"
                "AI will analyse all output in real-time and extract findings.",
                border_style="green",
            ))

    async def _cmd_run(self, _: str) -> None:
        if not self._mission:
            self.console.print("[yellow]No mission active. Use: mission <goal>[/yellow]")
            return

        if self.agent.mode == OperationMode.AUTOPILOT:
            await self._run_autopilot()
        elif self.agent.mode == OperationMode.COPILOT:
            self.console.print("[dim]Copilot mode: use [cyan]next[/cyan] -> [cyan]approve[/cyan] workflow[/dim]")
        else:
            self.console.print("[dim]Manual mode: use [cyan]exec <command>[/cyan] to run tools[/dim]")

    async def _run_autopilot(self) -> None:
        self.console.rule("[bold magenta]🤖 AUTOPILOT ENGAGED[/bold magenta]", style="magenta")

        progress = Progress(
            SpinnerColumn(spinner_name="aesthetic"),
            TextColumn("[bold magenta]{task.description}"),
            BarColumn(bar_width=30, style="magenta"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )

        async def progress_cb(event: str, data: Any) -> None:
            if event == "step_complete":
                step: ExecutedStep = data
                rc_str = "[green]✓[/green]" if step.return_code == 0 else "[red]✗[/red]"
                self.console.print(
                    f"  {rc_str} [{step.tool}] {' '.join(str(c) for c in step.command[:5])} "
                    f"({step.duration:.1f}s | {len(step.findings_extracted)} findings)"
                )
                for f in step.findings_extracted:
                    sev = f.get("severity", "INFO")
                    style, icon = SEVERITY_STYLE.get(sev, ("white", "•"))
                    self.console.print(
                        f"    {icon} [{style}][{sev}][/{style}] {f.get('title', '')}"
                    )
            elif event == "risk_gate":
                proposed: ProposedStep = data
                self.console.print(Panel(
                    f"[bold red]RISK GATE — Critical Tool[/bold red]\n\n"
                    f"Tool: [bold]{proposed.tool}[/bold]\n"
                    f"Command: [cyan]{' '.join(proposed.command)}[/cyan]\n"
                    f"Rationale: {proposed.rationale}\n\n"
                    "[yellow]Autopilot paused. Critical-risk tools require manual approval.[/yellow]\n"
                    "Switch to copilot mode and use [cyan]next -> approve[/cyan]",
                    border_style="red",
                ))

        with progress:
            task = progress.add_task("[magenta]Running mission...", total=None)
            self._mission = await self.agent.run_autopilot(self._mission, progress_cb)
            progress.update(task, description="[green]Mission complete[/green]")

        self._print_mission_summary(self._mission)

    async def _cmd_exec(self, command: str) -> None:
        if not command:
            self.console.print("[yellow]Usage: exec <full command>[/yellow]")
            return
        if not self._mission:
            target = "unknown"
            self._mission = await self.agent.create_mission(
                f"Ad-hoc security task", target
            )

        self._step_counter += 1
        parts = command.split()

        self.console.print(
            f"\n[bold cyan]► Executing:[/bold cyan] [white]{command}[/white]"
        )

        with self.console.status(f"[cyan]Running {parts[0]}...", spinner="dots"):
            from reconai.ai.nexus_agent import ProposedStep
            proposed = ProposedStep(
                tool=parts[0], command=parts,
                rationale="User-executed command",
                expected_output="",
                risk_level="medium",
                phase="manual",
            )
            step = await self.agent.execute_approved_step(
                self._mission, proposed, self._step_counter
            )

        # Print result
        rc_str = "[green]✓ OK[/green]" if step.return_code == 0 else f"[red]✗ RC={step.return_code}[/red]"
        self.console.print(f"[dim]Status: {rc_str} | Time: {step.duration:.1f}s[/dim]")

        if step.stdout:
            output_lines = step.stdout.splitlines()[:30]
            preview = "\n".join(output_lines)
            if len(step.stdout.splitlines()) > 30:
                preview += f"\n[dim]... ({len(step.stdout.splitlines())-30} more lines)[/dim]"
            self.console.print(Panel(
                Syntax(preview, "text", theme="monokai", line_numbers=False),
                title=f"[cyan]{parts[0]} output[/cyan]",
                border_style="dim",
            ))

        if step.ai_interpretation:
            self.console.rule("[bold cyan]AI Analysis[/bold cyan]", style="cyan")
            self.console.print(Markdown(step.ai_interpretation))

        for f in step.findings_extracted:
            self._print_finding(f)

    async def _cmd_analyse(self, text: str) -> None:
        """Analyse pasted/piped output."""
        if not text:
            self.console.print("[yellow]Paste the output to analyse:[/yellow]")
            lines = []
            try:
                while True:
                    line = await asyncio.get_event_loop().run_in_executor(None, input, "")
                    if line.strip() == "END":
                        break
                    lines.append(line)
            except EOFError:
                pass
            text = "\n".join(lines)

        if not self._mission:
            self._mission = await self.agent.create_mission("Ad-hoc analysis", "unknown")

        with self.console.status("[cyan]AI is analysing the output...", spinner="dots"):
            analysis = await self.agent.analyse_manual_output(
                self._mission, "manual_input", "user-provided output", text
            )

        self.console.rule("[bold cyan]AI Analysis[/bold cyan]", style="cyan")
        self.console.print(Markdown(analysis))

    async def _cmd_next(self, _: str) -> None:
        if not self._mission:
            self.console.print("[yellow]No mission. Use: mission <goal>[/yellow]")
            return

        with self.console.status("[cyan]AI is planning next step...", spinner="aesthetic"):
            self._current_proposal = await self.agent.propose_next_step(self._mission)

        if self._current_proposal is None:
            self.console.print("[green]✓ AI considers this phase complete.[/green]")
            return

        self._print_proposal(self._current_proposal)

    async def _cmd_approve(self, _: str) -> None:
        if not self._current_proposal:
            self.console.print("[yellow]No pending proposal. Run: next[/yellow]")
            return
        if not self._mission:
            self.console.print("[yellow]No active mission.[/yellow]")
            return

        self._step_counter += 1
        cmd_str = " ".join(self._current_proposal.command)
        self.console.print(f"\n[bold green]► Approved:[/bold green] [white]{cmd_str}[/white]")

        with self.console.status(f"[cyan]Executing {self._current_proposal.tool}...", spinner="dots"):
            step = await self.agent.execute_approved_step(
                self._mission, self._current_proposal, self._step_counter
            )
        self._current_proposal = None

        # Display results
        self._print_step_result(step)

    async def _cmd_skip(self, _: str) -> None:
        self._current_proposal = None
        self.console.print("[dim]Proposal skipped. Run [cyan]next[/cyan] for another suggestion.[/dim]")

    async def _cmd_intel(self, _: str) -> None:
        if not self._mission or not self._mission.intelligence:
            self.console.print("[dim]No intelligence gathered yet.[/dim]")
            return
        self._print_intelligence(self._mission)

    async def _cmd_findings(self, _: str) -> None:
        if not self._mission or not self._mission.findings:
            self.console.print("[dim]No findings yet.[/dim]")
            return
        self._print_all_findings(self._mission.findings)

    async def _cmd_chain(self, _: str) -> None:
        if not self._mission:
            self.console.print("[yellow]No active mission.[/yellow]")
            return
        if not self._mission.findings:
            self.console.print("[yellow]No findings yet. Run some tools first.[/yellow]")
            return

        with self.console.status("[magenta]Building attack kill chain...", spinner="aesthetic"):
            chain = await self.agent._build_attack_chain(self._mission)
            self._mission.attack_chain = chain

        self.console.rule("[bold red]⚔ Attack Kill Chain[/bold red]", style="red")
        self.console.print(Markdown(chain))

    async def _cmd_report(self, _: str) -> None:
        if not self._mission:
            self.console.print("[yellow]No active mission.[/yellow]")
            return

        with self.console.status("[cyan]Generating mission report...", spinner="aesthetic"):
            report = await self.agent._generate_final_report(self._mission)
            self._mission.final_report = report

        self.console.rule("[bold cyan]📋 Mission Report[/bold cyan]", style="cyan")
        self.console.print(Markdown(report))

    async def _cmd_save(self, filename: str) -> None:
        if not self._mission:
            self.console.print("[yellow]No active mission.[/yellow]")
            return

        filename = filename.strip() or f"nexus_report_{self._mission.target}.md"
        if not self._mission.final_report:
            with self.console.status("[cyan]Generating report...", spinner="dots"):
                self._mission.final_report = await self.agent._generate_final_report(self._mission)

        content = self._build_markdown_report(self._mission)
        try:
            Path(filename).write_text(content, encoding="utf-8")
            self.console.print(f"[green]✓[/green] Report saved: [cyan]{filename}[/cyan]")
        except Exception as exc:
            self.console.print(f"[red]✗[/red] Save failed: {exc}")

    async def _cmd_tools(self, cat_filter: str) -> None:
        available = self.discovery.get_available()
        if cat_filter:
            available = [t for t in available if cat_filter.lower() in t.category]

        # Group by top-level category
        by_cat: dict[str, list] = {}
        for t in sorted(available, key=lambda x: x.category):
            cat = t.category.split("/")[0].upper()
            by_cat.setdefault(cat, []).append(t)

        tbl = Table(
            title=f"Available Kali Tools ({len(available)} installed)",
            box=box.ROUNDED, border_style="cyan", show_header=True,
        )
        tbl.add_column("Category", style="bold cyan", width=16)
        tbl.add_column("Tool", style="white", width=18)
        tbl.add_column("Risk", width=10)
        tbl.add_column("Description", style="dim")

        risk_colors = {"critical": "red", "high": "yellow", "medium": "blue",
                       "low": "green", "unknown": "dim"}
        for cat, tools in sorted(by_cat.items()):
            for i, t in enumerate(tools):
                risk_color = risk_colors.get(t.risk_level, "white")
                tbl.add_row(
                    cat if i == 0 else "",
                    t.name,
                    f"[{risk_color}]{t.risk_level.upper()}[/{risk_color}]",
                    t.description[:60],
                )

        self.console.print(tbl)
        stats = self.discovery.stats()
        self.console.print(
            f"\n[dim]Total in knowledge base: {stats['total_known']} | "
            f"Installed: [green]{stats['available']}[/green] | "
            f"Run [cyan]tools <category>[/cyan] to filter[/dim]"
        )

    async def _cmd_ask(self, question: str) -> None:
        if not question:
            self.console.print("[yellow]Usage: ask <question>[/yellow]")
            return

        with self.console.status("[cyan]NEXUS is thinking...", spinner="aesthetic"):
            answer = await self.agent.ask(question, self._mission)

        self.console.rule("[bold cyan]NEXUS Response[/bold cyan]", style="cyan")
        self.console.print(Markdown(answer))

    async def _cmd_status(self, _: str) -> None:
        if not self._mission:
            self.console.print(Panel(
                "[yellow]No active mission.[/yellow]\n"
                "Start one: [cyan]mission <your goal>[/cyan] or [cyan]target <host>[/cyan]",
                title="[cyan]Status[/cyan]", border_style="dim",
            ))
            return
        self._print_mission_status(self._mission)

    async def _cmd_history(self, _: str) -> None:
        if not self._mission or not self._mission.steps:
            self.console.print("[dim]No steps executed yet.[/dim]")
            return
        tbl = Table(title="Execution History", box=box.SIMPLE, border_style="dim")
        tbl.add_column("#", width=4, style="dim")
        tbl.add_column("Tool", style="cyan", width=14)
        tbl.add_column("Phase", width=14)
        tbl.add_column("Status", width=8)
        tbl.add_column("Time", width=7)
        tbl.add_column("Findings", width=10)
        tbl.add_column("Command", style="dim")
        for s in self._mission.steps:
            rc_str = "[green]✓[/green]" if s.return_code == 0 else "[red]✗[/red]"
            tbl.add_row(
                str(s.step_num), s.tool, s.phase, rc_str,
                f"{s.duration:.1f}s", str(len(s.findings_extracted)),
                " ".join(str(c) for c in s.command[:6]),
            )
        self.console.print(tbl)

    async def _cmd_clear(self, _: str) -> None:
        self.console.clear()
        self._print_banner()

    # ── Print Helpers ─────────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        stats = self.discovery.stats()
        avail = stats["available"]
        total = stats["total_known"]

        banner_text = Text(NEXUS_BANNER, style="bold cyan")
        self.console.print(banner_text)
        self.console.print(
            f"[bold white]  AI Security Operations Platform[/bold white]  "
            f"[dim]v2.0 — {avail} of {total}+ Kali tools available[/dim]"
        )
        self.console.print()

    def _print_status_bar(self) -> None:
        mode_style, mode_label = MODE_STYLES[self.agent.mode]
        tools_avail = len(self.discovery.get_available())
        self.console.print(Panel(
            f"Mode: [{mode_style}]{mode_label}[/{mode_style}]  |  "
            f"Tools: [green]{tools_avail}[/green] available  |  "
            f"Type [bold cyan]help[/bold cyan] or start with: [cyan]mission <goal>[/cyan]",
            border_style="dim cyan", padding=(0, 1),
        ))

    def _print_mission_briefing(self, mission: Mission) -> None:
        self.console.print()
        self.console.rule("[bold magenta]⚡ MISSION BRIEFING[/bold magenta]", style="magenta")
        self.console.print(Panel(
            f"[bold white]Goal:[/bold white] {mission.goal}\n"
            f"[bold white]Target:[/bold white] [bold cyan]{mission.target}[/bold cyan]\n"
            f"[bold white]Mode:[/bold white] {MODE_STYLES[mission.mode][1]}\n"
            "[bold white]Attack Phases:[/bold white] [dim]" + "  ->  ".join(mission.phases) + "[/dim]",
            title="[bold magenta]NEXUS Mission[/bold magenta]",
            border_style="magenta",
        ))

        if mission.mode == OperationMode.AUTOPILOT:
            self.console.print("[dim]Type [cyan]run[/cyan] to engage autopilot.[/dim]")
        elif mission.mode == OperationMode.COPILOT:
            self.console.print("[dim]Type [cyan]next[/cyan] to get AI's first recommendation.[/dim]")
        else:
            self.console.print("[dim]Use [cyan]exec <command>[/cyan] to run tools manually.[/dim]")

    def _print_proposal(self, p: ProposedStep) -> None:
        risk_colors = {"critical": "red", "high": "yellow", "medium": "blue",
                       "low": "green"}
        risk_color = risk_colors.get(p.risk_level, "white")
        cmd_str = " ".join(str(c) for c in p.command)

        self.console.print(Panel(
            f"[bold white]Tool:[/bold white] [cyan]{p.tool}[/cyan]  |  "
            f"[bold white]Risk:[/bold white] [{risk_color}]{p.risk_level.upper()}[/{risk_color}]  |  "
            f"[bold white]Phase:[/bold white] [dim]{p.phase}[/dim]\n\n"
            f"[bold white]Command:[/bold white]\n  [bold cyan]{cmd_str}[/bold cyan]\n\n"
            f"[bold white]Rationale:[/bold white] {p.rationale}\n\n"
            f"[bold white]Expected:[/bold white] [dim]{p.expected_output}[/dim]\n\n"
            f"[bold green]-> approve[/bold green] to execute  |  "
            f"[bold yellow]-> skip[/bold yellow] for different suggestion  |  "
            f"[dim]or type a custom command[/dim]",
            title="[bold cyan]🧠 AI Proposal[/bold cyan]",
            border_style="cyan",
        ))

    def _print_step_result(self, step: ExecutedStep) -> None:
        rc_str = "[green]✓ SUCCESS[/green]" if step.return_code == 0 else f"[red]✗ FAILED (rc={step.return_code})[/red]"

        # Output preview
        if step.stdout:
            lines = step.stdout.splitlines()
            preview = "\n".join(lines[:25])
            if len(lines) > 25:
                preview += f"\n[dim]... ({len(lines)-25} more)[/dim]"
            self.console.print(Panel(
                preview, title=f"[cyan]{step.tool}[/cyan] output | {rc_str} | {step.duration:.1f}s",
                border_style="dim",
            ))

        if step.ai_interpretation:
            self.console.rule("[bold cyan]AI Interpretation[/bold cyan]", style="cyan")
            self.console.print(Markdown(step.ai_interpretation))

        for f in step.findings_extracted:
            self._print_finding(f)

    def _print_finding(self, f: dict) -> None:
        sev = f.get("severity", "INFO")
        style, icon = SEVERITY_STYLE.get(sev, ("white", "•"))
        self.console.print(Panel(
            f"[bold white]What:[/bold white] {f.get('what', '-')}\n"
            f"[bold white]Where:[/bold white] {f.get('where', '-')}\n"
            f"[bold white]Risk:[/bold white] {f.get('risk', '-')}\n"
            f"[bold white]Action:[/bold white] {f.get('action', '-')}",
            title=f"{icon} [{style}][{sev}] {f.get('title', 'Finding')}[/{style}]",
            border_style=style.split()[-1],
        ))

    def _print_all_findings(self, findings: list[dict]) -> None:
        if not findings:
            return
        tbl = Table(title=f"Security Findings ({len(findings)} total)",
                    box=box.ROUNDED, border_style="yellow")
        tbl.add_column("#", width=4, style="dim")
        tbl.add_column("Severity", width=12)
        tbl.add_column("Finding", style="white")
        tbl.add_column("Where", style="cyan", width=30)
        tbl.add_column("Action", style="dim", width=35)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))

        for i, f in enumerate(sorted_f, 1):
            sev = f.get("severity", "INFO")
            style, icon = SEVERITY_STYLE.get(sev, ("white", "•"))
            tbl.add_row(
                str(i),
                f"{icon} [{style}]{sev}[/{style}]",
                f.get("title", ""),
                f.get("where", "")[:30],
                f.get("action", "")[:35],
            )
        self.console.print(tbl)

    def _print_intelligence(self, mission: Mission) -> None:
        tbl = Table(title="Gathered Intelligence", box=box.ROUNDED, border_style="cyan")
        tbl.add_column("Type", style="bold cyan", width=20)
        tbl.add_column("Data")
        for key, val in mission.intelligence.items():
            if isinstance(val, list):
                tbl.add_row(key.replace("_", " ").title(), ", ".join(str(v) for v in val[:30]))
            else:
                tbl.add_row(key.replace("_", " ").title(), str(val))
        self.console.print(tbl)

    def _print_mission_status(self, mission: Mission) -> None:
        crit = len(mission.critical_findings)
        self.console.print(Panel(
            f"[bold white]Target:[/bold white] [cyan]{mission.target}[/cyan]\n"
            f"[bold white]Goal:[/bold white] {mission.goal}\n"
            f"[bold white]Steps Executed:[/bold white] {len(mission.steps)}\n"
            f"[bold white]Findings:[/bold white] {len(mission.findings)} "
            f"([red]{crit} critical/high[/red])\n"
            f"[bold white]Intel Items:[/bold white] {len(mission.intelligence)}\n"
            f"[bold white]Elapsed:[/bold white] {mission.elapsed:.0f}s\n"
            f"[bold white]Status:[/bold white] "
            + ("[green]Complete[/green]" if mission.completed else "[yellow]In Progress[/yellow]"),
            title="[bold cyan]Mission Status[/bold cyan]",
            border_style="cyan",
        ))

    def _print_mission_summary(self, mission: Mission) -> None:
        self.console.rule("[bold green]✅ MISSION COMPLETE[/bold green]", style="green")
        self._print_mission_status(mission)
        if mission.findings:
            self._print_all_findings(mission.findings)
        if mission.intelligence:
            self._print_intelligence(mission)
        self.console.print(
            "[dim]Run [cyan]chain[/cyan] for attack kill chain | "
            "[cyan]report[/cyan] for full report | [cyan]save[/cyan] to export[/dim]"
        )

    def _build_markdown_report(self, mission: Mission) -> str:
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        steps_md = "\n".join(
            f"| {s.step_num} | `{s.tool}` | {s.phase} | {s.duration:.1f}s | {len(s.findings_extracted)} |"
            for s in mission.steps
        )
        findings_md = "\n\n".join(
            f"### [{f['severity']}] {f['title']}\n"
            f"- **Where**: {f.get('where', '-')}\n"
            f"- **What**: {f.get('what', '-')}\n"
            f"- **Risk**: {f.get('risk', '-')}\n"
            f"- **Action**: {f.get('action', '-')}"
            for f in sorted(mission.findings,
                            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", ""), 4))
        ) or "*No structured findings.*"
        intel_md = "\n".join(
            f"- **{k}**: {', '.join(str(v) for v in val[:20]) if isinstance(val, list) else val}"
            for k, val in mission.intelligence.items()
        ) or "*None gathered.*"

        return (
            f"# NEXUS Security Report\n\n"
            f"**Generated:** {ts}  \n"
            f"**Target:** {mission.target}  \n"
            f"**Mission:** {mission.goal}  \n"
            f"**Steps:** {len(mission.steps)}  \n"
            f"**Findings:** {len(mission.findings)}  \n"
            f"**Duration:** {mission.elapsed:.0f}s  \n\n"
            f"---\n\n"
            f"## Mission Plan\n\n"
            f"**Phases:** {' -> '.join(mission.phases)}\n\n"
            f"## Execution Log\n\n"
            f"| Step | Tool | Phase | Time | Findings |\n"
            f"|------|------|-------|------|----------|\n"
            f"{steps_md}\n\n"
            f"## Intelligence Gathered\n\n{intel_md}\n\n"
            f"## Security Findings\n\n{findings_md}\n\n"
            f"## AI Analysis Report\n\n{mission.final_report}\n\n"
            f"## Attack Kill Chain\n\n{mission.attack_chain or '*Not yet generated. Run: chain*'}\n"
        )
