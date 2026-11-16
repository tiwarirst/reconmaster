"""NEXUS — Next-Generation AI Security Operations Platform.

The future of cybersecurity operations: a unified platform where AI and humans
collaborate in real-time, with access to the ENTIRE Kali Linux tool ecosystem.

Three Operation Modes:
━━━━━━━━━━━━━━━━━━━━
  AUTOPILOT  — AI drives everything. Define a mission, AI plans, executes,
                analyses, and delivers a full intelligence report.

  COPILOT    — Human + AI collaboration. AI suggests each next step, human
                approves or modifies before execution. AI explains reasoning.

  MANUAL+AI  — Human runs commands freely. AI watches all output in real-time,
                detects findings automatically, and provides live commentary.

Revolutionary Capabilities:
━━━━━━━━━━━━━━━━━━━━━━━━━
  ✦ Dynamic access to ALL Kali tools (not 20 — ALL)
  ✦ AI generates exact commands with optimal flags (not templates)
  ✦ Mission planner: goal → phased attack plan → execution → report
  ✦ Live output intelligence: AI reads tool output as it streams
  ✦ Cross-tool correlation: findings from 10 tools merged into one report
  ✦ Attack chain synthesis: AI builds kill-chain from findings
  ✦ Persistent memory: remembers findings across conversation turns
  ✦ Adaptive strategy: AI changes plan based on what it discovers
  ✦ Risk gating: confirm before running destructive/active tools
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator

from reconai.ai.adapter import AIAdapter
from reconai.ai.tool_discovery import KaliToolDiscovery, ToolInfo


class OperationMode(Enum):
    AUTOPILOT = "autopilot"   # AI drives everything
    COPILOT = "copilot"       # AI suggests, human approves
    MANUAL = "manual"         # Human runs, AI analyses


class MissionPhase(Enum):
    RECON = "recon"
    ENUM = "enumeration"
    VULN_SCAN = "vulnerability_scan"
    EXPLOIT = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    REPORT = "reporting"


@dataclass
class ExecutedStep:
    """One step in the NEXUS execution chain."""
    step_num: int
    tool: str
    command: list[str]
    rationale: str
    stdout: str
    stderr: str
    return_code: int
    duration: float
    ai_interpretation: str = ""
    findings_extracted: list[dict[str, Any]] = field(default_factory=list)
    phase: str = ""


@dataclass
class Mission:
    """A complete security mission with goal, phases, and accumulated intelligence."""
    goal: str
    target: str
    mode: OperationMode
    phases: list[str] = field(default_factory=list)
    steps: list[ExecutedStep] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    intelligence: dict[str, Any] = field(default_factory=dict)
    attack_chain: str = ""
    final_report: str = ""
    started_at: float = field(default_factory=time.monotonic)
    completed: bool = False

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def critical_findings(self) -> list[dict[str, Any]]:
        return [f for f in self.findings if f.get("severity") in ("CRITICAL", "HIGH")]

    def add_intelligence(self, key: str, value: Any) -> None:
        """Accumulate structured intelligence (ports, subdomains, techs, etc.)."""
        if isinstance(value, list):
            existing = self.intelligence.get(key, [])
            if isinstance(existing, list):
                # BUG-013 FIX: set() fails on unhashable types (dicts/lists); use order-preserving dedup
                combined = existing + value
                seen_ids: set = set()
                deduped = []
                for item in combined:
                    try:
                        item_id = id(item) if not isinstance(item, (str, int, float, bool)) else item
                        hashable_key = item if isinstance(item, (str, int, float, bool)) else str(item)
                        if hashable_key not in seen_ids:
                            seen_ids.add(hashable_key)
                            deduped.append(item)
                    except TypeError:
                        deduped.append(item)
                self.intelligence[key] = deduped
            else:
                self.intelligence[key] = value
        else:
            self.intelligence[key] = value


@dataclass
class ProposedStep:
    """A step proposed by AI waiting for human approval (Copilot mode)."""
    tool: str
    command: list[str]
    rationale: str
    expected_output: str
    risk_level: str
    phase: str


class NexusAgent:
    """The NEXUS AI Security Operations Agent.

    The brain of the entire platform. Interfaces between:
    - The user's natural language intent
    - The full Kali tool ecosystem (dynamically discovered)
    - The AI model (for planning, command generation, analysis)
    - Real-time streaming output from tools
    - Structured intelligence accumulation
    """

    TOOL_TIMEOUT = 120          # Default per-tool timeout
    MAX_AUTO_STEPS = 20         # Maximum steps in autopilot mode
    MAX_OUTPUT_TO_AI = 15_000   # Chars of output sent to AI for analysis

    def __init__(
        self,
        ai: AIAdapter,
        discovery: KaliToolDiscovery,
        mode: OperationMode = OperationMode.COPILOT,
        workspace: Path | None = None,
        risk_gate: bool = True,
    ) -> None:
        self.ai = ai
        self.discovery = discovery
        self.mode = mode
        self.workspace = workspace or Path.cwd() / "nexus_workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.risk_gate = risk_gate  # Require approval for critical-risk tools
        self.logger = logging.getLogger(__name__)  # BUG-033 FIX: logger needed to surface risk-gate skip events

        self._mission: Mission | None = None
        self._conversation: list[dict[str, str]] = []
        self._manual_outputs: list[dict[str, str]] = []  # for MANUAL mode

    # ── Mission Creation ──────────────────────────────────────────────────────

    async def create_mission(
        self, goal: str, target: str | None = None, mode: OperationMode | None = None
    ) -> Mission:
        """Parse a natural language goal into a structured mission."""
        if mode:
            self.mode = mode

        # Extract target if not given
        if not target:
            target = await self._extract_target(goal)

        mission = Mission(goal=goal, target=target, mode=self.mode)
        self._mission = mission

        # Plan phases
        phases = await self._plan_phases(mission)
        mission.phases = phases

        return mission

    async def _plan_phases(self, mission: Mission) -> list[str]:
        """Ask AI to create an attack phase plan for the mission."""
        tool_summary = self.discovery.get_tool_summary_for_ai()
        prompt = (
            f"You are a senior red team lead planning a security assessment.\n\n"
            f"MISSION GOAL: {mission.goal}\n"
            f"TARGET: {mission.target}\n"
            f"MODE: {mission.mode.value}\n\n"
            f"{tool_summary}\n\n"
            "Plan this assessment as ordered phases. Respond ONLY with JSON:\n"
            '{"phases": ["phase1", "phase2", ...], "estimated_steps": 5, '
            '"priority_tools": ["tool1", "tool2"], "risk_assessment": "low|medium|high"}\n\n'
            "Phase examples: passive_recon, subdomain_enum, port_scan, service_fingerprint,\n"
            "web_recon, vulnerability_scan, exploit_attempt, post_exploitation, reporting"
        )
        try:
            raw = await self.ai.analyze(prompt)
            parsed = self._json(raw)
            return parsed.get("phases", ["recon", "vuln_scan", "reporting"])
        except Exception:
            return ["recon", "vuln_scan", "reporting"]

    # ── Autopilot Mode ────────────────────────────────────────────────────────

    async def run_autopilot(
        self, mission: Mission, progress_callback=None
    ) -> Mission:
        """Fully autonomous execution. AI decides and runs everything."""
        step_num = 0

        for phase in mission.phases:
            if step_num >= self.MAX_AUTO_STEPS:
                break

            # Get next action from AI for this phase
            while step_num < self.MAX_AUTO_STEPS:
                proposed = await self._propose_next_step(mission, phase)
                if proposed is None:
                    break  # AI says phase complete

                # Risk gate for critical tools
                if self.risk_gate and proposed.risk_level == "critical":
                    if progress_callback:
                        await progress_callback("risk_gate", proposed)
                    self.logger.warning(f"[NEXUS] Risk gate: skipping critical-risk step '{proposed.tool}' in autopilot mode")  # BUG-033 FIX: log skipped steps
                    continue  # BUG-033 FIX: continue to next tool instead of break which silently exits the entire phase

                step_num += 1
                executed = await self._execute_step(proposed, step_num)
                mission.steps.append(executed)

                # AI analyses output immediately
                executed.ai_interpretation = await self._analyse_output(
                    executed, mission
                )

                # Extract intelligence & findings
                new_findings = self._extract_findings_from_text(
                    executed.ai_interpretation
                )
                mission.findings.extend(new_findings)
                executed.findings_extracted = new_findings

                self._update_intelligence(mission, executed)

                if progress_callback:
                    await progress_callback("step_complete", executed)

                # Check if AI wants to stop (e.g., found critical vuln)
                if "MISSION_COMPLETE" in executed.ai_interpretation:
                    mission.completed = True
                    break

        # Final synthesis
        mission.attack_chain = await self._build_attack_chain(mission)
        mission.final_report = await self._generate_final_report(mission)
        mission.completed = True
        return mission

    # ── Copilot Mode ──────────────────────────────────────────────────────────

    async def propose_next_step(self, mission: Mission, phase: str = "") -> ProposedStep | None:
        """Generate the next recommended step for human approval."""
        if not phase and mission.phases:
            # Determine current phase from progress
            completed = len(mission.steps)
            phase_idx = min(completed // 3, len(mission.phases) - 1)
            phase = mission.phases[phase_idx]
        return await self._propose_next_step(mission, phase)

    async def execute_approved_step(
        self, mission: Mission, proposed: ProposedStep, step_num: int
    ) -> ExecutedStep:
        """Execute a step that the human has approved."""
        executed = await self._execute_step(proposed, step_num)
        mission.steps.append(executed)
        executed.ai_interpretation = await self._analyse_output(executed, mission)
        new_findings = self._extract_findings_from_text(executed.ai_interpretation)
        mission.findings.extend(new_findings)
        executed.findings_extracted = new_findings
        self._update_intelligence(mission, executed)
        return executed

    async def execute_custom_command(
        self, mission: Mission, command_str: str, step_num: int
    ) -> ExecutedStep:
        """Execute a custom command typed by the user (manual override)."""
        parts = command_str.strip().split()
        proposed = ProposedStep(
            tool=parts[0] if parts else "shell",
            command=parts,
            rationale="User-specified command",
            expected_output="Custom command output",
            risk_level="unknown",
            phase="manual",
        )
        return await self.execute_approved_step(mission, proposed, step_num)

    # ── Manual Mode ───────────────────────────────────────────────────────────

    async def analyse_manual_output(
        self, mission: Mission, tool: str, command: str, raw_output: str
    ) -> str:
        """User ran a tool manually. AI analyses its output live."""
        self._manual_outputs.append({
            "tool": tool, "command": command, "output": raw_output
        })
        prompt = (
            f"A penetration tester ran this command manually:\n\n"
            f"Tool: {tool}\n"
            f"Command: {command}\n"
            f"Target context: {mission.target}\n"
            f"Mission goal: {mission.goal}\n\n"
            f"RAW OUTPUT:\n{raw_output[:self.MAX_OUTPUT_TO_AI].rsplit(chr(10), 1)[0]}\n\n"  # BUG-021 FIX: truncate at last newline to avoid sending malformed partial lines to AI
            "Analyse this output as a senior red team analyst:\n"
            "1. What significant findings does this reveal?\n"
            "2. What attack surface was exposed?\n"
            "3. What should the operator do NEXT based on this?\n"
            "4. Any CVEs or known vulnerabilities suggested by the output?\n\n"
            "Format findings as: ### [SEVERITY] Finding Title\n"
            "Severity: CRITICAL/HIGH/MEDIUM/LOW/INFO"
        )
        analysis = await self.ai.analyze(prompt)
        new_findings = self._extract_findings_from_text(analysis)
        mission.findings.extend(new_findings)
        self._update_intelligence_from_text(mission, raw_output, tool)
        return analysis

    # ── Core Execution Engine ─────────────────────────────────────────────────

    async def _propose_next_step(
        self, mission: Mission, phase: str
    ) -> ProposedStep | None:
        """AI generates the single best next action for the current phase."""
        tool_summary = self.discovery.get_tool_summary_for_ai(max_tools=60)
        intel_summary = self._format_intelligence(mission)
        findings_summary = self._format_findings(mission.findings[-10:])
        steps_done = "\n".join(
            f"  Step {s.step_num}: [{s.tool}] {' '.join(str(c) for c in s.command[:4])} → "
            f"{len(s.findings_extracted)} findings"
            for s in mission.steps[-5:]
        ) or "  (none yet)"

        prompt = (
            f"You are an elite red team AI. Plan the NEXT single action.\n\n"
            f"MISSION: {mission.goal}\n"
            f"TARGET: {mission.target}\n"
            f"CURRENT PHASE: {phase}\n\n"
            f"INTELLIGENCE GATHERED SO FAR:\n{intel_summary}\n\n"
            f"RECENT FINDINGS:\n{findings_summary}\n\n"
            f"STEPS ALREADY EXECUTED:\n{steps_done}\n\n"
            f"{tool_summary}\n\n"
            "Generate the SINGLE BEST next action. Respond ONLY with JSON:\n"
            "{\n"
            '  "tool": "<exact binary name>",\n'
            '  "command": ["tool", "arg1", "arg2", "..."],\n'
            '  "rationale": "<why this step now>",\n'
            '  "expected_output": "<what you expect to find>",\n'
            '  "risk_level": "low|medium|high|critical",\n'
            '  "phase": "' + phase + '",\n'
            '  "phase_complete": false\n'
            "}\n\n"
            "If this phase is complete and no more steps are needed, respond:\n"
            '{"phase_complete": true}\n\n'
            "IMPORTANT: Only use tools that are in AVAILABLE SECURITY TOOLS above.\n"
            "Generate the most impactful command with optimal flags for the target."
        )

        try:
            raw = await self.ai.analyze(prompt)
            parsed = self._json(raw)

            if parsed.get("phase_complete"):
                return None

            tool_name = parsed.get("tool", "")
            cmd_list = parsed.get("command", [])

            if not tool_name or not cmd_list:
                return None

            # Validate tool is actually available
            tool_info = self.discovery.find_tool(tool_name)
            if tool_info and not tool_info.is_available:
                # Tool not available, return None to skip
                return None

            return ProposedStep(
                tool=str(tool_name),
                command=[str(c) for c in cmd_list],
                rationale=str(parsed.get("rationale", "")),
                expected_output=str(parsed.get("expected_output", "")),
                risk_level=str(parsed.get("risk_level", "medium")),
                phase=str(parsed.get("phase", phase)),
            )
        except Exception:
            return None

    async def _execute_step(
        self, proposed: ProposedStep, step_num: int
    ) -> ExecutedStep:
        """Execute a tool command with timeout, capturing all output."""
        cmd = proposed.command
        t0 = time.monotonic()

        # Save command for logging
        cmd_str = " ".join(str(c) for c in cmd)
        log_file = self.workspace / f"step_{step_num:03d}_{proposed.tool}.log"

        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(self.workspace),
                ),
                timeout=self.TOOL_TIMEOUT,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self.TOOL_TIMEOUT
            )
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            rc = proc.returncode or 0

            # Persist raw output
            try:
                log_file.write_text(
                    f"CMD: {cmd_str}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}",
                    encoding="utf-8",
                )
            except Exception:
                pass

        except asyncio.TimeoutError:
            stdout = ""
            stderr = f"[TIMEOUT] Exceeded {self.TOOL_TIMEOUT}s"
            rc = 124
        except FileNotFoundError:
            stdout = ""
            stderr = f"[NOT FOUND] '{cmd[0]}' binary not in PATH"
            rc = 127
        except Exception as exc:
            stdout = ""
            stderr = f"[ERROR] {exc}"
            rc = 1

        return ExecutedStep(
            step_num=step_num,
            tool=proposed.tool,
            command=cmd,
            rationale=proposed.rationale,
            stdout=stdout,
            stderr=stderr,
            return_code=rc,
            duration=time.monotonic() - t0,
            phase=proposed.phase,
        )

    async def _analyse_output(
        self, step: ExecutedStep, mission: Mission
    ) -> str:
        """AI interprets tool output in context of the full mission."""
        intel = self._format_intelligence(mission)
        prompt = (
            f"You are a senior red team analyst. Interpret this tool output.\n\n"
            f"MISSION: {mission.goal}\n"
            f"TARGET: {mission.target}\n"
            f"TOOL: {step.tool}\n"
            f"COMMAND: {' '.join(str(c) for c in step.command)}\n"
            f"RATIONALE: {step.rationale}\n"
            f"DURATION: {step.duration:.1f}s | RC: {step.return_code}\n\n"
            f"ACCUMULATED INTELLIGENCE:\n{intel}\n\n"
            f"TOOL OUTPUT:\n{(step.stdout or step.stderr)[:self.MAX_OUTPUT_TO_AI].rsplit(chr(10), 1)[0]}\n\n"  # BUG-021 FIX: truncate at last newline to avoid sending malformed partial lines to AI
            "Provide:\n"
            "1. Key findings (format: ### [SEVERITY] Title with - **What/Where/Evidence/Risk/Action**)\n"
            "2. Extracted data (ports, services, subdomains, techs, credentials, etc.)\n"
            "3. What this reveals about the attack surface\n"
            "4. Recommended next step\n"
            "If mission objective fully achieved, end with: MISSION_COMPLETE"
        )
        try:
            return await self.ai.analyze(prompt)
        except Exception:
            lines = (step.stdout or step.stderr).splitlines()
            return (
                f"**Tool:** {step.tool} | **RC:** {step.return_code} | **Time:** {step.duration:.1f}s\n\n"
                + "\n".join(lines[:100])
            )

    # ── Intelligence & Findings ───────────────────────────────────────────────

    def _update_intelligence(self, mission: Mission, step: ExecutedStep) -> None:
        """Parse raw tool output and update mission intelligence."""
        self._update_intelligence_from_text(mission, step.stdout, step.tool)

    def _update_intelligence_from_text(
        self, mission: Mission, text: str, tool: str
    ) -> None:
        """Extract structured data from raw tool output."""
        if not text:
            return

        # Ports
        port_pattern = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\s+open\s+(\S+)", re.IGNORECASE)
        ports = [f"{m.group(1)}/{m.group(2)}" for m in port_pattern.finditer(text)]
        if ports:
            mission.add_intelligence("open_ports", ports)

        # Subdomains
        domain_pattern = re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}"
            + re.escape(mission.target.split(".")[-2] + "." + mission.target.split(".")[-1])
            + r"\b"
        )
        subs = list(set(m.group(0).lower() for m in domain_pattern.finditer(text)))
        if subs:
            mission.add_intelligence("subdomains", subs)

        # URLs
        url_pattern = re.compile(r"https?://[^\s\"'<>]+")
        urls = list(set(url_pattern.findall(text)))[:50]
        if urls:
            mission.add_intelligence("urls", urls)

        # CVEs
        cve_pattern = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
        cves = list(set(cve_pattern.findall(text)))
        if cves:
            mission.add_intelligence("cves_referenced", cves)

        # Technologies
        tech_patterns = {
            "Apache": r"Apache[/\s]\S+", "Nginx": r"[Nn]ginx[/\s]\S+",
            "PHP": r"PHP[/\s][\d.]+", "WordPress": r"WordPress",
            "Drupal": r"Drupal", "Node.js": r"Node\.js|Express",
            "IIS": r"Microsoft-IIS[/\s]\S+", "Tomcat": r"Apache Tomcat[/\s]\S+",
        }
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, text):
                existing = mission.intelligence.get("technologies", [])
                if tech not in existing:
                    mission.add_intelligence("technologies", [tech])

    def _extract_findings_from_text(self, text: str) -> list[dict[str, Any]]:
        """Parse structured findings from AI analysis output."""
        findings = []
        pattern = re.compile(
            r"###\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)(?=###|\Z)",
            re.DOTALL | re.IGNORECASE,
        )
        for m in pattern.finditer(text):
            severity = m.group(1).upper()
            title = m.group(2).split("\n")[0].strip()
            body = m.group(2)
            what = re.search(r"\*\*What\*\*:\s*(.+)", body)
            where = re.search(r"\*\*Where\*\*:\s*(.+)", body)
            evidence = re.search(r"\*\*Evidence\*\*:\s*(.+)", body)
            risk = re.search(r"\*\*Risk\*\*:\s*(.+)", body)
            action = re.search(r"\*\*Action\*\*:\s*(.+)", body)
            findings.append({
                "severity": severity,
                "title": title,
                "what": what.group(1).strip() if what else "",
                "where": where.group(1).strip() if where else "",
                "evidence": evidence.group(1).strip() if evidence else "",
                "risk": risk.group(1).strip() if risk else "",
                "action": action.group(1).strip() if action else "",
            })
        return findings

    def _format_intelligence(self, mission: Mission) -> str:
        intel = mission.intelligence
        if not intel:
            return "(No intelligence gathered yet)"
        lines = []
        for key, val in intel.items():
            if isinstance(val, list):
                lines.append(f"  {key}: {', '.join(str(v) for v in val[:20])}")
            else:
                lines.append(f"  {key}: {val}")
        return "\n".join(lines)

    def _format_findings(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "(No findings yet)"
        return "\n".join(
            f"  [{f['severity']}] {f['title']} — {f.get('where', '')}"
            for f in findings
        )

    # ── Final Deliverables ────────────────────────────────────────────────────

    async def _build_attack_chain(self, mission: Mission) -> str:
        """AI synthesizes all findings into a correlated attack chain."""
        if not mission.findings:
            return "Insufficient findings for attack chain construction."

        intel = self._format_intelligence(mission)
        all_findings = "\n".join(
            f"[{f['severity']}] {f['title']} | {f.get('where', '')} | {f.get('evidence', '')}"
            for f in mission.findings
        )
        prompt = (
            f"You are an elite red team lead. Build a realistic attack chain.\n\n"
            f"TARGET: {mission.target}\n"
            f"MISSION GOAL: {mission.goal}\n\n"
            f"ACCUMULATED INTELLIGENCE:\n{intel}\n\n"
            f"ALL FINDINGS:\n{all_findings}\n\n"
            "Construct a realistic, step-by-step attack kill chain showing how an adversary\n"
            "would chain these findings from ZERO ACCESS to FULL OBJECTIVE ACHIEVEMENT.\n\n"
            "Include:\n"
            "- Phase labels (Initial Access → Foothold → Escalation → Lateral Movement → Objective)\n"
            "- Specific tools and exact commands for each phase\n"
            "- MITRE ATT&CK technique IDs (T-XXXX)\n"
            "- Estimated probability of success for each step\n"
            "- Indicators of compromise (IOCs) generated\n"
            "Format as a professional red team campaign report section."
        )
        try:
            return await self.ai.analyze(prompt)
        except Exception:
            return f"Attack chain synthesis unavailable. Found {len(mission.findings)} findings."

    async def _generate_final_report(self, mission: Mission) -> str:
        """Generate the complete final intelligence report."""
        intel = self._format_intelligence(mission)
        crit = mission.critical_findings
        all_findings = "\n".join(
            f"[{f['severity']}] {f['title']}: {f.get('where', '')} — {f.get('action', '')}"
            for f in mission.findings
        )
        steps_summary = "\n".join(
            f"  Step {s.step_num}: {s.tool} ({s.duration:.1f}s, {len(s.findings_extracted)} findings)"
            for s in mission.steps
        )

        prompt = (
            f"You are a senior penetration tester writing the final engagement report.\n\n"
            f"MISSION: {mission.goal}\n"
            f"TARGET: {mission.target}\n"
            f"TOTAL STEPS: {len(mission.steps)}\n"
            f"ELAPSED: {mission.elapsed:.0f}s\n\n"
            f"INTELLIGENCE GATHERED:\n{intel}\n\n"
            f"ALL FINDINGS ({len(mission.findings)} total, {len(crit)} critical/high):\n{all_findings}\n\n"
            f"STEPS EXECUTED:\n{steps_summary}\n\n"
            "Write a professional executive + technical report with:\n"
            "# Executive Summary\n"
            "# Attack Surface Overview\n"
            "# Critical & High Findings\n"
            "# Technical Finding Details\n"
            "# Risk Scoring\n"
            "# Remediation Roadmap (priority ordered)\n"
            "# Attack Chain Summary\n\n"
            "Be specific, technical, and actionable."
        )
        try:
            return await self.ai.analyze(prompt)
        except Exception:
            return f"Report: {len(mission.findings)} findings in {mission.elapsed:.0f}s"

    # ── Chat / Ask Anything ───────────────────────────────────────────────────

    async def ask(self, question: str, mission: Mission | None = None) -> str:
        """Answer any security question, optionally grounded in mission context."""
        ctx = ""
        if mission:
            intel = self._format_intelligence(mission)
            findings = self._format_findings(mission.findings)
            ctx = (
                f"\nMISSION CONTEXT — Target: {mission.target}\n"
                f"Intelligence:\n{intel}\n"
                f"Findings:\n{findings}\n\n"
            )

        self._conversation.append({"role": "user", "content": question})
        recent_conv = self._conversation[-8:]

        prompt = (
            "You are NEXUS, an elite AI cybersecurity operations system running inside an active terminal on Kali Linux.\n"
            "You are directly connected to an automated command execution engine that executes real security tools.\n"
            "IMPORTANT RULES:\n"
            "- NEVER say you are a 'simulated environment' or that you 'cannot execute commands'. You DO execute tools in this platform.\n"
            "- When the user asks to run, test, or execute tasks, instruct them on the exact NEXUS commands to use:\n"
            "    * In AUTOPILOT mode: type 'run' to have NEXUS plan and execute tools automatically in the background.\n"
            "    * In COPILOT mode: type 'next' to get the proposed command, then type 'approve' to execute it.\n"
            "    * Directly: type 'exec <command>' (e.g. 'exec subfinder -d <target>') to run any tool immediately.\n"
            "- Be concise, tactical, and offensive-security focused.\n\n"
            + ctx
            + "CONVERSATION:\n"
            + "\n".join(f"[{m['role'].upper()}]: {m['content']}" for m in recent_conv)
        )

        try:
            response = await self.ai.analyze(prompt)
        except Exception as exc:
            response = f"Unable to answer: {exc}"

        self._conversation.append({"role": "assistant", "content": response})
        return response

    # ── Utilities ─────────────────────────────────────────────────────────────

    async def _extract_target(self, text: str) -> str:
        """Use AI to extract target from natural language."""
        try:
            raw = await self.ai.analyze(
                f"Extract the primary target (hostname/IP/URL) from this security task. "
                f"Reply with ONLY the target, nothing else:\n\n{text}"
            )
            target = raw.strip().split()[0] if raw.strip() else ""
            if target and "." in target:
                return target
        except Exception:
            pass
        # Regex fallback
        patterns = [
            r"https?://[^\s]+",
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
            r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                return m.group(0)
        return "UNKNOWN"

    def _json(self, text: str) -> dict[str, Any]:
        """Robustly extract JSON from LLM response."""
        for attempt in [
            lambda t: json.loads(t.strip()),
            lambda t: json.loads(re.search(r"```(?:json)?\s*(\{.*?\})\s*```", t, re.DOTALL).group(1)),
            lambda t: json.loads(re.search(r"\{.*?\}", t, re.DOTALL).group(0)),
        ]:
            try:
                return attempt(text)
            except Exception:
                continue
        return {}
