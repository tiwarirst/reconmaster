"""ReconAI Natural Language Shell Agent.

An autonomous AI operator that accepts plain-English security research tasks,
decomposes them into tool execution steps, runs Kali/recon tools, collects
all output, synthesizes findings, and streams results back to the user.

Architecture: ReAct loop (Reason → Act → Observe → Synthesize)

Example interactions:
  > scan example.com for open ports
  > find all subdomains of target.com
  > check if target.com is behind a WAF
  > run full recon on evil.corp
  > look for XSS on https://target.com/search?q=
  > what technologies does google.com use?
  > check for CVE-2023-44487 on 192.168.1.1
  > enumerate DNS records for example.com
  > is there any sensitive data exposed on target.com?
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reconai.ai.adapter import AIAdapter


# ── Tool Catalogue ────────────────────────────────────────────────────────────
TOOL_CATALOGUE: dict[str, dict[str, Any]] = {
    "nmap": {
        "binary": "nmap",
        "description": "Port scanner & service version detector",
        "keywords": ["port", "scan", "service", "open", "nmap", "tcp", "udp", "version"],
        "category": "port_scan",
    },
    "naabu": {
        "binary": "naabu",
        "description": "Fast SYN port scanner (ProjectDiscovery)",
        "keywords": ["fast port", "quick port", "naabu", "syn scan"],
        "category": "port_scan",
    },
    "subfinder": {
        "binary": "subfinder",
        "description": "Passive subdomain discovery",
        "keywords": ["subdomain", "subfinder", "enumerate domains", "find subdomains"],
        "category": "subdomain",
    },
    "amass": {
        "binary": "amass",
        "description": "OWASP Amass in-depth network mapping",
        "keywords": ["amass", "deep subdomain", "osint subdomain"],
        "category": "subdomain",
    },
    "httpx": {
        "binary": "httpx",
        "description": "HTTP probe & tech fingerprinter",
        "keywords": ["http", "alive", "probe", "title", "status", "technology", "tech", "web server"],
        "category": "http_probe",
    },
    "nuclei": {
        "binary": "nuclei",
        "description": "Vulnerability scanner using templates",
        "keywords": ["vulnerability", "vuln", "nuclei", "cve", "exploit", "template", "security scan"],
        "category": "vuln_scan",
    },
    "dalfox": {
        "binary": "dalfox",
        "description": "XSS parameter scanner",
        "keywords": ["xss", "cross site", "dalfox", "reflected", "stored xss"],
        "category": "vuln_scan",
    },
    "sqlmap": {
        "binary": "sqlmap",
        "description": "SQL injection scanner",
        "keywords": ["sql injection", "sqli", "sqlmap", "database", "injection"],
        "category": "vuln_scan",
    },
    "whatweb": {
        "binary": "whatweb",
        "description": "Web technology fingerprinter",
        "keywords": ["technology", "tech stack", "framework", "cms", "whatweb", "fingerprint"],
        "category": "fingerprint",
    },
    "wafw00f": {
        "binary": "wafw00f",
        "description": "WAF fingerprinting tool",
        "keywords": ["waf", "firewall", "web application firewall", "wafw00f", "cloudflare", "akamai"],
        "category": "fingerprint",
    },
    "dnsx": {
        "binary": "dnsx",
        "description": "DNS resolution & record enumeration",
        "keywords": ["dns", "resolve", "mx", "txt", "cname", "ns", "a record", "dnsx"],
        "category": "dns",
    },
    "whois": {
        "binary": "whois",
        "description": "WHOIS registration & ownership lookup",
        "keywords": ["whois", "registrar", "registration", "owner", "who owns"],
        "category": "osint",
    },
    "katana": {
        "binary": "katana",
        "description": "Web crawler & endpoint spider",
        "keywords": ["crawl", "spider", "endpoints", "links", "katana", "paths"],
        "category": "crawl",
    },
    "ffuf": {
        "binary": "ffuf",
        "description": "Web fuzzer & directory brute-forcer",
        "keywords": ["directory", "fuzz", "brute force", "hidden", "ffuf", "wordlist", "dirs"],
        "category": "fuzz",
    },
    "gau": {
        "binary": "gau",
        "description": "Get all URLs from Wayback/CommonCrawl",
        "keywords": ["wayback", "archive", "all urls", "gau", "historical"],
        "category": "osint",
    },
    "trufflehog": {
        "binary": "trufflehog",
        "description": "Secret & credential scanner",
        "keywords": ["secret", "credential", "api key", "token", "leak", "trufflehog"],
        "category": "secrets",
    },
    "subzy": {
        "binary": "subzy",
        "description": "Subdomain takeover checker",
        "keywords": ["takeover", "subdomain takeover", "subzy", "dangling"],
        "category": "vuln_scan",
    },
    "tlsx": {
        "binary": "tlsx",
        "description": "TLS certificate grabber & analyser",
        "keywords": ["tls", "ssl", "certificate", "https", "jarm", "cipher"],
        "category": "fingerprint",
    },
    "dig": {
        "binary": "dig",
        "description": "DNS query tool",
        "keywords": ["dig", "dns query", "lookup"],
        "category": "dns",
    },
    "curl": {
        "binary": "curl",
        "description": "HTTP request tool",
        "keywords": ["curl", "http request", "fetch", "get request", "post request", "header"],
        "category": "http_probe",
    },
}


@dataclass
class ToolResult:
    """Result of a single tool execution."""
    tool: str
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration: float
    available: bool = True

    @property
    def success(self) -> bool:
        return self.return_code == 0 and bool(self.stdout.strip())

    @property
    def summary(self) -> str:
        lines = [line for line in self.stdout.splitlines() if line.strip()]
        if not lines:
            return f"[{self.tool}] No output (rc={self.return_code})"
        preview = "\n".join(lines[:50])
        if len(lines) > 50:
            preview += f"\n... ({len(lines) - 50} more lines)"
        return preview


@dataclass
class AgentTask:
    """A decomposed task with target, tools, and results."""
    intent: str
    target: str
    tools_planned: list[str] = field(default_factory=list)
    results: list[ToolResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    ai_synthesis: str = ""
    elapsed: float = 0.0


class NaturalLanguageShellAgent:
    """Autonomous AI operator: plain English -> Kali tools -> structured findings.

    ReAct loop:
      1. REASON  - parse user intent, identify target, plan tools
      2. ACT     - execute tools (with timeouts & error isolation)
      3. OBSERVE - collect raw output from all tools
      4. SYNTHESIZE - LLM produces structured findings from raw output
    """

    DEFAULT_TIMEOUT = 60
    MAX_OUTPUT_CHARS = 20_000

    def __init__(
        self,
        ai: AIAdapter,
        workspace_dir: Path | None = None,
        verbose: bool = False,
    ) -> None:
        self.ai = ai
        self.workspace = workspace_dir or Path.cwd() / "agent_workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self._history: list[dict[str, str]] = []
        self._available_tools: dict[str, bool] = {}
        self._detect_available_tools()

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self, user_input: str) -> AgentTask:
        """Process a plain-English task and return structured results."""
        # BUG-020 FIX: allow operator to refresh tool detection without restarting the agent
        if user_input.strip().lower() in ("/refresh", "refresh tools"):
            self._detect_available_tools()
            return AgentTask(
                intent="Refresh tool detection",
                target="localhost",
                ai_synthesis="🔄 Tool list refreshed. Re-detected available Kali tools.",
            )

        t0 = time.monotonic()

        # Step 1: REASON
        task = await self._parse_intent(user_input)

        # Step 2: ACT
        for tool_name in task.tools_planned:
            result = await self._execute_tool(tool_name, task.target, user_input)
            task.results.append(result)

        # Step 3: SYNTHESIZE
        task.ai_synthesis = await self._synthesize(task)
        task.findings = self._extract_findings(task.ai_synthesis)
        task.elapsed = time.monotonic() - t0

        self._history.append({"role": "user", "content": user_input})
        self._history.append({"role": "assistant", "content": task.ai_synthesis})

        return task

    def get_available_tools(self) -> list[str]:
        return [t for t, avail in self._available_tools.items() if avail]

    def get_missing_tools(self) -> list[str]:
        return [t for t, avail in self._available_tools.items() if not avail]

    def clear_history(self) -> None:
        self._history.clear()

    def _format_history(self, turns: int = 4) -> str:
        """Format recent conversation turns for context in intent parsing."""
        if not self._history:
            return "None"
        recent = self._history[-(turns * 2):]
        lines: list[str] = []
        for msg in recent:
            role = msg.get("role", "user").upper()
            content = msg.get("content", "").strip()
            if len(content) > 300:
                content = content[:300] + "..."
            lines.append(f"[{role}]: {content}")
        return "\n".join(lines) if lines else "None"

    # ── Step 1: Intent Parsing ────────────────────────────────────────────────

    async def _parse_intent(self, user_input: str) -> AgentTask:
        available = ", ".join(self.get_available_tools()) or "none detected"

        tool_descriptions = "\n".join(
            f"  - {name}: {info['description']} (keywords: {', '.join(info['keywords'][:4])})"
            for name, info in TOOL_CATALOGUE.items()
        )

        plan_prompt = (
            "You are an expert penetration tester and security tool orchestrator.\n"
            f"A user has given you this task in plain English:\n\n"
            f"USER TASK: {user_input}\n\n"
            f"CONVERSATION HISTORY (last 4 turns):\n{self._format_history(4)}\n\n"
            f"AVAILABLE TOOLS ON THIS SYSTEM:\n{available}\n\n"
            f"TOOL CATALOGUE:\n{tool_descriptions}\n\n"
            "Your job: Extract the primary TARGET and select the best 1-5 tools from the\n"
            "AVAILABLE TOOLS list that would accomplish this task.\n\n"
            "Respond ONLY with valid JSON in exactly this format:\n"
            '{"target": "<hostname, IP, or URL>", "intent_summary": "<one sentence>", '
            '"tools": ["tool1", "tool2"], "reason": "<brief explanation>"}\n\n'
            "Rules:\n"
            "- Only select tools from the AVAILABLE TOOLS list.\n"
            "- If no target can be identified, set target to UNKNOWN.\n"
            "- For port scanning: use nmap or naabu.\n"
            "- For subdomains: use subfinder or amass.\n"
            "- For vulns: use nuclei. For XSS: dalfox. For SQLi: sqlmap.\n"
            "- For web: httpx, katana, whatweb. For DNS: dnsx or dig.\n"
            "- Respond with ONLY the JSON object, no other text."
        )

        try:
            raw = await self.ai.analyze(plan_prompt)
            parsed = self._extract_json(raw)
            target = str(parsed.get("target", "UNKNOWN")).strip()
            tools_raw = parsed.get("tools", [])
            tools = [
                t for t in tools_raw
                if t in TOOL_CATALOGUE and self._available_tools.get(t, False)
            ]
            intent = str(parsed.get("intent_summary", user_input))
        except Exception:
            target = self._extract_target_fallback(user_input)
            tools = self._select_tools_by_keywords(user_input)
            intent = user_input

        return AgentTask(
            intent=intent,
            target=target,
            tools_planned=tools[:5],
        )

    # ── Step 2: Tool Execution ────────────────────────────────────────────────

    async def _execute_tool(
        self, tool_name: str, target: str, user_input: str
    ) -> ToolResult:
        if target == "UNKNOWN" or not target:
            return ToolResult(
                tool=tool_name, command="", stdout="", stderr="No target identified.",
                return_code=1, duration=0, available=False,
            )

        cmd = self._build_command(tool_name, target, user_input)
        if not cmd:
            return ToolResult(
                tool=tool_name, command="", stdout="", stderr="Could not build command.",
                return_code=1, duration=0, available=False,
            )

        t0 = time.monotonic()
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=self.DEFAULT_TIMEOUT,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self.DEFAULT_TIMEOUT
            )
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            rc = proc.returncode or 0
        except asyncio.TimeoutError:
            stdout = ""
            stderr = f"[TIMEOUT] Tool '{tool_name}' exceeded {self.DEFAULT_TIMEOUT}s limit."
            rc = 124
        except FileNotFoundError:
            stdout = ""
            stderr = f"[NOT FOUND] Binary '{tool_name}' not in PATH."
            rc = 127
        except Exception as exc:
            stdout = ""
            stderr = f"[ERROR] {exc}"
            rc = 1

        duration = time.monotonic() - t0
        return ToolResult(
            tool=tool_name,
            command=" ".join(str(c) for c in cmd),
            stdout=stdout[:self.MAX_OUTPUT_CHARS],
            stderr=stderr[:2000],
            return_code=rc,
            duration=duration,
        )

    def _build_command(
        self, tool_name: str, target: str, user_input: str
    ) -> list[str] | None:
        u = user_input.lower()
        bare_target = re.sub(r"^https?://", "", target).rstrip("/")
        url_target = target if target.startswith("http") else f"http://{target}"

        builders: dict[str, list[str]] = {
            "nmap": ["nmap", "-sV", "-T4", "--open", "-Pn", bare_target],
            "naabu": ["naabu", "-host", bare_target, "-top-ports", "1000", "-silent"],
            "subfinder": ["subfinder", "-d", bare_target, "-silent"],
            "amass": ["amass", "enum", "-passive", "-d", bare_target],
            "httpx": ["httpx", "-u", url_target, "-title", "-tech-detect",
                      "-status-code", "-follow-redirects", "-silent"],
            "nuclei": ["nuclei", "-u", url_target, "-severity",
                       "info,low,medium,high,critical", "-silent", "-no-color"],
            "dalfox": ["dalfox", "url", url_target, "--silence"],
            "sqlmap": ["sqlmap", "-u", url_target, "--batch",
                       "--level=1", "--risk=1"],
            "whatweb": ["whatweb", url_target, "--color=never"],
            "wafw00f": ["wafw00f", url_target, "-a"],
            "dnsx": ["dnsx", "-d", bare_target, "-resp", "-a", "-mx", "-ns", "-txt", "-silent"],
            "whois": ["whois", bare_target],
            "katana": ["katana", "-u", url_target, "-depth", "2", "-silent"],
            "ffuf": self._build_ffuf(url_target),
            "gau": ["gau", bare_target],
            "trufflehog": ["trufflehog", "filesystem", ".", "--no-verification", "--json"],
            "subzy": ["subzy", "run", "--targets", bare_target, "--hide_fails"],
            "tlsx": ["tlsx", "-u", bare_target, "-san", "-cn", "-silent"],
            "dig": ["dig", "+short", "ANY", bare_target],
            "curl": ["curl", "-sI", "-L", "--max-time", "15", url_target],
        }

        # Contextual overrides
        if tool_name == "nmap":
            if any(w in u for w in ["full", "all ports", "65535"]):
                return ["nmap", "-sV", "-T3", "-p-", "--open", "-Pn", bare_target]
            if any(w in u for w in ["quick", "fast", "top"]):
                return ["nmap", "-sV", "-T4", "--top-ports", "100", "--open", "-Pn", bare_target]
            if "udp" in u:
                return ["nmap", "-sU", "-T3", "--top-ports", "100", "-Pn", bare_target]

        if tool_name == "nuclei":
            cve_match = re.search(r"(cve-\d{4}-\d+)", u)
            if cve_match:
                return ["nuclei", "-u", url_target, "-id", cve_match.group(1),
                        "-silent", "-no-color"]
            if any(w in u for w in ["critical", "high"]):
                return ["nuclei", "-u", url_target, "-severity", "critical,high",
                        "-silent", "-no-color"]
            if "xss" in u:
                return ["nuclei", "-u", url_target, "-tags", "xss", "-silent", "-no-color"]
            if any(w in u for w in ["sqli", "sql injection"]):
                return ["nuclei", "-u", url_target, "-tags", "sqli", "-silent", "-no-color"]

        return builders.get(tool_name)

    def _build_ffuf(self, url_target: str) -> list[str]:
        wordlists = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        wl = next((w for w in wordlists if Path(w).exists()), None)
        if not wl:
            return []
        return ["ffuf", "-u", url_target.rstrip("/") + "/FUZZ", "-w", wl,
                "-mc", "200,204,301,302,307,401,403", "-silent"]

    # ── Step 3: Synthesis ─────────────────────────────────────────────────────

    async def _synthesize(self, task: AgentTask) -> str:
        if not task.results:
            return (
                "No tools were executed. Could not identify target or available tools.\n"
                "Try being more specific, e.g.: 'scan example.com for open ports'"
            )

        raw_outputs = []
        for r in task.results:
            status = "SUCCESS" if r.success else f"FAILED (rc={r.return_code})"
            raw_outputs.append(
                f"=== TOOL: {r.tool} | Status: {status} | Time: {r.duration:.1f}s ===\n"
                f"Command: {r.command}\n"
                f"Output:\n{r.stdout[:8000] or '(no output)'}\n"
                + (f"Stderr: {r.stderr[:500]}\n" if r.stderr.strip() else "")
            )

        combined = "\n\n".join(raw_outputs)

        synthesis_prompt = (
            "You are a senior red team security analyst. You have executed the following\n"
            "reconnaissance and vulnerability scanning task:\n\n"
            f"ORIGINAL REQUEST: {task.intent}\n"
            f"TARGET: {task.target}\n\n"
            "RAW TOOL OUTPUT:\n"
            "=" * 60 + "\n"
            f"{combined}\n"
            "=" * 60 + "\n\n"
            "Synthesize the raw output into a professional security analyst report.\n"
            "Format your response EXACTLY as:\n\n"
            "## Task Summary\n"
            "[What was done, which tools ran, how long]\n\n"
            "## Findings\n"
            "For each finding:\n"
            "### [SEVERITY] Finding Title\n"
            "- **What**: What was found\n"
            "- **Where**: Specific host/port/URL\n"
            "- **Evidence**: Exact output snippet\n"
            "- **Risk**: What an attacker could do\n"
            "- **Action**: Recommended fix\n\n"
            "## Raw Intelligence\n"
            "[Key data: open ports, subdomains, URLs, technologies, DNS records as bullets]\n\n"
            "## Attack Surface Summary\n"
            "[Overall attack surface and priority areas]\n\n"
            "## Next Steps\n"
            "[Specific follow-up commands to run next]\n\n"
            "Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO\n"
            "Be precise. Include exact port numbers, version strings, CVE IDs where found."
        )

        try:
            return await self.ai.analyze(synthesis_prompt)
        except Exception as exc:
            return self._offline_synthesis(task, str(exc))

    def _offline_synthesis(self, task: AgentTask, error: str = "") -> str:
        lines = [
            f"## Task: {task.intent}",
            f"**Target:** {task.target}",
            f"**Tools:** {', '.join(r.tool for r in task.results)}",
            "",
        ]
        if error:
            lines.append(f"> AI synthesis unavailable: `{error}`. Showing raw output.\n")
        for r in task.results:
            lines.append(f"### [{r.tool}] {'OK' if r.success else 'FAILED'} ({r.duration:.1f}s)")
            lines.append(f"```\n{r.stdout[:3000] or r.stderr or '(no output)'}\n```\n")
        return "\n".join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detect_available_tools(self) -> None:
        for name in TOOL_CATALOGUE:
            self._available_tools[name] = bool(shutil.which(name))

    def _extract_target_fallback(self, text: str) -> str:
        url_match = re.search(r"https?://[^\s]+", text)
        if url_match:
            return url_match.group(0)
        domain_match = re.search(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", text
        )
        if domain_match:
            return domain_match.group(0)
        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        if ip_match:
            return ip_match.group(0)
        return "UNKNOWN"

    def _select_tools_by_keywords(self, text: str) -> list[str]:
        text_lower = text.lower()
        scored: list[tuple[int, str]] = []
        for name, info in TOOL_CATALOGUE.items():
            if not self._available_tools.get(name):
                continue
            score = sum(1 for kw in info["keywords"] if kw in text_lower)
            if score > 0:
                scored.append((score, name))
        scored.sort(reverse=True)
        return [name for _, name in scored[:4]]

    def _extract_json(self, text: str) -> dict[str, Any]:
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        m2 = re.search(r"\{.*?\}", text, re.DOTALL)
        if m2:
            try:
                return json.loads(m2.group(0))
            except json.JSONDecodeError:
                pass
        return {}

    def _extract_findings(self, synthesis: str) -> list[dict[str, Any]]:
        findings = []
        pattern = re.compile(
            r"###\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)(?=###|\Z)",
            re.DOTALL | re.IGNORECASE,
        )
        for m in pattern.finditer(synthesis):
            severity = m.group(1).upper()
            title = m.group(2).split("\n")[0].strip()
            body = m.group(2)
            what = re.search(r"\*\*What\*\*:\s*(.+)", body)
            where = re.search(r"\*\*Where\*\*:\s*(.+)", body)
            risk = re.search(r"\*\*Risk\*\*:\s*(.+)", body)
            action = re.search(r"\*\*Action\*\*:\s*(.+)", body)
            findings.append({
                "severity": severity,
                "title": title,
                "what": what.group(1).strip() if what else "",
                "where": where.group(1).strip() if where else "",
                "risk": risk.group(1).strip() if risk else "",
                "action": action.group(1).strip() if action else "",
            })
        return findings
