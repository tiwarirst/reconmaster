"""ReconAI Interactive Red Team Copilot.

An interactive conversational AI assistant that allows operators to chat directly
with the AI about scan results, investigate findings, understand vulnerability mechanics,
evaluate attack depth/blast radius, and receive step-by-step verification and remediation guidance.

Grounded entirely in the target's recon database (reconai.db).
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from reconai.ai.adapter import AIAdapter
from reconai.core.correlation.engine import CorrelationEngine
from reconai.core.database.manager import DatabaseManager


class ReconCopilot:
    """Conversational AI Copilot grounded in scan data."""

    def __init__(self, db: DatabaseManager, scan_id: str, ai: AIAdapter | None = None) -> None:
        self.db = db
        self.scan_id = scan_id
        self.ai = ai
        self.history: list[dict[str, str]] = []

        # Pre-cache core recon intelligence
        self.stats = self.db.get_scan_stats(self.scan_id)
        scan = self.db.get_scan(self.scan_id) or {}
        self.target = scan.get("target") or self.stats.get("target", "Target")
        self.findings = self.db.get_findings(self.scan_id)
        self.subdomains = self.db.get_subdomains(self.scan_id)
        self.ports = self.db.get_ports(self.scan_id)
        self.technologies = self.db.get_technologies(self.scan_id)
        self.cloud_assets = self.db.get_cloud_assets(self.scan_id)
        self.correlation = CorrelationEngine(self.db, self.scan_id)
        self.attack_paths = self.correlation.find_attack_paths() if hasattr(self.correlation, "find_attack_paths") else []

        self._init_system_prompt()

    def _init_system_prompt(self) -> None:
        """Constructs the base grounding context for the LLM."""
        findings_summary = "\n".join(
            f"- Finding #{idx+1} [ID:{f.get('id')}]: [{str(f.get('severity')).upper()}] {f.get('title')} on {f.get('affected_asset')} | CVE: {f.get('cve', [])} | Method: {f.get('detection_method', 'scanner')}"
            for idx, f in enumerate(self.findings[:20])
        ) or "No security findings recorded."

        ports_summary = ", ".join(
            f"{p.get('host')}:{p.get('port')}/{p.get('protocol')} ({p.get('service', 'unknown')})"
            for p in self.ports[:15]
        ) or "None open."

        tech_summary = ", ".join(
            f"{t.get('name', '')} {t.get('version', '')}".strip()
            for t in self.technologies[:15]
        ) or "None detected."

        cloud_summary = ", ".join(
            f"[{c.get('provider', '').upper()}] {c.get('asset_name')} ({c.get('asset_type')})"
            for c in self.cloud_assets[:10]
        ) or "None discovered."

        system_instruction = (
            "You are the ReconAI Red Team Copilot, an elite offensive security analyst and advisor.\n"
            f"You are reviewing the completed reconnaissance assessment for target: '{self.target}'.\n\n"
            f"GROUND TRUTH SCAN INVENTORY:\n"
            f"- Target: {self.target}\n"
            f"- Subdomains Discovered: {self.stats.get('subdomains', len(self.subdomains))}\n"
            f"- Open Ports: {self.stats.get('ports', len(self.ports))} ({ports_summary})\n"
            f"- Technologies: {self.stats.get('technologies', len(self.technologies))} ({tech_summary})\n"
            f"- Cloud Assets: {len(self.cloud_assets)} ({cloud_summary})\n"
            f"- Total Findings: {len(self.findings)}\n\n"
            f"FINDINGS LIST:\n{findings_summary}\n\n"
            "YOUR ROLE & GUIDELINES:\n"
            "1. Answer user queries authoritatively using this real scan data.\n"
            "2. When asked about a vulnerability: explain root cause, how to safely verify it (e.g. non-destructive curl or tool commands), and potential penetration depth (what an attacker could achieve).\n"
            "3. When asked about attack depth / impact: clearly distinguish between initial foothold, lateral movement, and catastrophic compromise.\n"
            "4. Provide specific, tailored advice based on the detected software stack, ports, and assets.\n"
            "5. Keep responses structured, concise, and technically authoritative with Markdown formatting."
        )

        self.history = [{"role": "system", "content": system_instruction}]

    async def ask(self, user_query: str) -> str:
        """Processes a user question and returns the copilot response."""
        q = user_query.strip()
        if not q:
            return "Please ask a question about the target's attack surface or findings."

        # Quick local shortcut commands
        if q.lower() in ("/summary", "summary"):
            return self._quick_summary()
        elif q.lower() in ("/findings", "findings"):
            return self._quick_findings()
        elif q.lower() in ("/paths", "paths"):
            return self._quick_paths()
        elif q.lower() in ("/help", "help"):
            return self._quick_help()

        # Add user query to conversation
        self.history.append({"role": "user", "content": q})

        # If LLM is available, invoke multi-turn chat
        if self.ai and await self.ai.is_available():
            try:
                response = await self.ai.chat(self.history)
                if response:
                    self.history.append({"role": "assistant", "content": response})
                    return response
            except Exception as exc:
                pass

        # Offline fallback handler
        return self._offline_response(q)

    def _quick_summary(self) -> str:
        return (
            f"### 📊 Scan Summary for `{self.target}`\n"
            f"- **Subdomains:** {len(self.subdomains)}\n"
            f"- **Open Ports:** {len(self.ports)}\n"
            f"- **Technologies:** {len(self.technologies)}\n"
            f"- **Cloud Assets:** {len(self.cloud_assets)}\n"
            f"- **Findings:** {len(self.findings)} (Critical: {sum(1 for f in self.findings if f.get('severity') == 'critical')}, High: {sum(1 for f in self.findings if f.get('severity') == 'high')})\n"
            f"- **Attack Paths:** {len(self.attack_paths)}"
        )

    def _quick_findings(self) -> str:
        if not self.findings:
            return "No findings recorded in this scan."
        lines = [f"### 🛡️ Discovered Findings ({len(self.findings)} total):"]
        for idx, f in enumerate(self.findings, start=1):
            lines.append(f"**#{idx}** `[{str(f.get('severity')).upper()}]` **{f.get('title')}** on `{f.get('affected_asset')}`")
            if f.get("cve"):
                lines.append(f"   CVE: `{f.get('cve')}`")
        return "\n".join(lines)

    def _quick_paths(self) -> str:
        if not self.attack_paths:
            return "No multi-hop attack paths computed."
        lines = ["### ⚔️ Computed Attack Paths:"]
        for idx, p in enumerate(self.attack_paths[:5], start=1):
            nodes = " ➔ ".join([f"`{n['label']}`" for n in p.get("path_nodes", [])])
            lines.append(f"**Path #{idx}:** `[{p['severity']}]` {p['type']} via `{p['choke_point']}`\n   {nodes}")
        return "\n\n".join(lines)

    def _quick_help(self) -> str:
        return (
            "### 🤖 ReconAI Copilot Commands:\n"
            "- `/summary`: High-level scan inventory\n"
            "- `/findings`: List all vulnerabilities discovered\n"
            "- `/paths`: Display critical multi-hop attack paths\n"
            "- Or ask any question, e.g.:\n"
            "  * *'Explain finding #1 in detail and how I can verify it.'*\n"
            "  * *'Which subdomain is most vulnerable to penetration?'*\n"
            "  * *'How can an attacker pivot from the cloud bucket to the database?'*\n"
            "  * *'Give me the exact curl command to test the CORS finding.'*"
        )

    def _offline_response(self, query: str) -> str:
        """Deterministic response engine when LLM is offline."""
        q_lower = query.lower()

        # Check if user asked about a specific finding index (e.g. "finding 1", "#2", "first finding")
        match = re.search(r"finding\s*#?(\d+)", q_lower)
        if match:
            idx = int(match.group(1)) - 1
            if 0 <= idx < len(self.findings):
                f = self.findings[idx]
                return (
                    f"### Finding #{idx+1}: {f.get('title')} (Deterministic Engine)\n\n"
                    f"- **Severity:** `{str(f.get('severity')).upper()}` | **Confidence:** `{f.get('confidence', 'LIKELY')}`\n"
                    f"- **Affected Asset:** `{f.get('affected_asset')}`\n"
                    f"- **Description:** {f.get('description')}\n\n"
                    f"**Potential Attack Depth:**\n"
                    f"An attacker exploiting this vector can achieve impact on `{f.get('affected_asset')}`. "
                    f"{f.get('impact', 'Potential unauthorized disclosure or manipulation of target data.')}\n\n"
                    f"**Safe Verification:**\n"
                    f"{f.get('safe_verification') or 'Use benign test requests with custom headers or parameters to verify responsiveness without modification.'}\n\n"
                    f"**Remediation:**\n"
                    f"{f.get('remediation') or 'Update software stack and apply least-privilege access controls.'}\n\n"
                    "*(Note: Connect local or remote Ollama via `reconai chat --ai-url http://<IP>:11434` for full generative reasoning).* "
                )

        if "depth" in q_lower or "penetrat" in q_lower:
            return (
                "### 🔍 Penetration Depth Analysis (Deterministic):\n"
                f"Based on the {len(self.findings)} findings discovered on `{self.target}`:\n"
                "- **Initial Access Vectors:** Perimeter HTTP endpoints and exposed administrative services.\n"
                "- **Foothold & Lateral Movement:** Discovered cloud storage buckets and API endpoints provide opportunities to move beyond the public DMZ.\n"
                "- **Recommended Action:** Use `reconai exploit <scan_id> <finding_title>` to inspect tailored PoC verification scripts."
            )

        return (
            f"**ReconAI Copilot Grounded Response:**\n\n"
            f"I have reviewed `{self.target}` with {len(self.findings)} findings and {len(self.subdomains)} subdomains. "
            f"To get in-depth conversational answers to '{query}', connect to Ollama via:\n"
            f"`reconai chat <scan_id> --ai-url http://<GPU_IP>:11434 --ai-model <model_name>`\n\n"
            f"In offline mode, try typing `/summary`, `/findings`, or `/paths`."
        )
