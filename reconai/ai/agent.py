"""AI Red Team Autonomous Agent.

An autonomous ReAct (Reasoning + Acting) Red Team Engine that evaluates the
entire discovered attack surface graph, identifies high-value target assets,
formulates offensive initial access and lateral movement hypotheses, and generates
an actionable Red Team Operation Plan.

Core Principles:
1. Intelligent: Thinks like an elite red team lead, not just a scanner.
2. Fast: Analyzes the graph in seconds using async primitives.
3. Fail-Safe: Always produces a structured, actionable plan even if LLM is offline.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from reconai.ai.adapter import AIAdapter
from reconai.core.correlation.engine import CorrelationEngine
from reconai.core.database.manager import DatabaseManager


class RedTeamAgent:
    """Autonomous AI Red Team Operator Agent."""

    def __init__(self, db: DatabaseManager, scan_id: str, ai: AIAdapter | None = None) -> None:
        self.db = db
        self.scan_id = scan_id
        self.ai = ai
        self.correlation = CorrelationEngine(db, scan_id)

    async def run_campaign_analysis(self) -> dict[str, Any]:
        """Execute autonomous red team attack surface reasoning and generate plan."""
        # 1. Gather all intelligence from database
        stats = self.db.get_scan_stats(self.scan_id)
        target = stats.get("target") or "target.com"
        subdomains = self.db.get_subdomains(self.scan_id)
        ports = self.db.get_ports(self.scan_id)
        technologies = self.db.get_technologies(self.scan_id)
        findings = self.db.get_findings(self.scan_id)
        cloud_assets = self.db.get_cloud_assets(self.scan_id)

        # 2. Extract graph relationships and attack paths
        graph = self.correlation.build_graph()
        attack_paths = self.correlation.find_attack_paths() if hasattr(self.correlation, "find_attack_paths") else []

        # 3. Formulate Weakest-Link Assets
        weakest_assets = self._identify_high_value_targets(subdomains, ports, technologies, findings, cloud_assets)

        # 4. Generate AI Plan or Fallback
        plan_markdown = await self._generate_ai_plan(target, stats, weakest_assets, findings, cloud_assets, attack_paths)

        return {
            "target": target,
            "scan_id": self.scan_id,
            "weakest_assets": weakest_assets,
            "plan_markdown": plan_markdown,
            "attack_paths_count": len(attack_paths),
        }

    def _identify_high_value_targets(
        self,
        subdomains: list[dict[str, Any]],
        ports: list[dict[str, Any]],
        technologies: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        cloud_assets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Heuristically ranks assets by offensive interest / exploitability."""
        ranked: list[dict[str, Any]] = []

        # Prioritize cloud assets with potential exposure
        for ca in cloud_assets:
            ranked.append({
                "asset": ca.get("asset_name"),
                "type": f"Cloud Asset ({ca.get('provider')})",
                "interest_reason": "Potential unauthorized read/write or dangling bucket takeover",
                "priority": "HIGH",
            })

        # Prioritize subdomains with dev/admin/api keywords
        sensitive_keywords = ["admin", "api", "vpn", "corp", "internal", "dev", "staging", "test", "portal", "sso"]
        for sub in subdomains:
            name = str(sub.get("subdomain", "")).lower()
            if any(k in name for k in sensitive_keywords):
                ranked.append({
                    "asset": sub.get("subdomain"),
                    "type": "Sensitive Subdomain",
                    "interest_reason": "Contains sensitive environment keywords (dev/admin/sso)",
                    "priority": "HIGH",
                })

        # Prioritize non-standard open ports (management interfaces)
        sensitive_ports = {22: "SSH", 3389: "RDP", 8080: "Proxy/App", 8443: "Alt-HTTPS", 9200: "Elasticsearch", 6379: "Redis", 1433: "MSSQL"}
        for p in ports:
            port_num = p.get("port")
            if port_num in sensitive_ports:
                ranked.append({
                    "asset": f"{p.get('host')}:{port_num}",
                    "type": f"Management Service ({sensitive_ports[port_num]})",
                    "interest_reason": f"Directly exposed administrative protocol on port {port_num}",
                    "priority": "CRITICAL" if port_num in (3389, 6379, 9200) else "HIGH",
                })

        return ranked[:10]

    async def _generate_ai_plan(
        self,
        target: str,
        stats: dict[str, Any],
        weakest_assets: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        cloud_assets: list[dict[str, Any]],
        attack_paths: list[dict[str, Any]],
    ) -> str:
        """Constructs an offensive red team operation plan via LLM or deterministic engine."""
        assets_summary = "\n".join(
            f"- [{a['priority']}] `{a['asset']}` ({a['type']}): {a['interest_reason']}"
            for a in weakest_assets[:8]
        ) or "- No critical perimeter outliers identified."

        findings_summary = "\n".join(
            f"- [{f.get('severity', '').upper()}] {f.get('title')} on `{f.get('affected_asset')}`"
            for f in findings[:6]
        ) or "- No direct vulnerability findings flagged yet."

        if self.ai and await self.ai.is_available():
            prompt = (
                f"You are a Red Team Lead planning an authorized adversary simulation against '{target}'.\n"
                f"Attack surface metrics: {stats.get('subdomains', 0)} subdomains, {stats.get('ports', 0)} ports, "
                f"{len(cloud_assets)} cloud assets, {len(findings)} candidate findings.\n\n"
                f"PRIORITIZED HIGH-VALUE ASSETS:\n{assets_summary}\n\n"
                f"CONFIRMED VULNERABILITIES:\n{findings_summary}\n\n"
                "Generate a concise, professional Red Team Campaign Plan in Markdown:\n"
                "1. **Strategic Threat Model**: Likely adversary motivation and initial entry point.\n"
                "2. **Primary Attack Vector**: Specific target asset and exploitation hypothesis.\n"
                "3. **Lateral Movement & Pivot Scenarios**: How an initial foothold could reach internal infrastructure.\n"
                "4. **MITRE ATT&CK Alignment**: List 3-4 specific T-IDs applicable to this perimeter.\n"
                "5. **Recommended Immediate Probes**: 3 concrete, safe verification actions to take next."
            )
            ai_response = await self.ai.analyze(prompt)
            if ai_response:
                return ai_response

        # Deterministic Red Team Plan Fallback
        return (
            f"# Red Team Operation Plan: {target}\n\n"
            f"**Target**: `{target}` | **Discovered Footprint**: {stats.get('subdomains', 0)} subdomains, {stats.get('ports', 0)} open ports\n\n"
            "## 1. Perimeter Threat Model\n"
            "External threat actors typically target secondary non-production environments (staging, dev) and exposed administrative interfaces "
            "as initial footholds before attempting lateral expansion toward core corporate identities.\n\n"
            "## 2. Priority Target Assets\n"
            f"{assets_summary}\n\n"
            "## 3. Recommended Red Team Actions\n"
            "- **Action 1**: Execute deep authentication and API route fuzzing against sensitive subdomains using `reconai web <target>`.\n"
            "- **Action 2**: Run non-destructive cloud bucket access validation using `reconai cloud <target>`.\n"
            "- **Action 3**: Generate runnable verification scripts for any discovered findings using `reconai exploit <scan_id> <title>`.\n\n"
            "## 4. Relevant MITRE ATT&CK Techniques\n"
            "- **T1596 (Search Open Technical Databases)**: Active reconnaissance and OSINT aggregation.\n"
            "- **T1190 (Exploit Public-Facing Application)**: Probing identified perimeter web services.\n"
            "- **T1580 (Cloud Infrastructure Discovery)**: Enumeration of multi-cloud storage and DNS records.\n"
        )
