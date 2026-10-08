"""AI Threat Actor & TTP Profiler.

Analyzes detected technologies, open services, and cloud environments from the
attack surface to identify relevant real-world Advanced Persistent Threat (APT)
groups, their documented Tactics, Techniques, and Procedures (TTPs), and maps
them to the MITRE ATT&CK Enterprise Matrix for adversary emulation.
"""
from __future__ import annotations

import json
from typing import Any

from reconai.ai.adapter import AIAdapter
from reconai.core.database.manager import DatabaseManager


# ── Known Threat Actor TTP Mapping Knowledgebase ──────────────────────────
_TECH_ACTOR_MAP: dict[str, list[dict[str, str]]] = {
    "wordpress": [
        {"actor": "Initial Access Brokers (IABs)", "motive": "Perimeter Foothold / Credential Theft", "technique": "T1190 - Exploit Public-Facing Application (Plugins)"},
        {"actor": "Financially Motivated Actors (Magecart)", "motive": "Web Skimming / E-commerce compromise", "technique": "T1059.007 - JavaScript Injection"},
    ],
    "aws": [
        {"actor": "Scattered Spider (UNC3944)", "motive": "Cloud Identity & Credential Hijacking", "technique": "T1078.004 - Cloud Accounts Compromise"},
        {"actor": "Lapsus$", "motive": "Infrastructure Data Extortion", "technique": "T1530 - Data from Cloud Storage Object"},
    ],
    "nginx": [
        {"actor": "APT29 (Cozy Bear)", "motive": "Espionage & Stealth Persistence", "technique": "T1190 - Exploit Public-Facing Web Server"},
    ],
    "apache": [
        {"actor": "APT28 (Fancy Bear)", "motive": "Initial Access & Command Execution", "technique": "T1190 - Exploit Known CVEs on Web Server"},
    ],
    "php": [
        {"actor": "Web Shell Operators", "motive": "Persistent Backdoor Installation", "technique": "T1505.003 - Web Shell Deployment"},
    ],
    "laravel": [
        {"actor": "Automated Exploit Bots", "motive": "RCE via Deserialization / Debug Endpoints", "technique": "T1190 - Exploitation of Debug / Ignition Endpoints"},
    ],
    "kubernetes": [
        {"actor": "Cloud Crypto-Miners", "motive": "Cluster Resource Hijacking", "technique": "T1610 - Deploy Container / Unauthenticated API"},
    ],
    "jenkins": [
        {"actor": "Lazarus Group", "motive": "Software Supply Chain Compromise", "technique": "T1195.002 - Compromise Software Supply Chain"},
    ],
}


class ThreatActorProfiler:
    """Profiles potential adversary threat groups and MITRE ATT&CK TTPs targeting the perimeter."""

    def __init__(self, db: DatabaseManager, scan_id: str, ai: AIAdapter | None = None) -> None:
        self.db = db
        self.scan_id = scan_id
        self.ai = ai

    async def generate_threat_profile(self) -> dict[str, Any]:
        """Synthesize threat actor profiles and MITRE ATT&CK mappings."""
        stats = self.db.get_scan_stats(self.scan_id)
        target = stats.get("target", "target.com")
        techs = self.db.get_technologies(self.scan_id)
        cloud_assets = self.db.get_cloud_assets(self.scan_id)
        findings = self.db.get_findings(self.scan_id)

        detected_names = [t.get("name", "").lower() for t in techs if t.get("name")]
        if cloud_assets:
            detected_names.append("aws")

        matched_actors: list[dict[str, str]] = []
        mitre_techniques: set[str] = {
            "T1596 - Search Open Technical Databases (Active Recon)",
            "T1589 - Gather Victim Identity Information (Subdomain OSINT)",
            "T1595 - Active Scanning (Port & Vulnerability Probing)",
        }

        # Deterministic threat mapping
        for tech in detected_names:
            for key, actors in _TECH_ACTOR_MAP.items():
                if key in tech:
                    for a in actors:
                        matched_actors.append(a)
                        mitre_techniques.add(a["technique"])

        # Deduplicate actors
        unique_actors = []
        seen = set()
        for a in matched_actors:
            act_name = a["actor"]
            if act_name not in seen:
                seen.add(act_name)
                unique_actors.append(a)

        if not unique_actors:
            unique_actors = [
                {"actor": "Opportunistic Threat Actors", "motive": "Automated perimeter vulnerability exploitation", "technique": "T1190 - Exploit Public-Facing Application"},
                {"actor": "Initial Access Brokers (IABs)", "motive": "Perimeter breach for resale on dark web forums", "technique": "T1078 - Valid Accounts / Weak Credentials"},
            ]
            mitre_techniques.add("T1190 - Exploit Public-Facing Application")

        # Generate Narrative via AI if available
        narrative = await self._generate_ai_narrative(target, techs, unique_actors, list(mitre_techniques))

        return {
            "target": target,
            "scan_id": self.scan_id,
            "relevant_actors": unique_actors,
            "mitre_techniques": sorted(list(mitre_techniques)),
            "narrative_markdown": narrative,
        }

    async def _generate_ai_narrative(
        self,
        target: str,
        techs: list[dict[str, Any]],
        actors: list[dict[str, str]],
        techniques: list[str],
    ) -> str:
        """Generate executive threat intelligence narrative."""
        tech_list = ", ".join([f"{t.get('name', '')} {t.get('version', '')}".strip() for t in techs[:10]]) or "Generic web stack"
        actor_list = ", ".join([a["actor"] for a in actors[:5]])
        techniques_list = "\n".join([f"- {t}" for t in techniques[:8]])

        if self.ai and await self.ai.is_available():
            prompt = (
                f"You are a Principal Cyber Threat Intelligence (CTI) Analyst.\n"
                f"Target Organization: {target}\n"
                f"Perimeter Technology Stack: {tech_list}\n"
                f"Relevant Threat Actor Groups: {actor_list}\n\n"
                "Write a 3-section Threat Actor & Adversary Emulation Profile in Markdown:\n"
                "1. **Threat Actor Threat Landscape**: Who targets this specific technology stack and why.\n"
                "2. **Adversary Emulation Strategy**: Suggested red team scenario (e.g. emulating initial access, lateral movement).\n"
                "3. **Defensive Detection & SOC Recommendations**: Top 2 log sources or monitoring triggers (e.g., Sigma rules, WAF logs).\n"
            )
            res = await self.ai.analyze(prompt)
            if res:
                return res

        # Deterministic Fallback
        return (
            f"## Threat Actor & Adversary Emulation Profile: `{target}`\n\n"
            f"**Identified Perimeter Stack:** {tech_list}\n\n"
            "### 1. Adversary Threat Landscape\n"
            f"Organizations operating this technology footprint are frequently targeted by **{actor_list}**. "
            "Primary attacker objectives focus on acquiring initial access through unpatched CVEs, configuration drift, "
            "and public cloud storage discovery.\n\n"
            "### 2. MITRE ATT&CK Matrix Alignment\n"
            f"{techniques_list}\n\n"
            "### 3. Red Team Emulation Focus\n"
            "Emulate adversary initial access techniques focusing on public-facing application vulnerabilities (T1190) "
            "and cloud credential theft (T1078.004) before expanding internal reach."
        )
