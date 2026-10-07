"""World-Class AI Analyzer — ReconAI Offensive Intelligence Engine.

Combines:
1. Real CVE data from NVD API
2. Exploit intelligence (Exploit-DB, GitHub PoCs, CISA KEV, Metasploit)
3. AI-generated attack narratives, payloads, and PoC code
4. Attack chain correlation (how multiple findings combine into a kill chain)

This is the brain of ReconAI. Everything it produces is authoritative,
specific to the target, and immediately actionable by an offensive tester.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from reconai.ai.adapter import AIAdapter
from reconai.core.database.manager import DatabaseManager
from reconai.intelligence.cve_lookup import CVELookup, CVERecord
from reconai.intelligence.exploit_lookup import ExploitLookup, ExploitIntelligence
from reconai.intelligence.poc_generator import PoCGenerator, PoC


class Analyzer:
    """
    Central AI analysis engine.

    Provides four tiers of intelligence output:
    1. Executive Summary (business risk)
    2. Technical Finding Analysis (per-finding CVE + exploit data)
    3. Attack Chain Narrative (multi-finding kill chains)
    4. Full Offensive PoC Package (runnable scripts + payloads)
    """

    def __init__(self, ai: AIAdapter, db: DatabaseManager, scan_id: str):
        self.ai = ai
        self.db = db
        self.scan_id = scan_id
        self.cve_lookup = CVELookup()
        self.exploit_lookup = ExploitLookup()
        self.poc_gen = PoCGenerator()

    # ─────────────────────────────────────────────────────────────────────
    # 1. Executive Summary
    # ─────────────────────────────────────────────────────────────────────
    async def summarize_findings(self) -> str:
        """Generate a business-level executive summary of all findings."""
        findings = self.db.get_findings(self.scan_id)
        stats = self.db.get_scan_stats(self.scan_id)
        subdomains = self.db.get_subdomains(self.scan_id)
        ports = self.db.get_ports(self.scan_id)
        technologies = self.db.get_technologies(self.scan_id)
        cloud_assets = self.db.get_cloud_assets(self.scan_id)

        if not findings:
            # Generate Attack Surface Exposure & Intelligence Summary
            sub_sample = ", ".join([str(s["subdomain"]) for s in subdomains[:10]]) or "None discovered"
            ports_sample = ", ".join([f"{p['port']}/{p['protocol']} ({p.get('service', 'unknown')})" for p in ports[:10]]) or "None open"
            tech_sample = ", ".join([f"{t['name']} {t.get('version', '')}".strip() for t in technologies[:10]]) or "None fingerprinted"
            cloud_sample = ", ".join([f"{c['provider']} ({c['asset_name']})" for c in cloud_assets[:5]]) or "None"

            prompt = (
                "You are a Principal Cyber Security Architect reviewing an attack surface reconnaissance report for a client.\n"
                f"Target: {stats.get('target', 'Target Domain')}\n"
                f"Metrics: {stats.get('subdomains', 0)} subdomains, {stats.get('ports', 0)} open ports, "
                f"{stats.get('urls', 0)} URLs discovered, {stats.get('technologies', 0)} technologies detected, "
                f"{stats.get('cloud_assets', 0)} cloud assets.\n\n"
                f"Subdomains identified: {sub_sample}\n"
                f"Exposed ports/services: {ports_sample}\n"
                f"Detected technologies/stack: {tech_sample}\n"
                f"Cloud storage/endpoints: {cloud_sample}\n\n"
                "Write a concise, professional 3-paragraph Security Exposure Assessment:\n"
                "1. Attack Surface Overview: summary of perimeter footprint and exposed exposure.\n"
                "2. Potential Threat Vectors: reconnaissance value to attackers (what exposed services/tech reveal).\n"
                "3. Prioritized Hardening Recommendations: top 3 defensive actions to shrink the perimeter.\n"
            )
            summary = await self.ai.analyze(prompt)
            if summary:
                return summary
            return (
                f"Attack surface mapping completed for {stats.get('target', 'target')}. "
                f"Discovered {stats.get('subdomains', 0)} subdomains, {stats.get('ports', 0)} open ports, "
                f"and {stats.get('technologies', 0)} technologies. Zero direct vulnerability findings were flagged."
            )

        critical = [f for f in findings if f["severity"] == "critical"]
        high = [f for f in findings if f["severity"] == "high"]
        cves = self._extract_all_cves(findings)

        findings_text = "\n".join(
            f"[{f['severity'].upper()}] {f['title']} — {f['affected_asset']}"
            for f in sorted(findings, key=lambda x: self._severity_rank(x["severity"]))[:25]
        )

        cisa_kev_count = 0
        if cves:
            for cve_id in cves[:5]:
                intel = self.exploit_lookup.search(cve_id)
                if intel.is_in_cisa_kev:
                    cisa_kev_count += 1

        cloud_count = stats.get("cloud_assets", 0)

        prompt = (
            "You are a Principal Security Engineer writing an executive summary for a "
            "Fortune 500 client's CISO. A penetration test discovered the following:\n\n"
            f"Total Findings: {len(findings)} "
            f"(Critical: {len(critical)}, High: {len(high)})\n"
            f"CVEs Identified: {len(cves)} | "
            f"Actively Exploited in the Wild (CISA KEV): {cisa_kev_count}\n"
            f"Attack Surface: {stats.get('subdomains', 0)} subdomains, "
            f"{stats.get('ports', 0)} open ports, "
            f"{cloud_count} cloud assets (S3/GCS/Azure buckets & services)\n\n"
            f"FINDINGS:\n{findings_text}\n\n"
            "Write a 3-paragraph executive summary that:\n"
            "1. Explains the overall risk posture in business terms (no jargon)\n"
            "2. Highlights the worst-case attack scenario an attacker could achieve\n"
            "3. Provides top 3 prioritized remediation actions with business justification\n"
            "Be specific, concise, and alarming where warranted."
        )
        return await self.ai.analyze(prompt)

    # ─────────────────────────────────────────────────────────────────────
    # 2. Technical Finding Analysis (per-finding)
    # ─────────────────────────────────────────────────────────────────────
    async def analyze_finding(self, finding: dict) -> dict:
        """
        Full offensive intelligence package for a single finding.

        Returns:
        - CVE data (NVD)
        - Exploit intelligence (Exploit-DB / GitHub PoCs / Metasploit)
        - AI attack narrative
        - Runnable PoC scripts
        """
        result: dict[str, Any] = {
            "finding": finding,
            "cve_data": [],
            "exploit_intel": [],
            "poc": None,
            "ai_narrative": "",
            "attack_chain_position": "",
        }

        # Extract CVEs from finding
        cve_ids = finding.get("cve") or []
        if isinstance(cve_ids, str):
            cve_ids = re.findall(r"CVE-\d{4}-\d+", cve_ids, re.IGNORECASE)

        # Also extract from title and description
        for field in ("title", "description", "detection_method"):
            found = re.findall(r"CVE-\d{4}-\d+", finding.get(field, ""), re.IGNORECASE)
            cve_ids.extend(found)

        cve_ids = list(set(c.upper() for c in cve_ids))

        # Fetch CVE + exploit data
        cve_records = []
        exploit_records = []
        for cve_id in cve_ids[:5]:
            cve_rec = self.cve_lookup.lookup(cve_id)
            if cve_rec:
                cve_records.append(cve_rec)
                result["cve_data"].append(cve_rec.to_dict())

            exp_intel = self.exploit_lookup.search(cve_id)
            exploit_records.append(exp_intel)
            result["exploit_intel"].append({
                "cve_id": cve_id,
                "is_in_cisa_kev": exp_intel.is_in_cisa_kev,
                "kev_date": exp_intel.kev_date_added,
                "exploit_count": exp_intel.exploit_count,
                "metasploit_modules": exp_intel.metasploit_modules[:3],
                "public_exploits": [
                    {"source": e.source, "title": e.title, "url": e.url, "verified": e.verified}
                    for e in exp_intel.exploits[:5]
                ],
                "nuclei_templates": exp_intel.nuclei_templates[:3],
                "risk_summary": exp_intel.risk_summary,
            })

        # Generate PoC
        poc = self.poc_gen.generate(finding, cve_records[0].to_dict() if cve_records else {})
        result["poc"] = {
            "curl_command": poc.curl_command,
            "python_script": poc.python_script,
            "nuclei_template": poc.nuclei_template,
            "raw_http_request": poc.raw_http_request,
            "impact_description": poc.impact_description,
            "verification_steps": poc.verification_steps or [],
        }

        # AI attack narrative (enriched with real CVE context)
        cve_context = self._build_cve_context(cve_records, exploit_records)
        result["ai_narrative"] = await self._generate_attack_narrative(finding, cve_context)

        return result

    # ─────────────────────────────────────────────────────────────────────
    # 3. Attack Chain Correlation
    # ─────────────────────────────────────────────────────────────────────
    async def generate_attack_chain(self) -> str:
        """
        Correlate all findings into a realistic multi-step attack chain.
        Shows exactly how an adversary would chain findings to achieve
        maximum impact (account takeover, data exfil, full compromise).
        """
        findings = self.db.get_findings(self.scan_id)
        if len(findings) < 2:
            return "Not enough findings to construct an attack chain."

        sorted_findings = sorted(findings, key=lambda x: self._severity_rank(x["severity"]))
        stats = self.db.get_scan_stats(self.scan_id)

        findings_text = "\n".join(
            f"Step #{i+1}: [{f['severity'].upper()}] {f['title']} on {f['affected_asset']}"
            f" — {f.get('description', '')[:120]}"
            for i, f in enumerate(sorted_findings[:10])
        )

        prompt = (
            "You are a senior red team operator writing an attack chain narrative. "
            "The following vulnerabilities were discovered on a target during a "
            "penetration test. Construct a realistic, step-by-step attack chain "
            "showing how an adversary would chain these vulnerabilities to go from "
            "ZERO ACCESS to FULL COMPROMISE.\\n\\n"
            f"TARGET: {stats.get('target', 'unknown')}\\n"
            f"VULNERABILITIES DISCOVERED:\\n{findings_text}\\n\\n"
            "Format your response as:\\n"
            "## Attack Chain: [Title]\\n\\n"
            "**Starting Point**: Describe attacker's initial position\\n\\n"
            "**Phase 1 - Initial Access**: Which vuln, how used\\n"
            "**Phase 2 - Foothold**: What access is gained\\n"
            "**Phase 3 - Escalation**: How attacker expands access\\n"
            "**Phase 4 - Objective**: What attacker achieves\\n\\n"
            "**MITRE ATT&CK Techniques**: List relevant T-IDs\\n\\n"
            "Be technically precise and realistic. Name specific commands where applicable."
        )
        return await self.ai.analyze(prompt)

    # ─────────────────────────────────────────────────────────────────────
    # 4. Explain a Finding (for stakeholders)
    # ─────────────────────────────────────────────────────────────────────
    async def explain_finding(self, finding: dict) -> str:
        """Explain a finding in plain language for a non-technical stakeholder."""
        prompt = (
            f"Explain this security vulnerability to a non-technical executive:\\n"
            f"Title: {finding['title']}\\n"
            f"Severity: {finding['severity']}\\n"
            f"Asset: {finding['affected_asset']}\\n"
            f"Description: {finding.get('description', '')}\\n\\n"
            "Use an analogy. Explain: what it is, what an attacker can do, "
            "and what needs to be done to fix it. Keep it under 150 words."
        )
        return await self.ai.analyze(prompt)

    # ─────────────────────────────────────────────────────────────────────
    # 5. Full Offensive PoC Package (for a specific finding)
    # ─────────────────────────────────────────────────────────────────────
    async def generate_exploit_poc(self, finding: dict) -> str:
        """
        Generate a comprehensive offensive PoC package.
        This is the ultimate output for an offensive tester —
        everything needed to confirm and document a vulnerability.
        """
        # Get structured PoC
        poc = self.poc_gen.generate(finding)

        # Get CVE data if available
        cve_ids = finding.get("cve") or []
        cve_context_str = ""
        kev_warning = ""
        public_exploits_str = ""

        if cve_ids:
            for cve_id in cve_ids[:2]:
                cve_rec = self.cve_lookup.lookup(str(cve_id))
                exp_intel = self.exploit_lookup.search(str(cve_id))

                if cve_rec:
                    cve_context_str += (
                        f"\\n{cve_id}: CVSS {cve_rec.cvss_v3_score} [{cve_rec.cvss_severity}] "
                        f"| AV:{cve_rec.attack_vector} PR:{cve_rec.privileges_required} "
                        f"UI:{cve_rec.user_interaction}"
                    )

                if exp_intel.is_in_cisa_kev:
                    kev_warning = f"\\n!!! CISA KEV: ACTIVELY EXPLOITED IN THE WILD (Added: {exp_intel.kev_date_added}) !!!"

                if exp_intel.exploits:
                    public_exploits_str = "\\nPublic Exploits Found:\\n" + "\\n".join(
                        f"  [{e.source}] {e.title} — {e.url}"
                        for e in exp_intel.exploits[:5]
                    )

        # AI generates additional payload variants and analysis
        ai_prompt = (
            f"You are an expert red teamer. Provide an offensive exploitation analysis for:\\n"
            f"Vulnerability: {finding['title']}\\n"
            f"Target Asset: {finding['affected_asset']}\\n"
            f"Description: {finding.get('description', '')}\\n"
            f"{cve_context_str}\\n{kev_warning}\\n\\n"
            "Provide:\\n"
            "1. Advanced exploitation technique beyond the basic PoC\\n"
            "2. Three alternative payload variants for different WAF bypasses\\n"
            "3. Post-exploitation steps — what to do AFTER initial access\\n"
            "4. Out-of-band (OOB) detection technique using Burp Collaborator\\n"
            "5. CVSS scoring justification for this specific instance\\n"
            "Be precise. Output all code in markdown blocks."
        )
        ai_analysis = await self.ai.analyze(ai_prompt)

        # Compose the full package as a formatted string report
        separator = "=" * 70
        output_lines = [
            separator,
            f"  OFFENSIVE PoC PACKAGE — ReconAI",
            f"  Vulnerability: {finding['title']}",
            f"  Asset: {finding['affected_asset']}",
            f"  Severity: {finding['severity'].upper()}",
            separator,
        ]

        if kev_warning:
            output_lines.append(kev_warning)

        if cve_context_str:
            output_lines.append(f"\\nCVE Intelligence:{cve_context_str}")

        if public_exploits_str:
            output_lines.append(public_exploits_str)

        output_lines.append(f"\\n{'─'*70}")
        output_lines.append("CURL VERIFICATION COMMAND:")
        output_lines.append(poc.curl_command or "N/A")

        output_lines.append(f"\\n{'─'*70}")
        output_lines.append("RUNNABLE PYTHON PoC SCRIPT:")
        output_lines.append(poc.python_script or "N/A")

        if poc.nuclei_template:
            output_lines.append(f"\\n{'─'*70}")
            output_lines.append("NUCLEI TEMPLATE (save as custom-{finding}.yaml):")
            output_lines.append(poc.nuclei_template)

        if poc.verification_steps:
            output_lines.append(f"\\n{'─'*70}")
            output_lines.append("VERIFICATION STEPS:")
            output_lines.extend(poc.verification_steps)

        output_lines.append(f"\\n{'─'*70}")
        output_lines.append("AI ADVANCED EXPLOITATION ANALYSIS:")
        output_lines.append(ai_analysis)
        output_lines.append(separator)

        return "\\n".join(output_lines)

    # ─────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────
    async def _generate_attack_narrative(
        self, finding: dict, cve_context: str
    ) -> str:
        prompt = (
            f"You are a red team lead. Explain how to exploit this finding:\\n"
            f"Title: {finding['title']}\\n"
            f"Asset: {finding['affected_asset']}\\n"
            f"Description: {finding.get('description', '')}\\n"
            f"{cve_context}\\n\\n"
            "Provide:\\n"
            "1. Exploitation prerequisites\\n"
            "2. Step-by-step attack execution\\n"
            "3. Expected outcome and impact evidence\\n"
            "4. MITRE ATT&CK technique (T-ID)\\n"
            "Be technical and precise."
        )
        return await self.ai.analyze(prompt)

    def _build_cve_context(
        self, cve_records: list[CVERecord], exploit_records: list[ExploitIntelligence]
    ) -> str:
        if not cve_records:
            return ""
        lines = ["\\nCVE Intelligence:"]
        for cve, exp in zip(cve_records, exploit_records):
            lines.append(
                f"  {cve.cve_id}: CVSS {cve.cvss_v3_score} [{cve.cvss_severity}] "
                f"AV={cve.attack_vector} PR={cve.privileges_required}"
            )
            lines.append(f"    {cve.description[:200]}")
            if exp.is_in_cisa_kev:
                lines.append(f"    !!! ACTIVELY EXPLOITED IN THE WILD (CISA KEV {exp.kev_date_added})")
            if exp.exploits:
                lines.append(f"    Public exploits: {exp.exploit_count}")
                for e in exp.exploits[:2]:
                    lines.append(f"      - [{e.source}] {e.url}")
        return "\\n".join(lines)

    def _extract_all_cves(self, findings: list[dict]) -> list[str]:
        cves = set()
        for f in findings:
            raw = f.get("cve") or []
            if isinstance(raw, list):
                cves.update(raw)
            elif isinstance(raw, str):
                found = re.findall(r"CVE-\d{4}-\d+", raw, re.IGNORECASE)
                cves.update(found)
            for field in ("title", "description", "detection_method"):
                found = re.findall(r"CVE-\d{4}-\d+", f.get(field, ""), re.IGNORECASE)
                cves.update(found)
        return [c.upper() for c in cves]

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            severity.lower(), 5
        )
