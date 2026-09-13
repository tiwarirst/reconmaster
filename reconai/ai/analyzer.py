"""AI Analyzer.

Uses the AI adapter to generate intelligent summaries and explanations
for discovered findings and attack surface.
"""
from __future__ import annotations

from reconai.ai.adapter import AIAdapter
from reconai.core.database.manager import DatabaseManager


class Analyzer:
    def __init__(self, ai: AIAdapter, db: DatabaseManager, scan_id: str):
        self.ai = ai
        self.db = db
        self.scan_id = scan_id

    async def summarize_findings(self) -> str:
        """Ask the AI to summarize the key findings from the scan."""
        findings = self.db.get_findings(self.scan_id)
        if not findings:
            return "No findings to summarize."

        findings_text = "\n".join(
            f"[{f['severity'].upper()}] {f['title']} — {f['affected_asset']}"
            for f in findings[:20]
        )

        prompt = (
            "You are a cybersecurity expert. A reconnaissance scan discovered the following security issues:\n\n"
            f"{findings_text}\n\n"
            "Provide a concise executive summary (3-5 sentences) explaining the most critical risks "
            "and what an attacker could achieve. Then provide top 3 remediation priorities."
        )

        return await self.ai.analyze(prompt)

    async def explain_finding(self, finding: dict) -> str:
        """Ask the AI to explain a specific finding in plain language."""
        prompt = (
            f"Explain the following security finding to a non-technical stakeholder:\n"
            f"Title: {finding['title']}\n"
            f"Severity: {finding['severity']}\n"
            f"Affected Asset: {finding['affected_asset']}\n"
            f"Description: {finding['description']}\n\n"
            "Explain: what it is, why it matters, and what should be done to fix it. "
            "Use simple language, no jargon."
        )
        return await self.ai.analyze(prompt)
