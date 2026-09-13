"""SQLMap adapter."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
import csv

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target = kwargs.get("target", "")
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        self.tmp_out.close()
        
        # Batch mode, minimal output, output to CSV
        return [
            "sqlmap", "-u", target, 
            "--batch", "--quiet", "--level=1", "--risk=1",
            f"--output-dir={self.tmp_out.name}_dir", # SQLmap creates a structure
            "--dump-format=CSV"
        ]

    def parse(self, result: CommandResult, target_url: str = "") -> list[FindingRecord]:
        findings = []
        # SQLMap typically outputs if it is vulnerable to stdout or specific files.
        # Since parsing SQLMap output perfectly via stdout is hard, we look for standard success strings.
        if not result.has_output:
            return findings
            
        vulnerable = False
        payloads = []
        for line in result.output_lines:
            if "is vulnerable" in line.lower() or "sql injection" in line.lower() and "appears to be" in line.lower():
                vulnerable = True
            if "Payload:" in line:
                payloads.append(line.split("Payload:")[1].strip())
                
        if vulnerable:
            findings.append(FindingRecord(
                scan_id="",
                title="SQL Injection Vulnerability",
                severity=Severity.CRITICAL,
                confidence=Confidence.VERIFIED,
                status=FindingStatus.VERIFIED,
                affected_asset=target_url,
                affected_asset_type="URL",
                description="SQLMap confirmed a SQL injection vulnerability.",
                impact="An attacker can read, modify, or delete database information, and potentially achieve RCE.",
                evidence=f"Payload used: {payloads[0] if payloads else 'Unknown'}",
                remediation="Use prepared statements or parameterized queries.",
                detection_method="SQLMap automated scanning"
            ))
                
        return findings
