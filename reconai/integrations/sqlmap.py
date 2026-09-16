"""SQLMap adapter — stateless, correct detection logic.

Fixes applied:
  BUG 1 / BUG 6: Removed self.tmp_out — the temp CSV file was created but
    never read (parse() reads stdout) and never deleted, leaking disk space
    on every scan. Removed entirely.
  BUG 2: Fixed operator precedence bug in vulnerability detection.
    Original code: A or B and C  →  evaluated as  A or (B and C)
    SQLMap's real detection output uses "injectable" not "sql injection",
    so both branches were wrong. Replaced with a proper regex that matches
    SQLMap's actual stdout patterns.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


# Matches SQLMap's actual confirmation lines, e.g.:
#   "Parameter: id (GET) appears to be 'Boolean-based blind' injectable"
#   "sqlmap identified the following injection point(s)"
#   "Type: time-based blind"
_VULN_PATTERNS = re.compile(
    r"appears to be .{1,60} injectable"
    r"|sqlmap identified the following injection"
    r"|Type:\s+\w[\w\s\-]+blind"
    r"|Type:\s+Union query"
    r"|Type:\s+Error based",
    re.IGNORECASE,
)
_PAYLOAD_PATTERN = re.compile(r"Payload:\s+(.+)")


class SqlmapAdapter(ToolAdapter):
    """Stateless SQLMap adapter.

    build_command() has no side effects on self.
    parse() derives all output from the CommandResult's stdout.
    """

    name = "sqlmap"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build a SQLMap command.

        Args:
            target: URL to test (must include at least one parameter).
        """
        target: str = kwargs.get("target", "")
        return [
            "sqlmap",
            "-u", target,
            "--batch",          # Never prompt for user input
            "--quiet",
            "--level=1",
            "--risk=1",
            "--flush-session",  # Avoid stale session data from previous runs
        ]

    def parse(self, result: CommandResult, target_url: str = "") -> list[FindingRecord]:
        """Parse SQLMap stdout for confirmed vulnerabilities.

        SQLMap writes its detection status to stdout. We match on its real
        output patterns rather than naive substring checks.
        """
        findings: list[FindingRecord] = []
        if not result.has_output:
            return findings

        vulnerable = False
        payloads: list[str] = []

        for line in result.output_lines:
            if _VULN_PATTERNS.search(line):
                vulnerable = True
            m = _PAYLOAD_PATTERN.search(line)
            if m:
                payloads.append(m.group(1).strip())

        if vulnerable:
            evidence = f"Payload: {payloads[0]}" if payloads else "Vulnerability confirmed by SQLMap"
            findings.append(
                FindingRecord(
                    scan_id="",  # Set by module
                    title="SQL Injection Vulnerability",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=target_url,
                    affected_asset_type="URL",
                    description="SQLMap confirmed a SQL injection vulnerability.",
                    impact=(
                        "An attacker can read, modify, or delete database contents "
                        "and potentially achieve remote code execution."
                    ),
                    evidence=evidence,
                    remediation="Use prepared statements or parameterized queries for all database interactions.",
                    detection_method="SQLMap automated scanning",
                )
            )

        return findings
