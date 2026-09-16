"""Dalfox adapter — stateless, concurrent-safe.

Fix applied (BUG 1):
  Removed self.tmp_out from build_command(). The adapter was storing the
  output file path as instance state, meaning two concurrent DalfoxModule
  calls would overwrite each other's path before parse() could read it.

  Pattern (same as NucleiAdapter fix): the MODULE creates and owns the
  temp file, passes the path via kwargs, and calls parse_output_file(path).
  The adapter itself is fully stateless.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class DalfoxAdapter(ToolAdapter):
    """Stateless Dalfox XSS scanner adapter.

    Concurrency contract:
      - build_command() does NOT mutate self.
      - parse_output_file() is a pure function of the given path.
      - Multiple concurrent calls with different paths are fully safe.
    """

    name = "dalfox"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build a Dalfox command.

        Args:
            target:      URL to scan.
            output_file: Path where Dalfox writes JSON output.
                         Created and owned by the calling module.
        """
        target: str = kwargs.get("target", "")
        output_file: Path | str = kwargs.get("output_file", "")

        cmd = ["dalfox", "url", target, "--format", "json", "--silence"]
        if output_file:
            cmd.extend(["-o", str(output_file)])
        return cmd

    def parse_output_file(self, path: Path) -> list[FindingRecord]:
        """Parse Dalfox's JSON output file.

        Each line is an independent JSON record (JSONL-like).
        Works correctly even on partial output from a timed-out scan.

        Args:
            path: Output file path given to build_command.
        """
        findings: list[FindingRecord] = []
        try:
            if not path.exists() or path.stat().st_size == 0:
                return findings

            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        data: dict[str, Any] = json.loads(line)
                        vuln_type: str = data.get("type", "")
                        url: str = data.get("data", "")

                        # Dalfox marks confirmed XSS with type containing "V" (Verified)
                        if "V" in vuln_type:
                            findings.append(
                                FindingRecord(
                                    scan_id="",  # Set by module
                                    title="Cross-Site Scripting (XSS)",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.VERIFIED,
                                    status=FindingStatus.VERIFIED,
                                    affected_asset=url,
                                    affected_asset_type="URL",
                                    description="Dalfox confirmed an XSS vulnerability.",
                                    impact="Attackers can execute arbitrary JavaScript in the victim's browser.",
                                    evidence=f"Verified payload type: {vuln_type}",
                                    remediation="Implement Context-Aware Output Encoding.",
                                    detection_method="Dalfox automated XSS scanning",
                                )
                            )
                    except json.JSONDecodeError:
                        continue

        except Exception:
            pass

        return findings

    def parse(self, result: CommandResult) -> list[Any]:
        """Required by ToolAdapter base class — not used for Dalfox.

        Dalfox writes to a file via -o; the module calls parse_output_file().
        """
        return []
