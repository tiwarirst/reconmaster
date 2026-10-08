"""Gitleaks Secret Scanner Adapter.

Fast regex and entropy-based secret detection.
Translates Gitleaks JSON reports into FindingRecord models.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import Confidence, FindingRecord, FindingStatus, Severity
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class GitleaksAdapter(ToolAdapter):
    name = "gitleaks"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target_dir: Path = kwargs["target_dir"]
        output_file: Path = kwargs["output_file"]

        return [
            "gitleaks",
            "detect",
            "--source", str(target_dir),
            "--report-format", "json",
            "--report-path", str(output_file),
            "--no-git",
        ]

    def parse_output_file(self, path: Path) -> list[FindingRecord]:
        """Parse Gitleaks JSON output into FindingRecord objects."""
        findings: list[FindingRecord] = []
        if not path.exists() or path.stat().st_size == 0:
            return findings

        try:
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            items = json.loads(content)
            if not isinstance(items, list):
                return findings

            for item in items:
                rule_id = item.get("RuleID") or item.get("Description", "Exposed Secret")
                secret = item.get("Secret", "")
                file_path = item.get("File", "")
                start_line = item.get("StartLine", 0)

                # Redact middle of secret for safety
                redacted = secret[:4] + "*" * min(len(secret) - 6, 12) + secret[-2:] if len(secret) > 6 else "***"

                findings.append(FindingRecord(
                    scan_id="",
                    title=f"Hardcoded Secret Discovered ({rule_id})",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    status=FindingStatus.CONFIRMED,
                    affected_asset=f"{file_path}:{start_line}",
                    affected_asset_type="code",
                    description=f"Exposed credential matching rule '{rule_id}' in {file_path}. Value: {redacted}",
                    impact="Unauthorized access to external cloud resources, APIs, or developer environments.",
                    remediation="Immediately revoke and rotate the secret, and remove it from source files.",
                    evidence=f"File: {file_path}\nLine: {start_line}\nMatch: {redacted}",
                    attack_class="secret",
                    source="gitleaks",
                    verified=True,
                ))

        except Exception:
            pass

        return findings

    def parse(self, result: CommandResult) -> list[FindingRecord]:
        return []
