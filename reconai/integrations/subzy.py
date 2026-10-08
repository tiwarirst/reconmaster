"""Subzy Subdomain Takeover Adapter.

Subzy is a fast Go-based subdomain takeover scanner.
Translates JSON output from subzy into FindingRecord models.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import Confidence, FindingRecord, FindingStatus, Severity
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class SubzyAdapter(ToolAdapter):
    name = "subzy"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        targets_file: Path = kwargs["targets_file"]
        output_file: Path = kwargs["output_file"]
        concurrency: int = kwargs.get("concurrency", 20)

        return [
            "subzy",
            "run",
            "--targets", str(targets_file),
            "--concurrency", str(concurrency),
            "--output", str(output_file),
            "--hide_fails",
        ]

    def parse_output_file(self, path: Path) -> list[FindingRecord]:
        """Parse subzy JSON output containing vulnerable subdomains."""
        findings: list[FindingRecord] = []
        if not path.exists() or path.stat().st_size == 0:
            return findings

        try:
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            # subzy outputs either JSON array or line-delimited JSON
            entries = []
            if content.startswith("["):
                entries = json.loads(content)
            else:
                for line in content.splitlines():
                    if line.strip():
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            pass

            for item in entries:
                subdomain = item.get("subdomain") or item.get("target", "")
                service = item.get("service") or item.get("engine", "Cloud Service")
                status = str(item.get("status", "")).lower()

                # subzy reports "VULNERABLE" or "POTENTIAL"
                if "vulnerable" in status or item.get("vulnerable") is True:
                    sev = Severity.CRITICAL
                    conf = Confidence.CONFIRMED
                    f_status = FindingStatus.CONFIRMED
                else:
                    sev = Severity.HIGH
                    conf = Confidence.LIKELY
                    f_status = FindingStatus.POTENTIAL

                findings.append(FindingRecord(
                    scan_id="",
                    title=f"Subdomain Takeover ({service})",
                    severity=sev,
                    confidence=conf,
                    status=f_status,
                    affected_asset=subdomain,
                    affected_asset_type="subdomain",
                    description=f"Dangling DNS record pointing to unclaimed {service} resource. An attacker can register the resource and hijack the domain.",
                    impact="Full domain takeover enabling session hijacking, OAuth code theft, and phishing under trusted domain.",
                    remediation=f"Remove the dangling CNAME / DNS record or claim the {service} resource immediately.",
                    attack_class="subdomain takeover",
                    source="subzy",
                    verified=True if "vulnerable" in status else False,
                ))

        except Exception:
            pass

        return findings

    def parse(self, result: CommandResult) -> list[FindingRecord]:
        return []
