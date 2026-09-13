"""Dalfox adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class DalfoxAdapter(ToolAdapter):
    name = "dalfox"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target = kwargs.get("target", "")
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        return ["dalfox", "url", target, "--format", "json", "-o", self.tmp_out.name, "--silence"]

    def parse(self, result: CommandResult) -> list[FindingRecord]:
        findings = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.load(line)
                            # Dalfox output parsing
                            vuln_type = data.get("type", "")
                            url = data.get("data", "")
                            
                            if "V" in vuln_type: # Verified
                                findings.append(FindingRecord(
                                    scan_id="",
                                    title="Cross-Site Scripting (XSS)",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.VERIFIED,
                                    status=FindingStatus.VERIFIED,
                                    affected_asset=url,
                                    affected_asset_type="URL",
                                    description="Dalfox confirmed an XSS vulnerability.",
                                    impact="Attackers can execute arbitrary JavaScript in the victim's browser.",
                                    remediation="Implement Context-Aware Output Encoding.",
                                    detection_method="Dalfox automated scanning"
                                ))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return findings
