"""Nuclei adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class NucleiAdapter(ToolAdapter):
    name = "nuclei"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target = kwargs.get("target", "")
        # Output JSON to a temporary file
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        # We run nuclei with default templates but quietly
        return ["nuclei", "-u", target, "-json-export", self.tmp_out.name, "-silent"]

    def parse(self, result: CommandResult) -> list[FindingRecord]:
        findings = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path, "r") as f:
                    data = json.load(f)
                    # nuclei -json-export produces an array of objects
                    if isinstance(data, list):
                        for item in data:
                            info = item.get("info", {})
                            severity_str = info.get("severity", "info").lower()
                            
                            severity_map = {
                                "critical": Severity.CRITICAL,
                                "high": Severity.HIGH,
                                "medium": Severity.MEDIUM,
                                "low": Severity.LOW,
                                "info": Severity.INFO,
                                "unknown": Severity.INFO
                            }
                            
                            severity = severity_map.get(severity_str, Severity.INFO)
                            
                            findings.append(FindingRecord(
                                scan_id="", # Handled by module
                                title=info.get("name", item.get("template-id", "Nuclei Finding")),
                                severity=severity,
                                confidence=Confidence.VERIFIED,
                                status=FindingStatus.VERIFIED,
                                affected_asset=item.get("matched-at", item.get("host", "")),
                                affected_asset_type="URL",
                                description=info.get("description", ""),
                                remediation=info.get("remediation", ""),
                                detection_method=f"Nuclei Template ({item.get('template-id')})",
                                references=info.get("reference", []),
                            ))
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return findings
