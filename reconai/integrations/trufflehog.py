"""TruffleHog adapter."""
from __future__ import annotations

import json
from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class TrufflehogAdapter(ToolAdapter):
    name = "trufflehog"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target = kwargs.get("target", "")
        # trufflehog github/gitlab/filesystem/etc. We'll assume scanning a URL or git repo.
        # Since we're scanning dynamically discovered URLs/files, we might use the filesystem mode
        # or git mode if it's a repository. For simplicity, we'll scan a given URL/endpoint or file.
        # However, trufflehog v3 doesn't natively crawl a single arbitrary webpage url.
        # Usually, it's used as: trufflehog git https://github.com/repo
        # Or: trufflehog filesystem /path/
        # Since we're adapting for our pipeline, if we want to scan downloaded JS files, we'd use filesystem.
        path = kwargs.get("path", "")
        
        return ["trufflehog", "filesystem", path, "--json"]

    def parse(self, result: CommandResult) -> list[FindingRecord]:
        findings = []
        if not result.has_output:
            return findings
            
        for line in result.output_lines:
            if not line.strip():
                continue
            try:
                data = json.load(line)
                detector_name = data.get("DetectorName", "Unknown Secret")
                raw = data.get("Raw", "")
                file_path = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
                
                findings.append(FindingRecord(
                    scan_id="", # Handled by module
                    title=f"Exposed Secret: {detector_name}",
                    severity=Severity.HIGH,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=file_path,
                    affected_asset_type="File",
                    description=f"TruffleHog detected a {detector_name} secret.",
                    evidence=raw[:100] + "..." if len(raw) > 100 else raw,
                    remediation="Revoke the secret immediately and remove it from the source code.",
                    detection_method="TruffleHog Secret Scanner"
                ))
            except Exception:
                pass
                
        return findings
