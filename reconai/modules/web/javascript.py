"""JavaScript & API Analysis Module.

Extracts potential endpoints and secrets from discovered JS files.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import httpx

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence, APIEndpoint
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class JavaScriptAnalysisModule(ReconModule):
    config = ModuleConfig(
        name="js_analysis",
        category="web",
        description="Analyzes JS files for API endpoints and potential secrets",
        supports_timeout=True,
    )

    # Regex for endpoints (e.g., /api/v1/users)
    PATH_REGEX = re.compile(r'["\'](/(?:api|v[0-9]|users|admin)[a-zA-Z0-9_/\-\.]*)["\']')
    # Regex for potential API keys/tokens (very basic for illustration)
    SECRET_REGEX = re.compile(r'(?:api_key|access_token|secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', re.IGNORECASE)

    async def run(self, **kwargs: Any) -> Any:
        url_records = self.db.get_urls(self.scan_id)
        js_urls = [
            r["url"] for r in url_records
            if r.get("url", "").endswith(".js") or ".js?" in r.get("url", "")
        ]

        if not js_urls:
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(js_urls)} JS files")

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            tasks = [self._analyze_js(client, url) for url in js_urls[:50]]
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _analyze_js(self, client: httpx.AsyncClient, url: str) -> None:
        try:
            response = await client.get(url)
            content = response.text

            # Find Endpoints
            paths = self.PATH_REGEX.findall(content)
            for path in set(paths):
                record = APIEndpoint(
                    scan_id=self.scan_id,
                    host=url,
                    path=path,
                    source="js_analysis"
                )
                self.db.insert_api_endpoint(record)
                await self.events.emit_discovery(
                    event_type=EventType.API_DISCOVERED,
                    source=self.config.name,
                    data={"url": url, "path": path},
                    scan_id=self.scan_id,
                    target=self.target
                )

            # Find Secrets
            secrets = self.SECRET_REGEX.findall(content)
            if secrets:
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title="Potential Hardcoded Secret in JavaScript",
                    severity=Severity.HIGH,
                    confidence=Confidence.POTENTIAL,
                    status=FindingStatus.POTENTIAL,
                    affected_asset=url,
                    affected_asset_type="JavaScript File",
                    description="A string resembling an API key or token was found hardcoded in a client-side script.",
                    impact="Hardcoded secrets can be extracted by any user, leading to unauthorized access.",
                    remediation="Remove the secret from client-side code and implement proper backend authentication.",
                )
                self.db.insert_finding(finding)
                await self.events.emit_discovery(
                    event_type=EventType.FINDING_DISCOVERED,
                    source=self.config.name,
                    data={
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "asset": finding.affected_asset,
                    },
                    scan_id=self.scan_id,
                    target=self.target,
                )

        except Exception as e:
            self.logger.debug(f"JS analysis failed for {url}: {e}")
