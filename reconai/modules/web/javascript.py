"""JavaScript & API Analysis Module.

Extracts potential endpoints and secrets from discovered JS files and web pages.
Features zero-drop guarantee: if no JS files were discovered by prior modules,
it fetches the target root HTML, extracts <script> sources, and inspects inline scripts.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence, APIEndpoint, URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class JavaScriptAnalysisModule(ReconModule):
    config = ModuleConfig(
        name="js_analysis",
        category="web",
        description="Analyzes JS files and inline scripts for API endpoints and potential secrets",
        requires_tools=[],
        supports_timeout=True,
    )

    # Regex for endpoints (e.g., /api/v1/users)
    PATH_REGEX = re.compile(r'["\'](/(?:api|v[0-9]|users|admin|auth|graphql|v1|v2)[a-zA-Z0-9_/\-\.]*)["\']')
    # Regex for script tags in HTML
    SCRIPT_TAG_REGEX = re.compile(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
    # Regex for potential API keys/tokens
    SECRET_REGEX = re.compile(
        r'(?:api_key|access_token|secret|client_secret|auth_token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        re.IGNORECASE,
    )

    async def run(self, **kwargs: Any) -> Any:
        url_records = self.db.get_urls(self.scan_id)
        js_urls = [
            str(r["url"]) for r in url_records
            if str(r.get("url", "")).endswith(".js") or ".js?" in str(r.get("url", ""))
        ]

        start = time.monotonic()

        async with httpx.AsyncClient(
            verify=False,
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 ReconAI-JS-Analyzer/1.0"},
        ) as client:
            # Fallback if upstream crawler didn't discover .js URLs directly
            if not js_urls:
                base_urls = list(kwargs.get("urls", []))
                if not base_urls and self.target:
                    clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
                    base_urls = [f"https://{clean}", f"http://{clean}"]

                for base in base_urls[:3]:
                    try:
                        resp = await client.get(base)
                        if resp.status_code == 200:
                            # Analyze inline script content directly
                            await self._analyze_content(resp.text, base)

                            # Find script src references in HTML
                            found_scripts = self.SCRIPT_TAG_REGEX.findall(resp.text)
                            for s in found_scripts:
                                full_js = urljoin(base, s)
                                if full_js not in js_urls:
                                    js_urls.append(full_js)

                            # Check top common bundle filenames
                            for probe_js in ("/main.js", "/app.js", "/bundle.js", "/static/js/main.js"):
                                full_probe = urljoin(base, probe_js)
                                if full_probe not in js_urls:
                                    js_urls.append(full_probe)
                    except Exception:
                        pass

            if not js_urls:
                self.logger.info("No JavaScript assets available to analyze.", module=self.config.name)
                self.logger.module_complete(self.config.name, duration=time.monotonic() - start)
                return

            self.logger.module_start(self.config.name, target=f"{len(js_urls)} JS files")
            semaphore = asyncio.Semaphore(10)
            tasks = [self._analyze_js(client, semaphore, url) for url in list(dict.fromkeys(js_urls))[:35]]
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _analyze_js(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    # Save discovered JS file into DB as a URLRecord if not present
                    self.db.insert_url(URLRecord(
                        scan_id=self.scan_id,
                        url=url,
                        method="GET",
                        status_code=200,
                        content_length=len(response.content),
                        source="js_analysis",
                    ))
                    await self._analyze_content(response.text, url)
            except Exception as e:
                self.logger.debug(f"JS analysis failed for {url}: {e}")

    async def _analyze_content(self, content: str, source_asset: str) -> None:
        # Find Endpoints
        paths = self.PATH_REGEX.findall(content)
        for path in set(paths):
            record = APIEndpoint(
                scan_id=self.scan_id,
                host=source_asset,
                path=path,
                source="js_analysis",
            )
            self.db.insert_api_endpoint(record)
            await self.events.emit_discovery(
                event_type=EventType.API_DISCOVERED,
                source=self.config.name,
                data={"url": source_asset, "path": path},
                scan_id=self.scan_id,
                target=self.target,
            )

        # Find Secrets
        secrets = self.SECRET_REGEX.findall(content)
        if secrets:
            finding = FindingRecord(
                scan_id=self.scan_id,
                title="Potential Hardcoded Secret in Client-Side JavaScript",
                severity=Severity.HIGH,
                confidence=Confidence.POTENTIAL,
                status=FindingStatus.POTENTIAL,
                affected_asset=source_asset,
                affected_asset_type="JavaScript File",
                description="A string resembling an API key, client secret, or token was found hardcoded in client-side code.",
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
