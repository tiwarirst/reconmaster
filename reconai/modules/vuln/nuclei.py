"""Nuclei Vulnerability Scanning Module.

Uses Nuclei for template-based vulnerability scanning.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.integrations.nuclei import NucleiAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class NucleiModule(ReconModule):
    config = ModuleConfig(
        name="nuclei_vuln",
        category="vuln",
        description="Template-based vulnerability scanning using Nuclei",
        requires_tools=["nuclei"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls = kwargs.get("urls", [])
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            # Only scan root URLs or specific depths to prevent overwhelming
            urls = [r["url"] for r in url_records if r["status_code"] == 200 and r["depth"] == 0]

        if not urls:
            return

        adapter = NucleiAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("nuclei not available. Skipping vulnerability scan.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        # Nuclei handles its own concurrency, but we limit concurrent Nuclei processes
        semaphore = asyncio.Semaphore(2)
        tasks = [self._scan_url(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _scan_url(self, adapter: NucleiAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=url)
                # Nuclei can take a while, especially with full templates
                result = await self.runner.run(command=cmd, timeout=600)
                
                findings = adapter.parse(result)
                
                for finding in findings:
                    finding.scan_id = self.scan_id
                    self.db.insert_finding(finding)
                        
            except Exception as e:
                self.logger.debug(f"Nuclei scan failed for {url}: {e}")
