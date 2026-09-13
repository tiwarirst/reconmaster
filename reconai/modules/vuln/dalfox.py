"""Automated XSS Detection Module.

Uses Dalfox to safely test discovered parameters for XSS.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.integrations.dalfox import DalfoxAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class DalfoxModule(ReconModule):
    config = ModuleConfig(
        name="dalfox",
        category="vuln",
        description="Automated XSS detection using Dalfox",
        requires_tools=["dalfox"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        # Run on parameterized URLs
        url_records = self.db.get_urls(self.scan_id)
        urls = [r["url"] for r in url_records if "?" in r["url"] and "=" in r["url"]]
        
        if not urls:
            return

        adapter = DalfoxAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("dalfox not available. Skipping XSS scan.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} parameterized URLs")

        semaphore = asyncio.Semaphore(3)
        tasks = [self._test_xss(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _test_xss(self, adapter: DalfoxAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=url)
                result = await self.runner.run(command=cmd, timeout=60)
                
                findings = adapter.parse(result)
                
                for finding in findings:
                    finding.scan_id = self.scan_id
                    self.db.insert_finding(finding)
                        
            except Exception as e:
                self.logger.debug(f"Dalfox scan failed for {url}: {e}")
