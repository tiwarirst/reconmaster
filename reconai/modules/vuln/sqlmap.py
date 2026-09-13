"""Automated SQL Injection Detection Module.

Uses SQLMap to safely test discovered parameters for SQLi.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.integrations.sqlmap import SqlmapAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SqlmapModule(ReconModule):
    config = ModuleConfig(
        name="sqlmap",
        category="vuln",
        description="Automated SQL Injection detection using SQLMap",
        requires_tools=["sqlmap"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        # Only run on URLs that actually have parameters
        url_records = self.db.get_urls(self.scan_id)
        urls = [r["url"] for r in url_records if "?" in r["url"] and "=" in r["url"]]
        
        if not urls:
            return

        adapter = SqlmapAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("sqlmap not available. Skipping SQLi scan.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} parameterized URLs")

        # SQLMap is heavy, limit concurrency
        semaphore = asyncio.Semaphore(1)
        tasks = [self._test_sqli(adapter, semaphore, url) for url in urls[:10]] # Safety limit
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _test_sqli(self, adapter: SqlmapAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=url)
                result = await self.runner.run(command=cmd, timeout=300)
                
                findings = adapter.parse(result, target_url=url)
                
                for finding in findings:
                    finding.scan_id = self.scan_id
                    self.db.insert_finding(finding)
                        
            except Exception as e:
                self.logger.debug(f"SQLMap scan failed for {url}: {e}")
