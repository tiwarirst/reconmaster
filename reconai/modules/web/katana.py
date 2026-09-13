"""Advanced Web Crawling Module.

Uses Katana for deep JavaScript execution and crawling.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.katana import KatanaAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class KatanaModule(ReconModule):
    config = ModuleConfig(
        name="katana_crawler",
        category="web",
        description="Advanced headless web crawling using Katana",
        requires_tools=["katana"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls = kwargs.get("urls", [])
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [r["url"] for r in url_records if r["status_code"] == 200 and r["depth"] == 0]

        if not urls:
            return

        adapter = KatanaAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("katana not available. Skipping advanced crawling.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        semaphore = asyncio.Semaphore(3)
        tasks = [self._crawl_url(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _crawl_url(self, adapter: KatanaAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=url)
                result = await self.runner.run(command=cmd, timeout=300)
                
                url_records = adapter.parse(result)
                
                for record in url_records:
                    record.scan_id = self.scan_id
                    self.db.insert_url(record)
                    
                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": record.url, "status": record.status_code},
                        scan_id=self.scan_id,
                        target=self.target
                    )
                        
            except Exception as e:
                self.logger.debug(f"Katana crawl failed for {url}: {e}")
