"""WAF Detection Module.

Uses wafw00f to identify Web Application Firewalls protecting the target.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from reconai.core.database.models import TechnologyRecord
from reconai.core.events.types import EventType
from reconai.integrations.wafw00f import Wafw00fAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class WafModule(ReconModule):
    config = ModuleConfig(
        name="waf_detection",
        category="web",
        description="Detects Web Application Firewalls using WafW00f",
        requires_tools=["wafw00f"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls = kwargs.get("urls", [])
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [r["url"] for r in url_records if r["status_code"] == 200 and r["depth"] == 0]

        if not urls:
            return

        adapter = Wafw00fAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("wafw00f not available. Skipping WAF detection.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        semaphore = asyncio.Semaphore(5)
        tasks = [self._detect_waf(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _detect_waf(self, adapter: Wafw00fAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=url)
                result = await self.runner.run(command=cmd, timeout=60)
                
                wafs = adapter.parse(result)
                
                for waf in wafs:
                    # Treat WAF as a technology
                    record = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=url,
                        name=waf["firewall"],
                        category="WAF",
                        confidence=100.0,
                        source="wafw00f"
                    )
                    self.db.insert_technology(record)
                    
                    await self.events.emit_discovery(
                        event_type=EventType.TECHNOLOGY_DETECTED,
                        source=self.config.name,
                        data={"url": url, "technology": record.name, "category": "WAF"},
                        scan_id=self.scan_id,
                        target=self.target
                    )
                        
            except Exception as e:
                self.logger.debug(f"WAF detection failed for {url}: {e}")
