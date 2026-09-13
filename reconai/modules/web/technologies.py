"""Technology Fingerprinting Module.

Uses WhatWeb adapter to identify frameworks, CMS, web servers.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.core.database.models import TechnologyRecord
from reconai.core.events.types import EventType
from reconai.integrations.whatweb import WhatWebAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class TechnologyModule(ReconModule):
    config = ModuleConfig(
        name="technologies",
        category="web",
        description="Technology fingerprinting using WhatWeb",
        requires_tools=["whatweb"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls = kwargs.get("urls", [])
        
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [record["url"] for record in url_records if record["status_code"] and record["status_code"] < 400]
            
        if not urls:
            return

        adapter = WhatWebAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("WhatWeb not available. Skipping technology fingerprinting.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        semaphore = asyncio.Semaphore(5)
        tasks = [self._fingerprint_url(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _fingerprint_url(self, adapter: WhatWebAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(url=url)
                result = await self.runner.run(command=cmd, timeout=30)
                
                techs = adapter.parse(result)
                
                for tech_dict in techs:
                    record = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=url,
                        name=tech_dict.get("name", ""),
                        version=tech_dict.get("version", ""),
                        confidence=tech_dict.get("confidence", 100.0),
                        source="whatweb"
                    )
                    self.db.insert_technology(record)
                    
                    await self.events.emit_discovery(
                        event_type=EventType.TECHNOLOGY_DETECTED,
                        source=self.config.name,
                        data={"url": url, "technology": record.name, "version": record.version},
                        scan_id=self.scan_id,
                        target=self.target
                    )
            except Exception as e:
                self.logger.debug(f"WhatWeb fingerprint failed for {url}: {e}")
