"""Parameter Discovery Module.

Uses ParamSpider to find URLs with parameters for injection testing.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.integrations.paramspider import ParamspiderAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class ParamspiderModule(ReconModule):
    config = ModuleConfig(
        name="paramspider",
        category="passive",
        description="Mines historical URLs for query parameters using ParamSpider",
        requires_tools=["paramspider"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = kwargs.get("domains", [])
        if not domains:
            return

        adapter = ParamspiderAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("paramspider not available. Skipping parameter discovery.", module=self.config.name)
            return

        for domain in domains:
            self.logger.module_start(self.config.name, target=domain)
            
            cmd = adapter.build_command(domain=domain)
            result = await self.runner.run(command=cmd, timeout=300)
            urls = adapter.parse(result, domain=domain)
            
            for u in urls:
                record = URLRecord(
                    scan_id=self.scan_id,
                    url=u,
                    method="GET",
                    source="paramspider"
                )
                self.db.insert_url(record)
                
                await self.events.emit_discovery(
                    event_type=EventType.URL_DISCOVERED,
                    source=self.config.name,
                    data={"url": u, "status": None},
                    scan_id=self.scan_id,
                    target=self.target
                )
                
            self.logger.info(f"Discovered {len(urls)} parameterized URLs for {domain}", module=self.config.name)
            self.logger.module_complete(self.config.name)
