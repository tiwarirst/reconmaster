"""WHOIS Enumeration Module.

Retrieves WHOIS information for domains to identify ownership and registration details.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class WhoisModule(ReconModule):
    config = ModuleConfig(
        name="whois",
        category="passive",
        description="Retrieves domain WHOIS registration details",
        requires_tools=["whois"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = kwargs.get("domains", [])
        if not domains:
            return

        for domain in domains:
            self.logger.module_start(self.config.name, target=domain)
            
            result = await self.runner.run(["whois", domain], timeout=20)
            if result.succeeded and result.stdout:
                # We don't store full WHOIS text in a dedicated table yet, 
                # but we log it and emit an event.
                self.logger.info(f"WHOIS data retrieved for {domain}", module=self.config.name)
                
                await self.events.emit_discovery(
                    event_type=EventType.ASSET_DISCOVERED,
                    source=self.config.name,
                    data={"type": "whois", "domain": domain, "raw": result.stdout[:500] + "..."},
                    scan_id=self.scan_id,
                    target=self.target
                )
            
            self.logger.module_complete(self.config.name)
