"""Archive/Historical Reconnaissance Module.

Uses waybackurls to fetch historical URLs passively.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.integrations.waybackurls import WaybackurlsAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class ArchiveModule(ReconModule):
    config = ModuleConfig(
        name="archive_urls",
        category="passive",
        description="Discovers historical URLs via Waybackurls",
        requires_tools=["waybackurls"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = kwargs.get("domains", [])
        if not domains:
            return

        adapter = WaybackurlsAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("waybackurls not available. Skipping archive recon.", module=self.config.name)
            return

        for domain in domains:
            self.logger.module_start(self.config.name, target=domain)
            
            cmd = adapter.build_command(domain=domain)
            result = await self.runner.run(command=cmd, timeout=300)
            urls = adapter.parse(result)
            
            # Deduplicate by path/query structure
            unique_urls = set()
            for u in urls:
                parsed = urlparse(u)
                if parsed.netloc.endswith(domain):
                    unique_urls.add(u)
                    
            for u in unique_urls:
                record = URLRecord(
                    scan_id=self.scan_id,
                    url=u,
                    method="GET",
                    source="waybackurls"
                )
                self.db.insert_url(record)
                
                await self.events.emit_discovery(
                    event_type=EventType.URL_DISCOVERED,
                    source=self.config.name,
                    data={"url": u, "status": None},
                    scan_id=self.scan_id,
                    target=self.target
                )
                
            self.logger.info(f"Discovered {len(unique_urls)} historical URLs for {domain}", module=self.config.name)
            self.logger.module_complete(self.config.name)
