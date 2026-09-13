"""Advanced Directory Fuzzing Module.

Uses FFuF for ultra-fast directory discovery.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.ffuf import FfufAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class FfufModule(ReconModule):
    config = ModuleConfig(
        name="ffuf_dir",
        category="web",
        description="Fast directory brute-forcing using FFuF",
        requires_tools=["ffuf"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls = kwargs.get("urls", [])
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [r["url"] for r in url_records if r["status_code"] == 200 and r["depth"] == 0]

        if not urls:
            return

        adapter = FfufAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("ffuf not available. Skipping advanced directory fuzzing.", module=self.config.name)
            return
            
        # Common wordlist on Kali
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            self.logger.error(f"Wordlist {wordlist} not found. Skipping ffuf.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        semaphore = asyncio.Semaphore(3)
        tasks = [self._fuzz_url(adapter, semaphore, url, wordlist) for url in urls]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _fuzz_url(self, adapter: FfufAdapter, semaphore: asyncio.Semaphore, url: str, wordlist: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=url, wordlist=wordlist)
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
                self.logger.debug(f"FFuF fuzzing failed for {url}: {e}")
