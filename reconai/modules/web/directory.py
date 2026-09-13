"""Directory Discovery Module.

Pure Python, asynchronous, depth-controlled directory brute-forcing.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class DirectoryDiscoveryModule(ReconModule):
    config = ModuleConfig(
        name="directory_discovery",
        category="web",
        description="Pure Python asynchronous directory brute-forcing",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls = kwargs.get("urls", [])
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [r["url"] for r in url_records if r["status_code"] == 200 and urlparse(r["url"]).path in ("", "/")]

        if not urls:
            return

        # Wordlist
        wordlist_path = kwargs.get("wordlist")
        words = []
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path) as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            # Fallback tiny wordlist if none provided (for demo/testing)
            words = ["admin", "api", "login", "test", "dev", "staging", ".git", "wp-admin", "backup"]

        if not words:
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        # Concurrency control
        semaphore = asyncio.Semaphore(self.config_mgr.get_concurrency("directory") if hasattr(self, 'config_mgr') else 10)

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10.0) as client:
            tasks = []
            for url in urls:
                base_url = url.rstrip("/")
                for word in words:
                    target_url = f"{base_url}/{word}"
                    tasks.append(self._check_dir(client, semaphore, target_url))
            
            await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _check_dir(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                response = await client.get(url)
                if response.status_code in (200, 301, 302, 401, 403):
                    record = URLRecord(
                        scan_id=self.scan_id,
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        content_length=len(response.content),
                        source="directory_discovery"
                    )
                    self.db.insert_url(record)
                    
                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": url, "status": response.status_code},
                        scan_id=self.scan_id,
                        target=self.target
                    )
            except Exception:
                pass
