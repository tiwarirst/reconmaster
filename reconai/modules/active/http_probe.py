"""HTTP Probing Module.

Quickly checks if discovered subdomains have active web services.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class HTTPProbeModule(ReconModule):
    config = ModuleConfig(
        name="http_probe",
        category="active",
        description="Lightweight HTTP/HTTPS probing of discovered hosts",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        hosts = kwargs.get("hosts", [])
        if not hosts:
            # If no hosts provided directly, fetch all subdomains from DB
            subs = self.db.get_subdomains(self.scan_id)
            hosts = [s["subdomain"] for s in subs]
            
        if not hosts:
            return

        self.logger.module_start(self.config.name, target=f"{len(hosts)} hosts")
        
        # Concurrency limit
        semaphore = asyncio.Semaphore(20)
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10.0) as client:
            tasks = [self._probe_host(client, semaphore, host) for host in hosts]
            await asyncio.gather(*tasks)
            
        self.logger.module_complete(self.config.name)

    async def _probe_host(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, host: str) -> None:
        async with semaphore:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{host}"
                try:
                    response = await client.get(url)
                    
                    # Extract title
                    title = ""
                    if "<title>" in response.text.lower():
                        import re
                        match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL)
                        if match:
                            title = match.group(1).strip()
                            
                    record = URLRecord(
                        scan_id=self.scan_id,
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type", ""),
                        content_length=len(response.content),
                        title=title,
                        redirect_url=response.headers.get("location", ""),
                        source="http_probe"
                    )
                    self.db.insert_url(record)
                    
                    # Emit URL discovered
                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": url, "status": response.status_code, "title": title},
                        scan_id=self.scan_id,
                        target=self.target
                    )
                    
                except httpx.RequestError:
                    pass
                except Exception as e:
                    self.logger.debug(f"HTTP probe error for {url}: {e}")
