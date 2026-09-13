"""Web crawler module.

Lightweight spider to discover paths, parameters, and JavaScript files.
Uses httpx and beautifulsoup4.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class CrawlerModule(ReconModule):
    config = ModuleConfig(
        name="crawler",
        category="web",
        description="Lightweight web spider to discover links, forms, and scripts",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        start_urls = kwargs.get("urls", [])
        
        if not start_urls:
            url_records = self.db.get_urls(self.scan_id)
            # Only start crawling from root paths that returned 200
            start_urls = [r["url"] for r in url_records if r["status_code"] == 200 and urlparse(r["url"]).path in ("", "/")]

        if not start_urls:
            return

        self.logger.module_start(self.config.name, target=f"{len(start_urls)} root URLs")

        # Config limits
        max_depth = 2
        max_pages = 50

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            tasks = [self._crawl(client, start_url, max_depth, max_pages) for start_url in start_urls]
            await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _crawl(self, client: httpx.AsyncClient, start_url: str, max_depth: int, max_pages: int) -> None:
        visited = set()
        queue = [(start_url, 0)]
        start_domain = urlparse(start_url).netloc

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            
            if url in visited or depth > max_depth:
                continue
                
            visited.add(url)
            
            try:
                response = await client.get(url)
                if response.status_code >= 400:
                    continue
                    
                content_type = response.headers.get("content-type", "")
                
                # Save URL to DB
                record = URLRecord(
                    scan_id=self.scan_id,
                    url=url,
                    method="GET",
                    status_code=response.status_code,
                    content_type=content_type,
                    content_length=len(response.content),
                    source="crawler",
                    depth=depth
                )
                self.db.insert_url(record)
                
                # Emit URL event for non-root paths
                if depth > 0:
                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": url, "status": response.status_code},
                        scan_id=self.scan_id,
                        target=self.target
                    )

                # Only parse HTML for new links
                if "text/html" in content_type:
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    # Find links
                    for tag in soup.find_all(["a", "link", "script", "form", "img"]):
                        href = tag.get("href") or tag.get("src") or tag.get("action")
                        if not href:
                            continue
                            
                        absolute_url = urljoin(url, href)
                        parsed = urlparse(absolute_url)
                        
                        # Only follow links on the same domain (in-scope)
                        if parsed.netloc == start_domain:
                            # Clean fragments
                            clean_url = absolute_url.split("#")[0]
                            if clean_url not in visited and (clean_url, depth + 1) not in queue:
                                queue.append((clean_url, depth + 1))
                                
            except Exception as e:
                self.logger.debug(f"Crawl error for {url}: {e}")
