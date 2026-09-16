"""Web crawler module.

Lightweight spider to discover paths, parameters, and JavaScript files.
Uses httpx and beautifulsoup4.

Fixes applied:
  - Flaw 7: queue was a list, queue.pop(0) is O(n). Replaced with
    collections.deque — popleft() is O(1). At 500+ URLs the difference
    is visible; at 5000 it's the difference between seconds and minutes.
  - import re removed from inside the inner loop (http_probe shared pattern).
"""
from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

_RE_TITLE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@register_module
class CrawlerModule(ReconModule):
    config = ModuleConfig(
        name="crawler",
        category="web",
        description="Lightweight web spider to discover links, forms, and scripts",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        start_urls: list[str] = list(kwargs.get("urls", []))

        if not start_urls:
            url_records = self.db.get_urls(self.scan_id)
            # Only start crawling from root paths that returned 200
            start_urls = [
                r["url"] for r in url_records
                if r.get("status_code") == 200
                and urlparse(r["url"]).path in ("", "/")
            ]

        if not start_urls:
            return

        self.logger.module_start(self.config.name, target=f"{len(start_urls)} root URLs")

        max_depth = 2
        max_pages = 50

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15.0
        ) as client:
            tasks = [
                self._crawl(client, start_url, max_depth, max_pages)
                for start_url in start_urls
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name)

    async def _crawl(
        self,
        client: httpx.AsyncClient,
        start_url: str,
        max_depth: int,
        max_pages: int,
    ) -> None:
        """BFS crawl from start_url.

        Uses deque for O(1) popleft() instead of list.pop(0) which is O(n).
        """
        visited: set[str] = set()
        # deque gives O(1) append (right) and popleft (left) — correct for BFS
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        start_domain = urlparse(start_url).netloc

        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()  # O(1) — was list.pop(0) which is O(n)

            if url in visited or depth > max_depth:
                continue

            visited.add(url)

            try:
                response = await client.get(url)
                if response.status_code >= 400:
                    continue

                content_type = response.headers.get("content-type", "")

                # Extract title if present
                title = ""
                title_match = _RE_TITLE.search(response.text)
                if title_match:
                    title = title_match.group(1).strip()

                record = URLRecord(
                    scan_id=self.scan_id,
                    url=url,
                    method="GET",
                    status_code=response.status_code,
                    content_type=content_type,
                    content_length=len(response.content),
                    title=title,
                    source="crawler",
                    depth=depth,
                )
                self.db.insert_url(record)  # INSERT OR IGNORE — no duplicates

                if depth > 0:
                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": url, "status": response.status_code, "depth": depth},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

                if "text/html" not in content_type:
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                for tag in soup.find_all(["a", "link", "script", "form", "img"]):
                    href_raw = tag.get("href") or tag.get("src") or tag.get("action")
                    if not href_raw:
                        continue

                    href: str = href_raw[0] if isinstance(href_raw, list) else str(href_raw)
                    absolute_url = urljoin(url, href)
                    parsed = urlparse(absolute_url)

                    if parsed.netloc != start_domain:
                        continue

                    clean_url = absolute_url.split("#")[0]
                    if clean_url not in visited:
                        queue.append((clean_url, depth + 1))  # O(1)

            except Exception as exc:
                self.logger.debug(f"Crawl error for {url}: {exc}", module=self.config.name)
