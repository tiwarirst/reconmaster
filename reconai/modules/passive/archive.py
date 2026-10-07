"""Archive/Historical Reconnaissance Module.

Discovers historical URLs via waybackurls CLI or direct Wayback Machine CDX API over HTTP.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse

import httpx

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
        description="Discovers historical URLs via Wayback Machine (CLI or pure HTTP CDX API)",
        requires_tools=[],  # Optional: has built-in CDX HTTP fallback
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = list(kwargs.get("domains", []))
        if not domains and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                domains = [clean]

        if not domains:
            return

        adapter = WaybackurlsAdapter(self.runner)
        has_wayback = await adapter.is_available()

        for domain in domains:
            start = time.monotonic()
            self.logger.module_start(self.config.name, target=domain)

            urls: list[str] = []
            if has_wayback:
                cmd = adapter.build_command(domain=domain)
                result = await self.runner.run(command=cmd, timeout=60)
                urls = adapter.parse(result)

            if not urls:
                # Direct Wayback CDX JSON API fallback
                urls = await self._query_cdx_api(domain)

            # Deduplicate by path/query structure
            unique_urls = set()
            for u in urls:
                try:
                    parsed = urlparse(u)
                    if parsed.netloc.endswith(domain):
                        unique_urls.add(u)
                except Exception:
                    continue

            for u in unique_urls:
                record = URLRecord(
                    scan_id=self.scan_id,
                    url=u,
                    method="GET",
                    source="wayback_archive",
                )
                self.db.insert_url(record)

                await self.events.emit_discovery(
                    event_type=EventType.URL_DISCOVERED,
                    source=self.config.name,
                    data={"url": u, "status": 0},
                    scan_id=self.scan_id,
                    target=self.target,
                )

            self.logger.info(f"Discovered {len(unique_urls)} historical URLs for {domain}", module=self.config.name)
            duration = time.monotonic() - start
            self.logger.module_complete(self.config.name, duration=duration)

    async def _query_cdx_api(self, domain: str) -> list[str]:
        """Query Wayback Machine CDX API directly over HTTP."""
        found: list[str] = []
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=50"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    rows = resp.json()
                    # Skip header row ["original"]
                    for row in rows[1:]:
                        if row and isinstance(row, list):
                            found.append(row[0])
        except Exception:
            pass
        return found
