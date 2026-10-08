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
from reconai.integrations.gau import GauAdapter
from reconai.integrations.waybackurls import WaybackurlsAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class ArchiveModule(ReconModule):
    config = ModuleConfig(
        name="archive_urls",
        category="passive",
        description="Discovers historical URLs via gau / waybackurls CLI or pure HTTP CDX & OTX APIs",
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

        gau_adapter = GauAdapter(self.runner)
        wb_adapter = WaybackurlsAdapter(self.runner)
        has_gau = await gau_adapter.is_available()
        has_wayback = await wb_adapter.is_available()

        for domain in domains:
            start = time.monotonic()
            self.logger.module_start(self.config.name, target=domain)

            urls: list[str] = []
            if has_gau:
                try:
                    cmd = gau_adapter.build_command(domain=domain, threads=5)
                    res = await self.runner.run(command=cmd, timeout=60)
                    urls.extend(gau_adapter.parse(res))
                except Exception:
                    pass

            if not urls and has_wayback:
                try:
                    cmd = wb_adapter.build_command(domain=domain)
                    result = await self.runner.run(command=cmd, timeout=60)
                    urls.extend(wb_adapter.parse(result))
                except Exception:
                    pass

            if not urls:
                # Direct Wayback CDX JSON API and AlienVault OTX fallback
                cdx_task = self._query_cdx_api(domain)
                otx_task = self._query_otx_api(domain)
                cdx_res, otx_res = await asyncio.gather(cdx_task, otx_task, return_exceptions=True)
                if isinstance(cdx_res, list):
                    urls.extend(cdx_res)
                if isinstance(otx_res, list):
                    urls.extend(otx_res)

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

    async def _query_otx_api(self, domain: str) -> list[str]:
        """Query AlienVault OTX URL indicators API over HTTP without authentication."""
        found: list[str] = []
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=50&page=1"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("url_list", []):
                        u = entry.get("url")
                        if u and isinstance(u, str):
                            found.append(u)
        except Exception:
            pass
        return found
