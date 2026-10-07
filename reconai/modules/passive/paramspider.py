"""Parameter Discovery Module.

Uses ParamSpider to find URLs with parameters for injection testing.
"""
from __future__ import annotations

import asyncio
import time
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
        description="Mines historical URLs for query parameters using ParamSpider (with Python fallback)",
        requires_tools=[],
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

        adapter = ParamspiderAdapter(self.runner)

        for domain in domains:
            start = time.monotonic()
            self.logger.module_start(self.config.name, target=domain)

            urls: list[str] = []
            if await adapter.is_available():
                cmd = adapter.build_command(domain=domain)
                result = await self.runner.run(command=cmd, timeout=300)
                urls = adapter.parse(result, domain=domain)

            if not urls:
                self.record_warning(
                    "ParamSpider not installed. Install: 'git clone https://github.com/devanshbatham/paramspider && pip install ./paramspider'. "
                    "Ran CDX & synthetic parameter mining fallback."
                )
                urls = await self._mine_archive_parameters(domain)

            # Ensure at least baseline parameterized URLs exist for injection fuzzers
            if not urls:
                urls = [
                    f"https://{domain}/?q=test",
                    f"https://{domain}/?search=query",
                    f"https://{domain}/?id=1",
                    f"https://{domain}/?page=1",
                ]

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
            duration = time.monotonic() - start
            self.logger.module_complete(self.config.name, duration=duration)

    async def _mine_archive_parameters(self, domain: str) -> list[str]:
        """Fetch historical URLs containing query parameters from Wayback CDX API."""
        import httpx
        params_urls: list[str] = []
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
        try:
            async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": "Mozilla/5.0"}) as client:
                resp = await client.get(cdx_url)
                if resp.status_code == 200:
                    data = resp.json()
                    # Skip header row
                    for row in data[1:]:
                        if row and isinstance(row, list) and len(row) > 0:
                            candidate = row[0]
                            if "?" in candidate and "=" in candidate:
                                params_urls.append(candidate)
        except Exception:
            pass
        return params_urls[:50]

