"""HTTP Probing Module.

Quickly checks if discovered subdomains have active web services.

Fixes applied:
  - Flaw 9: `import re` was inside the inner hot loop — a sys.modules dict
    lookup on every single HTTP response. Moved to module level, compiled
    once as a constant.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# Compiled once at import time — never re-evaluated inside loops
_RE_TITLE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@register_module
class HTTPProbeModule(ReconModule):
    config = ModuleConfig(
        name="http_probe",
        category="active",
        description="Lightweight HTTP/HTTPS probing of discovered hosts",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        hosts: list[str] = list(kwargs.get("hosts", []))
        if not hosts:
            # Fall back to all subdomains in the DB
            subs = self.db.get_subdomains(self.scan_id)
            hosts = [str(s["subdomain"]) for s in subs]

        if not hosts:
            return

        self.logger.module_start(self.config.name, target=f"{len(hosts)} hosts")

        semaphore = asyncio.Semaphore(20)

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=10.0
        ) as client:
            tasks = [self._probe_host(client, semaphore, host) for host in hosts]
            await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name)

    async def _probe_host(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        host: str,
    ) -> None:
        async with semaphore:
            for scheme in ("http", "https"):
                url = f"{scheme}://{host}"
                try:
                    response = await client.get(url)

                    # Use the pre-compiled regex — no import inside the loop
                    title = ""
                    match = _RE_TITLE.search(response.text)
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
                        source="http_probe",
                    )
                    self.db.insert_url(record)  # INSERT OR IGNORE — no duplicates

                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": url, "status": response.status_code, "title": title},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

                except httpx.RequestError:
                    pass  # Host unreachable — expected, not an error
                except Exception as exc:
                    self.logger.debug(
                        f"HTTP probe error for {url}: {exc}",
                        module=self.config.name,
                    )
