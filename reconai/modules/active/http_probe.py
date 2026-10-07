"""HTTP Probing Module.

Quickly checks if discovered subdomains have active web services.

Fixes applied:
  - Flaw 9: `import re` was inside the inner hot loop — moved to module level,
    compiled once as a constant.
  - Added duration telemetry to module_complete().
  - Added target fallback if no subdomains were discovered.
"""
from __future__ import annotations

import asyncio
import re
import time
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
        subs = self.db.get_subdomains(self.scan_id)
        sub_hosts = [str(s["subdomain"]) for s in subs if s.get("subdomain")]
        kw_hosts = list(kwargs.get("hosts", []))
        
        # Merge target, kwargs hosts, and discovered subdomains
        hosts = list(dict.fromkeys(kw_hosts + sub_hosts))

        if not hosts and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                hosts = [clean]

        if not hosts:
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(hosts)} hosts")

        semaphore = asyncio.Semaphore(20)

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=10.0
        ) as client:
            tasks = [self._probe_host(client, semaphore, host) for host in hosts[:150]]
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

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

                    title = ""
                    match = _RE_TITLE.search(response.text)
                    if match:
                        title = match.group(1).strip()

                    redirect_url = response.headers.get("location", "")

                    record = URLRecord(
                        scan_id=self.scan_id,
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type", ""),
                        content_length=len(response.content),
                        title=title,
                        redirect_url=redirect_url,
                        source="http_probe",
                    )
                    self.db.insert_url(record)

                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": url, "status": response.status_code, "title": title},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

                    # If this is a redirect, also probe the destination to record the live 200 URL
                    if response.status_code in (301, 302, 303, 307, 308) and redirect_url:
                        from urllib.parse import urljoin
                        dest_url = urljoin(url, redirect_url)
                        try:
                            dest_resp = await client.get(dest_url, follow_redirects=True)
                            dest_title = ""
                            dest_match = _RE_TITLE.search(dest_resp.text)
                            if dest_match:
                                dest_title = dest_match.group(1).strip()

                            dest_record = URLRecord(
                                scan_id=self.scan_id,
                                url=str(dest_resp.url),
                                method="GET",
                                status_code=dest_resp.status_code,
                                content_type=dest_resp.headers.get("content-type", ""),
                                content_length=len(dest_resp.content),
                                title=dest_title,
                                source="http_probe",
                            )
                            self.db.insert_url(dest_record)
                        except Exception:
                            pass

                except httpx.RequestError:
                    pass  # Host unreachable — expected, not an error
                except Exception as exc:
                    self.logger.debug(
                        f"HTTP probe error for {url}: {exc}",
                        module=self.config.name,
                    )
