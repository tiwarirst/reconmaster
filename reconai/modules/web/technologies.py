"""Technology Fingerprinting Module.

Uses WhatWeb adapter to identify frameworks, CMS, web servers.

Fixes applied:
  BUG 4: Updated to use stateless WhatWebAdapter.parse_output_file(path).
         Each concurrent _fingerprint_url() now creates its own isolated temp
         file — no shared adapter state, no lost results.

  BUG 9: host field now stores urlparse(url).netloc (clean hostname) instead
         of the full URL string. The technologies table has a UNIQUE constraint
         on (scan_id, host, name). Storing full URLs with different paths as
         the host value broke deduplication and created false duplicates.
         e.g. "https://example.com/" and "https://example.com/admin" would
         insert "Apache" twice under different host values.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reconai.core.database.models import TechnologyRecord
from reconai.core.events.types import EventType
from reconai.integrations.whatweb import WhatWebAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class TechnologyModule(ReconModule):
    config = ModuleConfig(
        name="technologies",
        category="web",
        description="Technology fingerprinting using WhatWeb",
        requires_tools=["whatweb"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls: list[str] = list(kwargs.get("urls", []))

        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [
                str(r["url"]) for r in url_records
                if r.get("status_code") and int(r["status_code"]) < 400
            ]

        if not urls and self.target:
            urls = [self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"]

        if not urls:
            return

        adapter = WhatWebAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error(
                "WhatWeb not available. Skipping technology fingerprinting.",
                module=self.config.name,
            )
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        semaphore = asyncio.Semaphore(5)
        tasks = [self._fingerprint_url(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _fingerprint_url(
        self,
        adapter: WhatWebAdapter,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> None:
        """Fingerprint a single URL.

        Temp file lifecycle:
          1. Created here, before build_command.
          2. Path passed to adapter — WhatWeb writes --log-json to it.
          3. Path passed to parse_output_file after process exits.
          4. Always deleted in finally.
        """
        async with semaphore:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False, prefix="whatweb_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(url=url, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=30)

                techs = adapter.parse_output_file(tmp_path)

                # Extract clean hostname — never store the full URL as host
                hostname = urlparse(url).netloc or url

                for tech_dict in techs:
                    record = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=hostname,           # Fix BUG 9: netloc, not full URL
                        name=str(tech_dict.get("name", "")),
                        version=str(tech_dict.get("version", "")),
                        confidence=float(tech_dict.get("confidence", 100.0)),
                        source="whatweb",
                    )
                    self.db.insert_technology(record)

                    await self.events.emit_discovery(
                        event_type=EventType.TECHNOLOGY_DETECTED,
                        source=self.config.name,
                        data={
                            "url":        url,
                            "host":       hostname,
                            "technology": record.name,
                            "version":    record.version,
                        },
                        scan_id=self.scan_id,
                        target=self.target,
                    )

            except Exception as exc:
                self.logger.debug(
                    f"WhatWeb fingerprint failed for {url}: {exc}",
                    module=self.config.name,
                )
            finally:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
