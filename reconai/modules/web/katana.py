"""Advanced Web Crawling Module.

Uses Katana for deep JavaScript-aware crawling.

FIXES APPLIED:
  BUG 1 (Shared adapter state / race condition): Each _crawl_url() call
    now creates its own isolated temp file and passes the path to
    build_command + parse_output_file. Adapter is now fully stateless.
  BUG 2 (KeyError on depth): url_records now uses .get("depth", 0)
    to avoid KeyError when depth column is NULL.
  BUG 3 (Missing duration telemetry): module_complete() now receives
    actual wall-clock duration.
  BUG 4 (return_exceptions missing): asyncio.gather now has
    return_exceptions=True.
  BUG 5 (module kwarg missing): debug logs now pass module= kwarg.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.katana import KatanaAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class KatanaModule(ReconModule):
    config = ModuleConfig(
        name="katana_crawler",
        category="web",
        description="Advanced JS-aware web crawling using Katana",
        requires_tools=["katana"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls = list(kwargs.get("urls", []))
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [
                r["url"] for r in url_records
                if r.get("status_code") == 200 and r.get("depth", 0) == 0
            ]

        if not urls:
            return

        adapter = KatanaAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("katana not available. Skipping advanced crawling.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")
        start = time.monotonic()

        semaphore = asyncio.Semaphore(3)
        tasks = [self._crawl_url(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name, duration=time.monotonic() - start)

    async def _crawl_url(self, adapter: KatanaAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False, prefix="katana_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=url, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=300)

                url_records = adapter.parse_output_file(tmp_path)

                for record in url_records:
                    record.scan_id = self.scan_id
                    self.db.insert_url(record)

                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": record.url, "status": record.status_code},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

                self.logger.info(
                    f"Katana found {len(url_records)} URL(s) from {url}",
                    module=self.config.name,
                )

            except Exception as exc:
                self.logger.debug(f"Katana crawl failed for {url}: {exc}", module=self.config.name)
            finally:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
