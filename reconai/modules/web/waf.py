"""WAF Detection Module.

Uses wafw00f to identify Web Application Firewalls protecting the target.

FIXES APPLIED:
  BUG 1 (Shared adapter state / race condition): Each _detect_waf() call
    now creates its own isolated temp file and passes the path to
    build_command + parse_output_file. Adapter is now fully stateless.
  BUG 2 (KeyError on depth): url_records now uses .get("depth", 0)
    and .get("status_code") safely.
  BUG 3 (Missing duration telemetry): module_complete() now receives
    actual wall-clock duration.
  BUG 4 (return_exceptions missing): asyncio.gather now has
    return_exceptions=True.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

from reconai.core.database.models import TechnologyRecord
from reconai.core.events.types import EventType
from reconai.integrations.wafw00f import Wafw00fAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class WafModule(ReconModule):
    config = ModuleConfig(
        name="waf_detection",
        category="web",
        description="Detects Web Application Firewalls using WafW00f",
        requires_tools=["wafw00f"],
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

        adapter = Wafw00fAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("wafw00f not available. Skipping WAF detection.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")
        start = time.monotonic()

        semaphore = asyncio.Semaphore(5)
        tasks = [self._detect_waf(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name, duration=time.monotonic() - start)

    async def _detect_waf(self, adapter: Wafw00fAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False, prefix="wafw00f_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=url, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=60)

                wafs = adapter.parse_output_file(tmp_path)

                for waf in wafs:
                    record = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=url,
                        name=waf["firewall"],
                        category="WAF",
                        confidence=100.0,
                        source="wafw00f",
                    )
                    self.db.insert_technology(record)

                    await self.events.emit_discovery(
                        event_type=EventType.TECHNOLOGY_DETECTED,
                        source=self.config.name,
                        data={"url": url, "technology": record.name, "category": "WAF"},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

                if wafs:
                    self.logger.info(
                        f"WAF detected on {url}: {', '.join(w['firewall'] for w in wafs)}",
                        module=self.config.name,
                    )
                else:
                    self.logger.info(f"No WAF detected on {url}", module=self.config.name)

            except Exception as exc:
                self.logger.debug(f"WAF detection failed for {url}: {exc}", module=self.config.name)
            finally:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
