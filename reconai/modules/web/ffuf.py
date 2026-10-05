"""Advanced Directory Fuzzing Module.

Uses FFuF for ultra-fast directory discovery.

Fix applied (BUG 1):
  Temp file is now owned by the module, not the adapter.
  Concurrent _fuzz_url() calls each get an independent output file.
  Added return_exceptions=True to asyncio.gather.
  Added multi-wordlist discovery fallback and duration telemetry.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.ffuf import FfufAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class FfufModule(ReconModule):
    config = ModuleConfig(
        name="ffuf_dir",
        category="web",
        description="Fast directory brute-forcing using FFuF",
        requires_tools=["ffuf"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls: list[str] = list(kwargs.get("urls", []))
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [
                r["url"] for r in url_records
                if r.get("status_code") == 200 and r.get("depth", 0) == 0
            ]

        if not urls and self.target:
            urls = [self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"]

        if not urls:
            return

        adapter = FfufAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("ffuf not available. Skipping directory fuzzing.", module=self.config.name)
            return

        possible_wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        ]
        wordlist = next((w for w in possible_wordlists if os.path.exists(w)), "")
        if not wordlist:
            self.logger.warning("No standard wordlists found on system (/usr/share/wordlists/). Skipping ffuf.", module=self.config.name)
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        semaphore = asyncio.Semaphore(3)
        tasks = [self._fuzz_url(adapter, semaphore, url, wordlist) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _fuzz_url(
        self,
        adapter: FfufAdapter,
        semaphore: asyncio.Semaphore,
        url: str,
        wordlist: str,
    ) -> None:
        """Fuzz a single URL for directories.

        Temp file lifecycle:
          1. Created here, before build_command.
          2. Path passed to adapter — adapter instructs FFuF to write there.
          3. Path passed to parse_output_file after process exits.
          4. Always deleted in finally.
        """
        async with semaphore:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False, prefix="ffuf_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=url, wordlist=wordlist, output_file=tmp_path)
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

            except Exception as exc:
                self.logger.debug(f"FFuF fuzzing failed for {url}: {exc}", module=self.config.name)
            finally:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
