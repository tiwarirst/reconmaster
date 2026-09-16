"""Nuclei Vulnerability Scanning Module.

Uses Nuclei for template-based vulnerability scanning.

Fixes applied:
  - Temp file is owned by the *module*, not the adapter.
    Each concurrent _scan_url() call creates its own isolated temp file
    and passes the path to build_command + parse_output_file.
    Adapter state is never shared between concurrent calls.
  - Scans URLs at depth 0 AND depth 1 (crawler-discovered endpoints).
    Depth-0-only previously missed all authenticated/internal API paths.
  - Temp file cleanup is guaranteed via try/finally.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from reconai.integrations.nuclei import NucleiAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class NucleiModule(ReconModule):
    config = ModuleConfig(
        name="nuclei_vuln",
        category="vuln",
        description="Template-based vulnerability scanning using Nuclei",
        requires_tools=["nuclei"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls: list[str] = list(kwargs.get("urls", []))

        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            # Scan depth 0 (probed root) AND depth 1 (crawler-discovered).
            # Depth-only-0 misses API endpoints discovered by the crawler.
            urls = [
                r["url"] for r in url_records
                if r.get("status_code") == 200 and r.get("depth", 0) <= 1
            ]

        if not urls:
            return

        adapter = NucleiAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error(
                "nuclei not available. Skipping vulnerability scan.",
                module=self.config.name,
            )
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs (depth 0–1)")

        # Nuclei handles internal concurrency — cap at 2 processes to avoid overload
        semaphore = asyncio.Semaphore(2)
        tasks = [self._scan_url(adapter, semaphore, url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name)

    async def _scan_url(
        self,
        adapter: NucleiAdapter,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> None:
        """Scan a single URL.

        Temp file lifecycle:
          1. Created here, before build_command.
          2. Path passed to adapter — adapter writes to it via -o flag.
          3. Path passed to parse_output_file after process exits.
          4. Always deleted in finally — no leaks.
        """
        async with semaphore:
            tmp_path: Path | None = None
            try:
                # Create isolated output file for this specific invocation
                with tempfile.NamedTemporaryFile(
                    suffix=".jsonl", delete=False, prefix="nuclei_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=url, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=600)

                # parse_output_file works correctly even if Nuclei timed out —
                # every JSONL line written before the kill is independently valid.
                findings = adapter.parse_output_file(tmp_path)

                for finding in findings:
                    finding.scan_id = self.scan_id
                    self.db.insert_finding(finding)

            except Exception as exc:
                self.logger.debug(
                    f"Nuclei scan failed for {url}: {exc}",
                    module=self.config.name,
                )
            finally:
                # Guaranteed cleanup — no temp files left on disk
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
