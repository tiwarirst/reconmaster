"""Screenshot Module.

Uses Gowitness to take screenshots of all discovered live URLs.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from reconai.integrations.gowitness import GowitnessAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class ScreenshotModule(ReconModule):
    config = ModuleConfig(
        name="screenshot",
        category="web",
        description="Takes visual screenshots of discovered web pages",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        self.logger.module_start(self.config.name)

        # Get all live URLs (200 OK, 401, 403)
        urls = self.db.get_urls(self.scan_id)
        live_urls = [u["url"] for u in urls if u["status_code"] in (200, 401, 403)]

        if not live_urls:
            self.logger.info("No live URLs found to screenshot.")
            self.logger.module_complete(self.config.name)
            return

        # ── Instantiate adapter with the module's runner (required by ToolAdapter) ──
        adapter = GowitnessAdapter(runner=self.runner)
        if not await adapter.is_available():
            self.logger.warning(f"{adapter.name} is not installed. Skipping screenshots.")
            self.logger.module_complete(self.config.name)
            return

        # Write URLs to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            for url in live_urls:
                tmp.write(f"{url}\n")
            urls_file = tmp.name

        try:
            cmd = adapter.build_command(
                urls_file=urls_file,
                out_dir=self.out_dir,
                timeout=self.timeout,
            )

            self.logger.info(f"Taking screenshots of {len(live_urls)} URLs...")
            await self.runner.run(command=cmd, timeout=self.timeout * len(live_urls))

            # Gowitness doesn't produce JSON for our DB — images are saved to the folder
            screenshot_dir = self.out_dir / "screenshots"
            if screenshot_dir.exists():
                count = len(list(screenshot_dir.glob("*.png")))
                self.logger.info(f"Captured {count} screenshots → {screenshot_dir}")

        finally:
            Path(urls_file).unlink(missing_ok=True)

        self.logger.module_complete(self.config.name)
