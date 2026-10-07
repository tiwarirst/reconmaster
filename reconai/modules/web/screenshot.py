"""Screenshot Module — multi-engine cross-platform implementation.

Captures visual screenshots of live web pages using:
1. Gowitness (if installed in system PATH)
2. Headless Chrome / Chromium / Edge (standard across Linux, WSL, and Windows)
3. Playwright (if installed in Python environment)
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reconai.core.events.types import EventType
from reconai.integrations.gowitness import GowitnessAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


def _find_system_browser() -> str | None:
    """Find installed Chrome, Chromium, or Edge binary on Linux, WSL, or Windows."""
    candidates = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "msedge",
        # Common Linux paths
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        # Common Windows paths
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        # Common macOS paths
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ]
    for candidate in candidates:
        if shutil.which(candidate) or os.path.isfile(candidate):
            return candidate
    return None


@register_module
class ScreenshotModule(ReconModule):
    config = ModuleConfig(
        name="screenshot",
        category="web",
        description="Captures visual screenshots of web pages via Gowitness, Chromium, or Headless Browser",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        start = time.monotonic()
        self.logger.module_start(self.config.name)

        # 1. Gather URLs to screenshot
        live_urls: list[str] = []
        kw_urls = list(kwargs.get("urls", []))
        if kw_urls:
            live_urls.extend(kw_urls)

        # Retrieve discovered URLs from DB
        db_urls = self.db.get_urls(self.scan_id)
        for u in db_urls:
            url_str = str(u.get("url", ""))
            status = u.get("status_code")
            # Include successful or redirected URLs
            if url_str and status in (200, 301, 302, 307, 308, 401, 403, None):
                if url_str not in live_urls:
                    live_urls.append(url_str)

        # Fallback to target if DB has no URLs
        if not live_urls and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            live_urls = [f"https://{clean}", f"http://{clean}"]

        if not live_urls:
            self.logger.warning("No URLs found to screenshot.", module=self.config.name)
            self.logger.module_complete(self.config.name, duration=time.monotonic() - start)
            return

        screenshot_dir = self.out_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        # Filter and prioritize root URLs first to avoid redundant shots
        target_urls = self._prioritize_urls(live_urls)[:20]

        # 2. Try Gowitness first
        adapter = GowitnessAdapter(runner=self.runner)
        if await adapter.is_available():
            self.logger.info(f"Using Gowitness to capture {len(target_urls)} URL(s)...", module=self.config.name)
            await self._run_gowitness(adapter, target_urls, screenshot_dir)
        else:
            # 3. Fallback: Check for system browser (Chromium / Chrome / Edge)
            browser_bin = _find_system_browser()
            if browser_bin:
                self.logger.info(
                    f"Gowitness not installed. Using native headless browser ({Path(browser_bin).name}) for screenshots...",
                    module=self.config.name,
                )
                await self._run_browser_cli(browser_bin, target_urls, screenshot_dir)
            else:
                # 4. Fallback: Check Playwright in Python
                try:
                    from playwright.async_api import async_playwright
                    self.logger.info("Using Playwright engine for screenshots...", module=self.config.name)
                    await self._run_playwright(target_urls, screenshot_dir)
                except ImportError:
                    self.record_warning(
                        "No screenshot engine available. Install Gowitness ('go install github.com/sensepost/gowitness@latest') "
                        "or install Google Chrome / Edge / Chromium to enable visual screenshot captures."
                    )

        count = len(list(screenshot_dir.glob("*.png")))
        if count > 0:
            self.logger.info(f"Successfully saved {count} screenshot(s) to {screenshot_dir}", module=self.config.name)

        self.logger.module_complete(self.config.name, duration=time.monotonic() - start)

    def _prioritize_urls(self, urls: list[str]) -> list[str]:
        """Order URLs so distinct hosts and root paths come first."""
        seen_hosts: set[str] = set()
        roots: list[str] = []
        others: list[str] = []

        for u in urls:
            try:
                parsed = urlparse(u)
                if not parsed.scheme.startswith("http"):
                    continue
                host = parsed.netloc.lower()
                if parsed.path in ("", "/"):
                    if host not in seen_hosts:
                        seen_hosts.add(host)
                        roots.append(u)
                else:
                    others.append(u)
            except Exception:
                continue

        return roots + [u for u in others if urlparse(u).netloc.lower() not in seen_hosts]

    async def _run_gowitness(
        self, adapter: GowitnessAdapter, urls: list[str], screenshot_dir: Path
    ) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            for url in urls:
                tmp.write(f"{url}\n")
            urls_file = tmp.name

        try:
            cmd = adapter.build_command(
                urls_file=urls_file,
                out_dir=self.out_dir,
                timeout=self.timeout,
            )
            timeout_val = min(300, max(30, len(urls) * 5))
            await self.runner.run(command=cmd, timeout=timeout_val)
        finally:
            Path(urls_file).unlink(missing_ok=True)

    async def _run_browser_cli(
        self, browser_bin: str, urls: list[str], screenshot_dir: Path
    ) -> None:
        """Run headless browser directly via subprocess to capture PNGs."""
        semaphore = asyncio.Semaphore(3)

        async def _capture(url: str) -> None:
            safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", url.replace("https://", "").replace("http://", ""))
            out_file = screenshot_dir / f"{safe_name}.png"
            cmd = [
                browser_bin,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                f"--screenshot={out_file}",
                "--window-size=1280,800",
                url,
            ]
            async with semaphore:
                try:
                    await self.runner.run(command=cmd, timeout=20)
                except Exception as e:
                    self.logger.debug(f"Headless screenshot error for {url}: {e}", module=self.config.name)

        tasks = [_capture(u) for u in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_playwright(self, urls: list[str], screenshot_dir: Path) -> None:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 800})
            for url in urls[:10]:
                try:
                    page = await context.new_page()
                    await page.goto(url, timeout=12000, wait_until="load")
                    safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", url.replace("https://", "").replace("http://", ""))
                    out_file = screenshot_dir / f"{safe_name}.png"
                    await page.screenshot(path=str(out_file))
                    await page.close()
                except Exception:
                    pass
            await browser.close()
