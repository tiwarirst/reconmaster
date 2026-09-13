"""Headless Browser Reconnaissance Module.

Uses Playwright to take screenshots, discover endpoints in SPAs, and monitor networks.
"""
from __future__ import annotations

import asyncio
from typing import Any

# Playwright is optional. If not installed, module handles it gracefully.
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from reconai.core.database.models import URLRecord, FindingRecord, Severity, Confidence, FindingStatus
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class BrowserReconModule(ReconModule):
    config = ModuleConfig(
        name="browser_recon",
        category="web",
        description="Headless browser automation for SPA crawling and screenshots",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        if not HAS_PLAYWRIGHT:
            self.logger.error("Playwright not installed. Run: pip install playwright && playwright install", module=self.config.name)
            return

        urls = kwargs.get("urls", [])
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            # Only visit root URLs that returned 200
            urls = [r["url"] for r in url_records if r["status_code"] == 200 and r["depth"] == 0]

        if not urls:
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        # Create screenshots dir
        screenshot_dir = self.out_dir / "screenshots"
        screenshot_dir.mkdir(exist_ok=True)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            
            for url in urls[:10]: # Limit to avoid massive overhead
                await self._visit_url(context, url, screenshot_dir)
                
            await browser.close()

        self.logger.module_complete(self.config.name)

    async def _visit_url(self, context: Any, url: str, screenshot_dir: Any) -> None:
        page = await context.new_page()
        
        # Intercept network requests to find API calls made by SPAs
        api_endpoints = set()
        page.on("request", lambda request: api_endpoints.add(request.url) if "api" in request.url.lower() else None)

        try:
            # Go to URL and wait until network is idle (good for SPAs)
            await page.goto(url, wait_until="networkidle", timeout=15000)
            
            # Take screenshot
            safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_") + ".png"
            path = screenshot_dir / safe_name
            await page.screenshot(path=str(path), full_page=True)
            
            # Save intercepted APIs
            for api_url in api_endpoints:
                if url in api_url or "api" in api_url:
                    record = URLRecord(
                        scan_id=self.scan_id,
                        url=api_url,
                        method="GET",
                        source="browser_recon"
                    )
                    self.db.insert_url(record)
                    
        except PlaywrightTimeout:
            self.logger.debug(f"Timeout loading {url} in browser")
        except Exception as e:
            self.logger.debug(f"Browser error for {url}: {e}")
        finally:
            await page.close()
