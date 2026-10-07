"""Headless Browser Reconnaissance Module.

Uses Playwright to take full-page screenshots, discover endpoints in Single Page Applications (SPAs),
and monitor background network calls (XHR / Fetch).
"""
from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Playwright is optional. If not installed, module handles it gracefully.
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from reconai.core.database.models import APIEndpoint, URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class BrowserReconModule(ReconModule):
    config = ModuleConfig(
        name="browser_recon",
        category="web",
        description="Headless browser automation for SPA crawling, network monitoring, and screenshots",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        if not HAS_PLAYWRIGHT:
            self.record_warning(
                "Playwright not installed in Python environment. Install with: "
                "'pip install playwright && playwright install chromium' to enable browser crawling and visual screenshots."
            )
            return

        urls = list(kwargs.get("urls", []))
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [
                str(r["url"]) for r in url_records
                if r.get("status_code") in (200, 301, 302, None) and r.get("depth", 0) <= 1
            ]

        if not urls and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            urls = [f"https://{clean}", f"http://{clean}"]

        if not urls:
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        # Create screenshots dir
        screenshot_dir = self.out_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )

            for url in urls[:12]:  # Top 12 entry points to avoid excess latency
                await self._visit_url(context, url, screenshot_dir)

            await browser.close()

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _visit_url(self, context: Any, url: str, screenshot_dir: Path) -> None:
        page = await context.new_page()

        # Intercept background network requests (XHR / Fetch / API calls)
        api_endpoints: set[str] = set()

        async def _handle_request(request: Any) -> None:
            req_url = request.url
            if any(kw in req_url.lower() for kw in ("api", "graphql", "v1", "v2", "json", "token")):
                api_endpoints.add(req_url)

        page.on("request", lambda req: asyncio.create_task(_handle_request(req)))

        try:
            # Navigate and wait for DOM and initial network settlement
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            try:
                await page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:
                pass

            # Take full-page screenshot
            safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", url.replace("https://", "").replace("http://", ""))[:120] + ".png"
            path = screenshot_dir / safe_name
            try:
                await page.screenshot(path=str(path), full_page=True)
            except Exception:
                pass

            # Extract client-side DOM links
            dom_links: list[str] = await page.evaluate("""
                () => {
                    const links = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        if (a.href && a.href.startsWith('http')) links.add(a.href);
                    });
                    document.querySelectorAll('[data-href], [data-url]').forEach(el => {
                        const val = el.getAttribute('data-href') || el.getAttribute('data-url');
                        if (val) links.add(val);
                    });
                    return Array.from(links);
                }
            """)

            for link in dom_links:
                clean_link = link.split("#")[0]
                self.db.insert_url(URLRecord(
                    scan_id=self.scan_id,
                    url=clean_link,
                    method="GET",
                    source="browser_dom",
                    depth=1,
                ))

            # Save intercepted APIs to both URL and APIEndpoint tables
            for api_url in api_endpoints:
                parsed_api = urlparse(api_url)
                rec = URLRecord(
                    scan_id=self.scan_id,
                    url=api_url,
                    method="GET",
                    source="browser_network",
                    depth=1,
                )
                self.db.insert_url(rec)

                self.db.insert_api_endpoint(APIEndpoint(
                    scan_id=self.scan_id,
                    host=f"{parsed_api.scheme}://{parsed_api.netloc}",
                    method="GET",
                    path=parsed_api.path or "/",
                    full_url=api_url,
                    source="browser_network",
                    api_type="XHR/Fetch",
                ))

                await self.events.emit_discovery(
                    event_type=EventType.URL_DISCOVERED,
                    source=self.config.name,
                    data={"url": api_url, "source": "browser_network"},
                    scan_id=self.scan_id,
                    target=self.target,
                )

        except PlaywrightTimeout:
            self.logger.debug(f"Timeout loading {url} in browser")
        except Exception as e:
            self.logger.debug(f"Browser error for {url}: {e}")
        finally:
            try:
                await page.close()
            except Exception:
                pass
