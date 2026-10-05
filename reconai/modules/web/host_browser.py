"""Host Browser Crawler Module — with Full Stealth Engine.

Connects to the user's OWN real browser via CDP, or launches a heavily
hardened headless browser if no real browser is available.

All stealth techniques from reconai.core.stealth.engine are applied
to ensure the crawler appears as a real human user.

HOW TO USE (for maximum stealth with real sessions):
  1. Open Chrome with remote debugging:
       chrome --remote-debugging-port=9222 --no-first-run
  2. Log into any sites you want to scan (Instagram, corporate portals, etc.)
  3. Run: reconai scan target.com --mode authenticated
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.core.stealth.engine import (
    STEALTH_JS,
    apply_stealth,
    human_delay,
    human_scroll,
    human_mouse_move,
    random_user_agent,
    random_viewport,
    REAL_USER_AGENTS,
)
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


CDP_DEFAULT_PORT = 9222


@register_module
class HostBrowserCrawlerModule(ReconModule):
    config = ModuleConfig(
        name="host_browser_crawler",
        category="web",
        description=(
            "Stealth CDP crawler — connects to your real browser (with live sessions) "
            "or launches a hardened headless browser with 15 bot-evasion techniques."
        ),
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        if not HAS_PLAYWRIGHT:
            self.logger.error(
                "Playwright not installed. Run: pip install playwright && playwright install",
                module=self.config.name
            )
            return

        cdp_port = kwargs.get("cdp_port", CDP_DEFAULT_PORT)
        cdp_endpoint = f"http://localhost:{cdp_port}"
        max_pages = kwargs.get("max_pages", 50)

        target_urls = await self._get_target_urls()
        if not target_urls:
            self.logger.warning("No target URLs found to crawl.")
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(target_urls)} URLs")

        if await self._is_browser_available(cdp_endpoint):
            self.logger.info(
                f"[STEALTH] Connected to real browser at {cdp_endpoint} — "
                f"using your live sessions (max stealth mode)"
            )
            await self._run_cdp_mode(cdp_endpoint, target_urls, max_pages)
        else:
            self.logger.warning(
                f"[STEALTH] Real browser not found at {cdp_endpoint}. "
                "Launching hardened stealth headless browser..."
            )
            await self._run_stealth_headless(target_urls, max_pages)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    # ────────────────────────────────────────────────────────────────────────
    # CDP Mode — Real browser with live sessions
    # ────────────────────────────────────────────────────────────────────────
    async def _run_cdp_mode(self, endpoint: str, target_urls: list[str], max_pages: int) -> None:
        screenshot_dir = self.out_dir / "screenshots" / "host_browser"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        discovered: set[str] = set()
        api_calls: set[str] = set()

        async with async_playwright() as p:
            browser = await p.chromium.connect_over_cdp(endpoint)
            contexts = browser.contexts
            context = contexts[0] if contexts else await browser.new_context()

            for root_url in target_urls[:5]:
                scope_host = urlparse(root_url).netloc
                await self._crawl_page(
                    context=context,
                    url=root_url,
                    screenshot_dir=screenshot_dir,
                    discovered=discovered,
                    api_calls=api_calls,
                    scope_host=scope_host,
                    max_pages=max_pages,
                    is_real_browser=True,
                )

            # Do NOT close the context — it's the user's real browser
            await browser.close()

        await self._save_results(discovered, api_calls, source="host_browser_cdp")

    # ────────────────────────────────────────────────────────────────────────
    # Stealth Headless Mode — Hardened against bot detection
    # ────────────────────────────────────────────────────────────────────────
    async def _run_stealth_headless(self, target_urls: list[str], max_pages: int) -> None:
        screenshot_dir = self.out_dir / "screenshots" / "stealth_headless"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        ua = random_user_agent()
        vp = random_viewport()

        self.logger.info(f"[STEALTH] User-Agent: {ua}")
        self.logger.info(f"[STEALTH] Viewport: {vp['width']}x{vp['height']}")

        discovered: set[str] = set()
        api_calls: set[str] = set()

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    # Remove all automation indicators
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    # Mimic real Chrome flags
                    "--disable-extensions-except=",
                    "--disable-default-apps",
                    "--no-first-run",
                    "--disable-sync",
                    "--disable-translate",
                    "--hide-scrollbars",
                    "--metrics-recording-only",
                    "--mute-audio",
                    "--no-report-upload",
                    "--safebrowsing-disable-download-protection",
                    "--disable-hang-monitor",
                    "--disable-prompt-on-repost",
                    "--disable-client-side-phishing-detection",
                    "--password-store=basic",
                    "--use-mock-keychain",
                    # Performance
                    "--disable-backgrounding-occluded-windows",
                    "--disable-breakpad",
                    "--disable-component-update",
                    "--disable-domain-reliability",
                    "--disable-features=AudioServiceOutOfProcess",
                    "--disable-ipc-flooding-protection",
                    "--enable-features=NetworkService,NetworkServiceInProcess",
                ]
            )

            context = await browser.new_context(
                user_agent=ua,
                viewport=vp,
                locale="en-US",
                timezone_id="America/New_York",
                ignore_https_errors=True,
                java_script_enabled=True,
                bypass_csp=False,  # Keep CSP on — disabling it is suspicious
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9,hi;q=0.8",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Cache-Control": "max-age=0",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                    "Upgrade-Insecure-Requests": "1",
                },
                permissions=["geolocation", "notifications"],
            )

            for root_url in target_urls[:8]:
                scope_host = urlparse(root_url).netloc
                await self._crawl_page(
                    context=context,
                    url=root_url,
                    screenshot_dir=screenshot_dir,
                    discovered=discovered,
                    api_calls=api_calls,
                    scope_host=scope_host,
                    max_pages=max_pages,
                    is_real_browser=False,
                )
                # Long delay between different root URLs to avoid rate limiting
                await human_delay(3000, 8000)

            await browser.close()

        await self._save_results(discovered, api_calls, source="stealth_headless")

    # ────────────────────────────────────────────────────────────────────────
    # Core Crawling Logic (shared by both modes)
    # ────────────────────────────────────────────────────────────────────────
    async def _crawl_page(
        self,
        context: Any,
        url: str,
        screenshot_dir: Any,
        discovered: set,
        api_calls: set,
        scope_host: str,
        max_pages: int,
        is_real_browser: bool,
        depth: int = 0,
        max_depth: int = 3,
    ) -> None:
        if url in discovered or len(discovered) >= max_pages or depth > max_depth:
            return

        discovered.add(url)
        page = await context.new_page()

        # ── Inject stealth JS BEFORE page loads (init script) ────────────
        if not is_real_browser:
            await apply_stealth(page)

        # ── Intercept API calls ──────────────────────────────────────────
        async def on_request(request: Any) -> None:
            req_url = request.url
            if (urlparse(req_url).netloc == scope_host and
                    request.resource_type in ("xhr", "fetch")):
                api_calls.add(req_url)

        page.on("request", lambda req: asyncio.create_task(on_request(req)))

        try:
            # ── Navigate with realistic wait strategy ─────────────────────
            await page.goto(url, wait_until="domcontentloaded", timeout=25000)

            # ── Human-like behaviour after page loads ─────────────────────
            # Wait for network to settle
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except PlaywrightTimeout:
                pass  # Some pages never reach networkidle — that's fine

            # Simulate reading the page
            await human_delay(1500, 4000)

            # Move mouse naturally
            await human_mouse_move(page)
            await human_delay(500, 1500)

            # Scroll through the page like a reader
            await human_scroll(page)
            await human_delay(800, 2500)

            # ── Screenshot ────────────────────────────────────────────────
            safe_name = (
                url.replace("https://", "").replace("http://", "")
                   .replace("/", "_").replace(":", "_")[:120] + ".png"
            )
            try:
                await page.screenshot(path=str(screenshot_dir / safe_name), full_page=True)
            except Exception:
                pass

            # ── Extract links via JS ──────────────────────────────────────
            links: list[str] = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                          .map(a => a.href)
                          .filter(href => href.startsWith('http'))
            """)

            # ── Recurse on in-scope links ─────────────────────────────────
            same_scope = [
                l for l in links
                if urlparse(l).netloc == scope_host and l not in discovered
            ]
            random.shuffle(same_scope)  # Randomise visit order (more human)

            for link in same_scope[:8]:
                if len(discovered) < max_pages:
                    # Random delay between page visits (avoids rate limiting)
                    await human_delay(2000, 6000)
                    await self._crawl_page(
                        context, link, screenshot_dir, discovered,
                        api_calls, scope_host, max_pages,
                        is_real_browser, depth + 1, max_depth,
                    )

        except PlaywrightTimeout:
            self.logger.debug(f"[STEALTH] Timeout: {url}")
        except Exception as e:
            self.logger.debug(f"[STEALTH] Error crawling {url}: {e}")
        finally:
            try:
                await page.close()
            except Exception:
                pass

    # ────────────────────────────────────────────────────────────────────────
    # Helpers
    # ────────────────────────────────────────────────────────────────────────
    async def _save_results(self, discovered: set[str], api_calls: set[str], source: str) -> None:
        self.logger.info(
            f"[STEALTH] Saving {len(discovered)} pages, {len(api_calls)} API calls..."
        )
        for url in discovered:
            record = URLRecord(scan_id=self.scan_id, url=url, method="GET", source=source)
            self.db.insert_url(record)
            await self.event_bus.emit_discovery(
                event_type=EventType.URL_DISCOVERED,
                source=source,
                data={"url": url, "source": source},
                scan_id=self.scan_id,
                target=self.target,
            )

        for api_url in api_calls:
            record = URLRecord(
                scan_id=self.scan_id, url=api_url,
                method="GET", source=f"{source}_api", depth=1
            )
            self.db.insert_url(record)

    async def _get_target_urls(self) -> list[str]:
        urls = self.db.get_urls(self.scan_id)
        live = [u["url"] for u in urls if u.get("status_code") == 200 and u.get("depth", 1) == 0]
        if live:
            return live
        subs = self.db.get_subdomains(self.scan_id)
        sub_urls = [f"https://{s['subdomain']}" for s in subs if s.get("is_alive")]
        if sub_urls:
            return sub_urls
        if self.target:
            t = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
            return [t]
        return []

    async def _is_browser_available(self, endpoint: str) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{endpoint}/json/version")
                return resp.status_code == 200
        except Exception:
            return False
