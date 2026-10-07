"""Technology Fingerprinting Module.

Uses WhatWeb adapter to identify frameworks, CMS, and web servers.
Provides an automated pure-Python HTTP fingerprinting fallback when WhatWeb is absent.
"""
from __future__ import annotations

import asyncio
import re
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

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
        description="Technology fingerprinting using WhatWeb with pure-Python fallback",
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
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            urls = [f"https://{clean}", f"http://{clean}"]

        if not urls:
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        adapter = WhatWebAdapter(self.runner)
        if await adapter.is_available():
            semaphore = asyncio.Semaphore(5)
            tasks = [self._fingerprint_url(adapter, semaphore, url) for url in urls[:15]]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            self.logger.info(
                "WhatWeb binary not found; using built-in HTTP header and DOM technology inspector...",
                module=self.config.name,
            )
            await self._fingerprint_pure_python(urls[:20])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _fingerprint_pure_python(self, urls: list[str]) -> None:
        """Inspect HTTP response headers, cookies, and DOM signatures."""
        semaphore = asyncio.Semaphore(10)

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconAI/1.0"},
        ) as client:
            async def _check(url: str) -> None:
                async with semaphore:
                    try:
                        resp = await client.get(url)
                        hostname = urlparse(str(resp.url)).netloc or urlparse(url).netloc
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        text = resp.text[:200000]

                        detected: list[tuple[str, str, str]] = []

                        # 1. Server header
                        server = headers.get("server", "")
                        if server:
                            detected.append((server, "", "Web Server"))
                            if "cloudflare" in server.lower():
                                detected.append(("Cloudflare", "", "CDN / Proxy"))
                            if "nginx" in server.lower():
                                detected.append(("Nginx", "", "Web Server"))
                            if "apache" in server.lower():
                                detected.append(("Apache", "", "Web Server"))
                            if "litespeed" in server.lower():
                                detected.append(("LiteSpeed", "", "Web Server"))
                            if "caddy" in server.lower():
                                detected.append(("Caddy", "", "Web Server"))

                        # 2. X-Powered-By
                        powered = headers.get("x-powered-by", "")
                        if powered:
                            detected.append((powered, "", "Programming Language / Framework"))

                        # 3. CDN & Infrastructure headers
                        if "cf-ray" in headers:
                            detected.append(("Cloudflare", "", "CDN / WAF"))
                        if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", "").lower():
                            detected.append(("AWS CloudFront", "", "CDN"))
                        if "x-github-request-id" in headers:
                            detected.append(("GitHub Pages", "", "PaaS Hosting"))

                        # 4. Web Frameworks & CMS DOM Patterns
                        if "_next/" in text or "__NEXT_DATA__" in text:
                            detected.append(("Next.js", "", "JavaScript Framework"))
                            detected.append(("React", "", "UI Library"))
                        elif "react-root" in text or "data-reactroot" in text:
                            detected.append(("React", "", "UI Library"))

                        if "wp-content" in text or "wp-includes" in text:
                            detected.append(("WordPress", "", "CMS"))

                        if "sites/default/files" in text or "drupal" in text.lower():
                            detected.append(("Drupal", "", "CMS"))

                        if "shopify.com" in text or "cdn.shopify.com" in text:
                            detected.append(("Shopify", "", "E-Commerce"))

                        if "bootstrap" in text.lower():
                            detected.append(("Bootstrap", "", "CSS Framework"))

                        if "tailwind" in text.lower():
                            detected.append(("Tailwind CSS", "", "CSS Framework"))

                        # Save unique detections
                        seen: set[str] = set()
                        for name, ver, cat in detected:
                            clean_name = name.strip()
                            if clean_name and clean_name.lower() not in seen:
                                seen.add(clean_name.lower())
                                record = TechnologyRecord(
                                    scan_id=self.scan_id,
                                    host=hostname,
                                    name=clean_name,
                                    version=ver,
                                    category=cat,
                                    confidence=90.0,
                                    source="http_fingerprint",
                                )
                                self.db.insert_technology(record)
                                await self.events.emit_discovery(
                                    event_type=EventType.TECHNOLOGY_DETECTED,
                                    source=self.config.name,
                                    data={
                                        "url": url,
                                        "host": hostname,
                                        "technology": clean_name,
                                        "version": ver,
                                    },
                                    scan_id=self.scan_id,
                                    target=self.target,
                                )

                    except Exception as e:
                        self.logger.debug(f"HTTP technology inspection error for {url}: {e}", module=self.config.name)

            tasks = [_check(u) for u in urls]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _fingerprint_url(
        self,
        adapter: WhatWebAdapter,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> None:
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
                hostname = urlparse(url).netloc or url

                for tech_dict in techs:
                    record = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=hostname,
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
                            "url": url,
                            "host": hostname,
                            "technology": record.name,
                            "version": record.version,
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
