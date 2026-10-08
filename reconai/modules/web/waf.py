"""WAF Detection Module.

Uses wafw00f to identify Web Application Firewalls protecting the target.
Provides pure-Python HTTP header & challenge inspection fallback when wafw00f is not installed.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from reconai.core.database.models import TechnologyRecord
from reconai.core.events.types import EventType
from reconai.integrations.wafw00f import Wafw00fAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# Known WAF header / cookie fingerprints
_WAF_FINGERPRINTS = [
    ("Cloudflare", ["cf-ray", "__cfduid", "cf-cache-status"]),
    ("AWS WAF", ["x-amzn-waf-action", "x-amzn-requestid", "awswaf"]),
    ("Akamai", ["x-akamai-transformed", "akamai-grn"]),
    ("Imperva / Incapsula", ["x-cdn", "incap_ses", "visid_incap"]),
    ("Sucuri CloudProxy", ["x-sucuri-id", "x-sucuri-cache"]),
    ("F5 BIG-IP ASM", ["bigip", "f5_cspm"]),
    ("Fortinet FortiWeb", ["fortiwafsid"]),
    ("Barracuda WAF", ["barra_counter_session", "bndi"]),
]


@register_module
class WafModule(ReconModule):
    config = ModuleConfig(
        name="waf_detection",
        category="web",
        description="Detects Web Application Firewalls using WafW00f or pure-Python inspection",
        requires_tools=[],  # Optional: has pure-Python fallback
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls: list[str] = list(kwargs.get("urls", []))
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [
                str(r["url"]) for r in url_records
                if r.get("status_code") and int(r["status_code"]) < 500
            ]

        if not urls and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            urls = [f"https://{clean}", f"http://{clean}"]

        if not urls:
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        adapter = Wafw00fAdapter(self.runner)
        if await adapter.is_available():
            semaphore = asyncio.Semaphore(10)
            tasks = [self._detect_waf(adapter, semaphore, url) for url in urls[:50]]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            self.logger.info("wafw00f tool not found; using pure-Python WAF signature inspector...", module=self.config.name)
            await self._detect_waf_pure_python(urls[:50])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _detect_waf_pure_python(self, urls: list[str]) -> None:
        semaphore = asyncio.Semaphore(10)
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconAI/1.0"},
        ) as client:
            detected_wafs: set[str] = set()

            async def _check(url: str) -> None:
                async with semaphore:
                    try:
                        resp = await client.get(url)
                        hostname = urlparse(str(resp.url)).netloc or urlparse(url).netloc
                        headers_str = " ".join(f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items())
                        cookies_str = " ".join(resp.cookies.keys()).lower()

                        for waf_name, indicators in _WAF_FINGERPRINTS:
                            if waf_name in detected_wafs:
                                continue
                            matched = any(ind in headers_str or ind in cookies_str for ind in indicators)
                            if matched:
                                detected_wafs.add(waf_name)
                                record = TechnologyRecord(
                                    scan_id=self.scan_id,
                                    host=hostname,
                                    name=waf_name,
                                    category="WAF / DDoS Shield",
                                    confidence=95.0,
                                    source="waf_signature",
                                )
                                self.db.insert_technology(record)
                                await self.events.emit_discovery(
                                    event_type=EventType.TECHNOLOGY_DETECTED,
                                    source=self.config.name,
                                    data={"url": url, "host": hostname, "waf": waf_name},
                                    scan_id=self.scan_id,
                                    target=self.target,
                                )
                                self.logger.info(f"Detected WAF: {waf_name} protecting {hostname}", module=self.config.name)
                    except Exception:
                        pass

            tasks = [_check(u) for u in urls]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _detect_waf(self, adapter: Wafw00fAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False, prefix="waf_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=url, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=30)

                wafs = adapter.parse_output_file(tmp_path)
                hostname = urlparse(url).netloc or url

                for waf_name in wafs:
                    record = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=hostname,
                        name=waf_name,
                        category="WAF",
                        confidence=100.0,
                        source="wafw00f",
                    )
                    self.db.insert_technology(record)

                    await self.events.emit_discovery(
                        event_type=EventType.TECHNOLOGY_DETECTED,
                        source=self.config.name,
                        data={"url": url, "host": hostname, "waf": waf_name},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

            except Exception as exc:
                self.logger.debug(f"WAF detection failed for {url}: {exc}", module=self.config.name)
            finally:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
