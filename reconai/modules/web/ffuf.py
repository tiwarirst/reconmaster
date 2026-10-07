"""Advanced Directory Fuzzing Module.

Uses FFuF for ultra-fast directory discovery with zero-tool pure-Python fallback.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.integrations.ffuf import FfufAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

_HIGH_SIGNAL_PATHS = [
    "admin", "api", "login", "auth", "portal", "dashboard", "console",
    "v1", "v2", "api/v1", "api/v2", "swagger", "docs", "swagger.json",
    "openapi.json", "graphql", ".env", ".git", ".git/HEAD", "robots.txt",
    "sitemap.xml", "health", "metrics", "actuator", "status", "info",
    "backup", "backups", "backup.sql", "db", "test", "dev", "staging",
    "internal", "secret", "config", "wp-admin", "wp-login.php",
    "phpinfo.php", "user", "users", "account", "static", "assets", "uploads",
]


@register_module
class FfufModule(ReconModule):
    config = ModuleConfig(
        name="ffuf_dir",
        category="web",
        description="Fast directory brute-forcing using FFuF (with pure-Python fallback)",
        requires_tools=[],
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
        has_ffuf = await adapter.is_available()

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        if has_ffuf:
            possible_wordlists = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            ]
            wordlist = next((w for w in possible_wordlists if os.path.exists(w)), "")
            temp_wordlist_path: Path | None = None

            if not wordlist:
                # Create a temporary embedded wordlist so FFuF can execute even without SecLists installed
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp_w:
                    tmp_w.write("\n".join(_HIGH_SIGNAL_PATHS))
                    temp_wordlist_path = Path(tmp_w.name)
                    wordlist = str(temp_wordlist_path)

            try:
                semaphore = asyncio.Semaphore(3)
                tasks = [self._fuzz_url(adapter, semaphore, url, wordlist) for url in urls[:5]]
                await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                if temp_wordlist_path and temp_wordlist_path.exists():
                    temp_wordlist_path.unlink(missing_ok=True)
        else:
            self.record_warning(
                "FFuF not installed. Install: 'go install github.com/ffuf/ffuf/v2@latest' (or 'sudo apt install ffuf'). "
                "Running built-in async HTTP directory discovery fallback..."
            )
            await self._pure_python_fuzz(urls[:5])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _fuzz_url(
        self,
        adapter: FfufAdapter,
        semaphore: asyncio.Semaphore,
        url: str,
        wordlist: str,
    ) -> None:
        """Fuzz a single URL for directories using FFuF."""
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

    async def _pure_python_fuzz(self, urls: list[str]) -> None:
        """Built-in async HTTP directory prober when FFuF is not installed."""
        semaphore = asyncio.Semaphore(10)
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=6.0,
            headers={"User-Agent": "Mozilla/5.0 ReconAI-FFuF-Fallback/1.0"},
        ) as client:
            async def _probe(base_url: str, path: str) -> None:
                target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                async with semaphore:
                    try:
                        resp = await client.get(target_url)
                        if resp.status_code in (200, 204, 301, 302, 307, 308, 401, 403):
                            record = URLRecord(
                                scan_id=self.scan_id,
                                url=target_url,
                                method="GET",
                                status_code=resp.status_code,
                                content_length=len(resp.content),
                                redirect_url=resp.headers.get("location", ""),
                                source=self.config.name,
                            )
                            self.db.insert_url(record)
                            await self.events.emit_discovery(
                                event_type=EventType.URL_DISCOVERED,
                                source=self.config.name,
                                data={"url": target_url, "status": resp.status_code},
                                scan_id=self.scan_id,
                                target=self.target,
                            )
                    except Exception:
                        pass

            tasks = []
            for u in urls:
                for p in _HIGH_SIGNAL_PATHS:
                    tasks.append(_probe(u, p))
            await asyncio.gather(*tasks, return_exceptions=True)
