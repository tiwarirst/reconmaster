"""Directory Discovery Module.

Pure Python, asynchronous, cross-platform directory brute-forcing.
Works out-of-the-box on Linux, macOS, WSL, and Windows without external tools.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from reconai.core.database.models import URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# High-signal standard reconnaissance paths
_DEFAULT_PATHS = [
    "admin", "api", "login", "auth", "portal", "dashboard", "console",
    "v1", "v2", "v3", "api/v1", "api/v2", "swagger", "docs", "swagger.json",
    "openapi.json", "api-docs", "graphql", "graphql/console", "graphiql",
    ".env", ".git", ".git/HEAD", "robots.txt", "sitemap.xml",
    "health", "healthz", "metrics", "actuator", "actuator/health", "actuator/env",
    "server-status", "status", "info", "debug", "trace",
    "backup", "backups", "backup.sql", "dump.sql", "db", "database",
    "test", "dev", "staging", "internal", "private", "secret", "config",
    "wp-admin", "wp-login.php", "administrator", "cpanel", "webmail",
    "phpinfo.php", "manager/html", "user", "users", "account", "register",
    "static", "assets", "uploads", "files", "download", "downloads",
]


@register_module
class DirectoryDiscoveryModule(ReconModule):
    config = ModuleConfig(
        name="directory_discovery",
        category="web",
        description="Fast asynchronous directory brute-forcing with high-signal wordlist",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        start = time.monotonic()

        # 1. Collect unique base origins to scan
        base_urls: set[str] = set()

        for u in kwargs.get("urls", []):
            try:
                p = urlparse(str(u))
                if p.scheme in ("http", "https") and p.netloc:
                    base_urls.add(f"{p.scheme}://{p.netloc}")
            except Exception:
                continue

        # Check DB for probed URLs
        db_urls = self.db.get_urls(self.scan_id)
        for r in db_urls:
            try:
                u_str = str(r.get("url", ""))
                p = urlparse(u_str)
                if p.scheme in ("http", "https") and p.netloc:
                    base_urls.add(f"{p.scheme}://{p.netloc}")
            except Exception:
                continue

        # Fallback to target if none discovered yet
        if not base_urls and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            base_urls.add(f"https://{clean}")
            base_urls.add(f"http://{clean}")

        if not base_urls:
            self.logger.warning("No targets available for directory discovery.", module=self.config.name)
            self.logger.module_complete(self.config.name, duration=time.monotonic() - start)
            return

        # 2. Select Wordlist
        words = self._load_wordlist(kwargs.get("wordlist"))

        self.logger.module_start(
            self.config.name,
            target=f"{len(base_urls)} host(s), {len(words)} paths each",
        )

        semaphore = asyncio.Semaphore(15)
        discovered_count = 0

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconAI/1.0"},
        ) as client:
            tasks = []
            for base_url in list(base_urls)[:10]:  # Cap at top 10 hosts to prevent excess delay
                for word in words:
                    target_url = f"{base_url.rstrip('/')}/{word.lstrip('/')}"
                    tasks.append(self._check_dir(client, semaphore, target_url))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if res is True:
                    discovered_count += 1

        self.logger.info(
            f"Directory discovery complete: found {discovered_count} accessible endpoint(s)",
            module=self.config.name,
        )
        self.logger.module_complete(self.config.name, duration=time.monotonic() - start)

    def _load_wordlist(self, custom_path: str | None) -> list[str]:
        if custom_path and Path(custom_path).exists():
            with open(custom_path, encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Check standard Linux SecLists / Wordlists paths if on Linux
        linux_paths = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for p in linux_paths:
            if os.path.isfile(p):
                try:
                    with open(p, encoding="utf-8", errors="ignore") as f:
                        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                        if lines:
                            return lines[:500]  # Cap at 500 for reasonable scan time
                except Exception:
                    pass

        # High-signal embedded defaults
        return list(_DEFAULT_PATHS)

    async def _check_dir(
        self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, url: str
    ) -> bool:
        async with semaphore:
            try:
                response = await client.get(url)
                # Flag 200 OK, 301/302 Redirects, 401 Unauthorized, 403 Forbidden
                if response.status_code in (200, 204, 301, 302, 307, 308, 401, 403):
                    record = URLRecord(
                        scan_id=self.scan_id,
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        content_length=len(response.content),
                        redirect_url=response.headers.get("location", ""),
                        source="directory_discovery",
                    )
                    self.db.insert_url(record)

                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": url, "status": response.status_code},
                        scan_id=self.scan_id,
                        target=self.target,
                    )
                    return True
            except Exception:
                pass
        return False
