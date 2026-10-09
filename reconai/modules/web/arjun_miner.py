"""Arjun Parameter Discovery Module.

Discovers hidden query parameters across web endpoints using Arjun CLI
with high-speed pure-Python differential analysis fallback.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from reconai.core.database.models import APIEndpoint, URLRecord
from reconai.core.events.types import EventType
from reconai.integrations.arjun import ArjunAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# Top high-signal red teaming parameter candidates for pure-Python fallback
TOP_PARAMETERS: list[str] = [
    "debug", "test", "admin", "redirect", "url", "next", "return", "dest",
    "api_key", "secret", "token", "auth", "key", "id", "user", "file", "path",
    "view", "page", "include", "cmd", "exec", "query", "callback", "action",
]


@register_module
class ArjunParamsModule(ReconModule):
    config = ModuleConfig(
        name="arjun_params",
        category="web",
        description="Hidden HTTP parameter discovery using Arjun (with pure-Python differential fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        url_records = self.db.get_urls(self.scan_id)
        candidate_urls: list[str] = [r["url"] for r in url_records if r.get("url")]

        if not candidate_urls and self.target:
            base = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
            candidate_urls = [base, f"{base}/api"]

        if not candidate_urls:
            return

        # Target top 2 representative base endpoints to avoid scan bloat
        sample_urls = candidate_urls[:2]

        adapter = ArjunAdapter(self.runner)
        has_arjun = await adapter.is_available()

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(sample_urls)} endpoints")

        # Bound per-URL timeout strictly so single endpoint hangs never block pipeline
        per_url_timeout = min(max(self.timeout // max(len(sample_urls), 1), 20), 45)
        deadline = time.monotonic() + self.timeout

        if has_arjun:
            for url in sample_urls:
                if time.monotonic() >= deadline - 5:
                    break
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                    tmp_out = Path(tf.name)
                try:
                    cmd = adapter.build_command(target=url, output_file=tmp_out)
                    await self.runner.run(command=cmd, timeout=per_url_timeout)
                    endpoints, urls = adapter.parse_output_file(tmp_out)

                    for ep in endpoints:
                        ep.scan_id = self.scan_id
                        self.db.insert_api_endpoint(ep)

                    for u in urls:
                        u.scan_id = self.scan_id
                        self.db.insert_url(u)
                        await self.events.emit_discovery(
                            event_type=EventType.URL_DISCOVERED,
                            source=self.config.name,
                            data={"url": u.url, "source": "arjun"},
                            scan_id=self.scan_id,
                            target=self.target,
                        )
                finally:
                    if tmp_out.exists():
                        tmp_out.unlink(missing_ok=True)
        else:
            self.record_warning(
                "Arjun not installed in PATH. Install: 'pip install arjun' (or 'sudo apt install arjun'). "
                "Ran pure-Python parameter differential analysis fallback."
            )
            await self._python_parameter_miner(sample_urls)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _python_parameter_miner(self, urls: list[str]) -> None:
        """High-speed async pure-Python parameter differential fuzzing fallback."""
        sem = asyncio.Semaphore(6)

        async with httpx.AsyncClient(verify=False, timeout=3.5, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            for url in urls:
                try:
                    base_resp = await client.get(url)
                    base_len = len(base_resp.content)
                    base_status = base_resp.status_code
                except Exception:
                    continue

                async def _probe_param(param: str) -> None:
                    async with sem:
                        test_url = f"{url}?{param}=reconai_canary" if "?" not in url else f"{url}&{param}=reconai_canary"
                        try:
                            resp = await client.get(test_url)
                            if resp.status_code != base_status or abs(len(resp.content) - base_len) > 20 or "reconai_canary" in resp.text:
                                host = url.split("://")[-1].split("/")[0].split(":")[0]
                                path_part = "/" + url.split("://")[-1].split("/", 1)[-1] if "/" in url.split("://")[-1] else "/"

                                endpoint = APIEndpoint(
                                    scan_id=self.scan_id,
                                    host=host,
                                    method="GET",
                                    path=path_part,
                                    full_url=test_url,
                                    source="arjun_python_fallback",
                                    api_type="rest",
                                )
                                self.db.insert_api_endpoint(endpoint)

                                url_rec = URLRecord(
                                    scan_id=self.scan_id,
                                    url=test_url,
                                    method="GET",
                                    status_code=resp.status_code,
                                    content_length=len(resp.content),
                                    source="arjun_python_fallback",
                                )
                                self.db.insert_url(url_rec)

                                await self.events.emit_discovery(
                                    event_type=EventType.URL_DISCOVERED,
                                    source=self.config.name,
                                    data={"url": test_url, "param": param, "source": "param_diff"},
                                    scan_id=self.scan_id,
                                    target=self.target,
                                )
                        except Exception:
                            pass

                tasks = [_probe_param(p) for p in TOP_PARAMETERS]
                await asyncio.gather(*tasks, return_exceptions=True)
