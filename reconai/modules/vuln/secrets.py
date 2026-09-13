"""Secret Scanning Module.

Uses TruffleHog to scan downloaded JS files and other assets for secrets.
"""
from __future__ import annotations

import asyncio
import tempfile
import os
from pathlib import Path
from typing import Any

import httpx

from reconai.integrations.trufflehog import TrufflehogAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SecretsModule(ReconModule):
    config = ModuleConfig(
        name="secrets",
        category="vuln",
        description="Scans scripts and assets for leaked secrets using TruffleHog",
        requires_tools=["trufflehog"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        url_records = self.db.get_urls(self.scan_id)
        # Find all JS files
        js_urls = [r["url"] for r in url_records if r["url"].endswith(".js")]
        
        if not js_urls:
            return

        adapter = TrufflehogAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("trufflehog not available. Skipping secret scan.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(js_urls)} JS files")

        # We'll download the JS files to a temp directory and run trufflehog on it
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            
            # Download files
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                tasks = [self._download_file(client, url, tmp_path) for url in js_urls[:50]]
                await asyncio.gather(*tasks)
                
            # Run trufflehog on the directory
            cmd = adapter.build_command(path=str(tmp_path))
            result = await self.runner.run(command=cmd, timeout=120)
            
            findings = adapter.parse(result)
            for finding in findings:
                finding.scan_id = self.scan_id
                self.db.insert_finding(finding)

        self.logger.module_complete(self.config.name)

    async def _download_file(self, client: httpx.AsyncClient, url: str, target_dir: Path) -> None:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
                file_path = target_dir / safe_name
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
        except Exception:
            pass
