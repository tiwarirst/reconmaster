"""gau (GetAllUrls) adapter — fetches known URLs from AlienVault OTX, Wayback Machine, and Common Crawl."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from reconai.core.executor.command_runner import CommandRunner
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class GauAdapter(ToolAdapter):
    """Adapter for lc/gau (GetAllUrls) tool."""

    name: str = "gau"

    async def is_available(self) -> bool:
        """Check if gau binary is available on system PATH or runner environment."""
        if shutil.which("gau") or shutil.which("gauplus"):
            return True
        avail, _ = await self.runner.check_tool("gau")
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build the gau command.

        Parameters:
            domain (str): Target domain
            threads (int): Concurrency limit (default: 5)
            include_subs (bool): Include subdomains (default: True)
            providers (list[str]): List of providers (e.g. ['wayback', 'commoncrawl', 'otx', 'urlscan'])
        """
        domain = kwargs.get("domain", "")
        threads = kwargs.get("threads", 5)
        include_subs = kwargs.get("include_subs", True)
        providers = kwargs.get("providers")

        bin_name = "gau" if shutil.which("gau") else "gauplus"

        cmd = [bin_name]
        if include_subs:
            cmd.append("--subs")
        if threads:
            cmd.extend(["--threads", str(threads)])
        if providers:
            cmd.extend(["--providers", ",".join(providers)])

        cmd.append(domain)
        return cmd

    def parse(self, result: CommandResult) -> list[str]:
        """Parse raw gau output into unique URLs."""
        if result.failed or not result.has_output:
            return []

        urls: list[str] = []
        for line in result.output_lines:
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
        return urls
