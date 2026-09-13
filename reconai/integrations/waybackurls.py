"""Waybackurls adapter."""
from __future__ import annotations

from typing import Any

from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class WaybackurlsAdapter(ToolAdapter):
    name = "waybackurls"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        domain = kwargs.get("domain", "")
        # waybackurls reads from stdin by default if domain is not passed in some specific flags
        # Alternatively, we can just echo it in bash, but it's safer to use the positional arg if the tool supports it.
        # Actually waybackurls takes the domain as a positional argument: waybackurls example.com
        return ["waybackurls", domain]

    def parse(self, result: CommandResult) -> list[str]:
        if result.failed or not result.has_output:
            return []
        
        urls = []
        for line in result.output_lines:
            line = line.strip()
            if line.startswith("http"):
                urls.append(line)
        return urls
