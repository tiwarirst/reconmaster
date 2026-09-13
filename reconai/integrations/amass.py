"""Amass adapter."""
from __future__ import annotations

from typing import Any

from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class AmassAdapter(ToolAdapter):
    name = "amass"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        domain = kwargs.get("domain", "")
        passive = kwargs.get("passive", True)
        
        cmd = ["amass", "enum", "-d", domain, "-nocolor"]
        if passive:
            cmd.append("-passive")
        return cmd

    def parse(self, result: CommandResult) -> list[str]:
        if result.failed or not result.has_output:
            return []
        
        subdomains = []
        for line in result.output_lines:
            line = line.strip()
            # Basic parsing, Amass output can be noisy depending on flags
            if line and " " not in line and "." in line:
                subdomains.append(line.lower())
        return subdomains
