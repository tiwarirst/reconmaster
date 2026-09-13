"""ParamSpider adapter."""
from __future__ import annotations

import os
from typing import Any

from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class ParamspiderAdapter(ToolAdapter):
    name = "paramspider"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        domain = kwargs.get("domain", "")
        # By default, paramspider outputs to results/{domain}.txt in the cwd
        return ["paramspider", "-d", domain]

    def parse(self, result: CommandResult, domain: str = "") -> list[str]:
        urls = []
        out_file = f"results/{domain}.txt"
        try:
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    for line in f:
                        if line.strip() and line.startswith("http"):
                            urls.append(line.strip())
                # Cleanup
                os.remove(out_file)
        except Exception:
            pass
            
        return urls
