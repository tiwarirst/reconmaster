"""WafW00f adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class Wafw00fAdapter(ToolAdapter):
    name = "wafw00f"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target = kwargs.get("target", "")
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        return ["wafw00f", target, "-o", self.tmp_out.name]

    def parse(self, result: CommandResult) -> list[dict]:
        wafs = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for entry in data:
                            if "firewall" in entry and entry["firewall"] != "None":
                                wafs.append({
                                    "url": entry.get("url", ""),
                                    "firewall": entry["firewall"]
                                })
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return wafs
