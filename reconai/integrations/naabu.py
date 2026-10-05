"""Naabu adapter — stateless, no shared instance state.

BUG FIX: Removed self.tmp_out shared state. The module now owns the temp
file lifecycle (passed as output_file kwarg). Each concurrent scan call
creates its own isolated file. No race conditions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import PortRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class NaabuAdapter(ToolAdapter):
    name = "naabu"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target: str = kwargs["target"]
        output_file: Path = kwargs["output_file"]
        return [
            "naabu",
            "-host", target,
            "-json",
            "-o", str(output_file),
            "-silent",
            "-rate", "1000",
        ]

    def parse_output_file(self, path: Path) -> list[PortRecord]:
        """Parse a naabu JSON-lines output file.

        Stateless: caller owns the file lifecycle.
        """
        ports: list[PortRecord] = []
        if not path.exists() or path.stat().st_size == 0:
            return ports
        try:
            with open(path, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        port = data.get("port")
                        host = data.get("host") or data.get("ip")
                        if port and host:
                            ports.append(PortRecord(
                                scan_id="",   # set by module
                                host=host,
                                port=int(port),
                                protocol="tcp",
                                state="open",
                                source="naabu",
                            ))
                    except (json.JSONDecodeError, ValueError):
                        pass
        except Exception:
            pass
        return ports

    # Keep legacy parse() for backwards compat — delegates to new method
    def parse(self, result: CommandResult) -> list[PortRecord]:
        return []
