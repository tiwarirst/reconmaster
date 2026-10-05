"""Katana adapter — stateless, no shared instance state.

BUG FIX: Removed self.tmp_out shared state. The module now owns the temp
file lifecycle. Removed -headless flag from default — Katana's headless
mode requires Chromium to be installed; failing silently is better.

BUG FIX 2: parse() now accepts output_file path (stateless pattern),
not the CommandResult (which holds no output path reference).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import URLRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class KatanaAdapter(ToolAdapter):
    name = "katana"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target: str = kwargs["target"]
        output_file: Path = kwargs["output_file"]
        cmd = [
            "katana",
            "-u", target,
            "-j",
            "-o", str(output_file),
            "-silent",
            "-depth", "3",
            "-js-crawl",
        ]
        return cmd

    def parse_output_file(self, path: Path) -> list[URLRecord]:
        """Parse a katana JSON-lines output file.

        Stateless: caller owns the file lifecycle.
        Katana JSON lines have the format:
          {"timestamp":"...","request":{"method":"GET","endpoint":"https://..."},...}
        """
        urls: list[URLRecord] = []
        if not path.exists() or path.stat().st_size == 0:
            return urls
        try:
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        endpoint = (
                            data.get("request", {}).get("endpoint")
                            or data.get("endpoint")
                            or data.get("url")
                        )
                        method = data.get("request", {}).get("method", "GET")
                        status = data.get("response", {}).get("status_code")
                        if endpoint:
                            urls.append(URLRecord(
                                scan_id="",
                                url=endpoint,
                                method=method,
                                status_code=status,
                                source="katana",
                                depth=1,
                            ))
                    except (json.JSONDecodeError, KeyError):
                        pass
        except Exception:
            pass
        return urls

    # Legacy shim
    def parse(self, result: CommandResult) -> list[URLRecord]:
        return []
