"""Katana adapter."""
from __future__ import annotations

import json
import tempfile
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
        target = kwargs.get("target", "")
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        # Katana with headless mode and JSON output
        return ["katana", "-u", target, "-j", "-o", self.tmp_out.name, "-silent", "-headless"]

    def parse(self, result: CommandResult) -> list[URLRecord]:
        urls = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.load(line)
                            url = data.get("request", {}).get("endpoint") or data.get("url")
                            method = data.get("request", {}).get("method", "GET")
                            status = data.get("response", {}).get("status_code")
                            if url:
                                urls.append(URLRecord(
                                    scan_id="",
                                    url=url,
                                    method=method,
                                    status_code=status,
                                    source="katana"
                                ))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return urls
