"""FFuF adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from reconai.core.database.models import URLRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class FfufAdapter(ToolAdapter):
    name = "ffuf"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target = kwargs.get("target", "")
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        url = target.rstrip("/") + "/FUZZ"
        
        return ["ffuf", "-u", url, "-w", wordlist, "-o", self.tmp_out.name, "-of", "json", "-s"]

    def parse(self, result: CommandResult) -> list[URLRecord]:
        urls = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path, "r") as f:
                    data = json.load(f)
                    results = data.get("results", [])
                    for entry in results:
                        status = entry.get("status")
                        if status and status < 400:
                            urls.append(URLRecord(
                                scan_id="",
                                url=entry.get("url", ""),
                                method="GET",
                                status_code=status,
                                content_length=entry.get("length", 0),
                                content_type=entry.get("content-type", ""),
                                source="ffuf"
                            ))
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return urls
