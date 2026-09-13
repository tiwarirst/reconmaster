"""Naabu adapter."""
from __future__ import annotations

import json
import tempfile
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
        target = kwargs.get("target", "")
        # Output JSON to a temporary file
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        return ["naabu", "-host", target, "-json", "-o", self.tmp_out.name, "-silent"]

    def parse(self, result: CommandResult) -> list[PortRecord]:
        ports = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            port = data.get("port")
                            host = data.get("host")
                            if port and host:
                                ports.append(PortRecord(
                                    scan_id="", # Handled by module
                                    host=host,
                                    port=int(port),
                                    protocol="tcp", # naabu default is tcp
                                    state="open",
                                    source="naabu"
                                ))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return ports
