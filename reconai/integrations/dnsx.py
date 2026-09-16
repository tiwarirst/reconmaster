"""DNSx adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from reconai.core.database.models import DNSRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class DnsxAdapter(ToolAdapter):
    name = "dnsx"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        domain_file = kwargs.get("domain_file", "")
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        # DNSx resolve, wildcard filtering, JSON output
        return ["dnsx", "-l", domain_file, "-j", "-o", self.tmp_out.name, "-silent", "-a", "-aaaa", "-cname"]

    def parse(self, result: CommandResult) -> list[DNSRecord]:
        records = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            host = data.get("host")
                            a_records = data.get("a", [])
                            
                            for a in a_records:
                                records.append(DNSRecord(
                                    scan_id="",
                                    hostname=host,
                                    record_type="A",
                                    value=a,
                                    source="dnsx"
                                ))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return records
