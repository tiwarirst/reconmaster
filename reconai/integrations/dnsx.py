"""DNSx adapter — stateless, concurrent-safe.

Fix: Removed self.tmp_out (same race condition as other adapters).
The module creates and owns the output file path, passing it via kwargs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import DNSRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class DnsxAdapter(ToolAdapter):
    """Stateless DNSx adapter.

    Concurrency contract:
      - build_command() does NOT mutate self.
      - parse_output_file() is a pure function of the given path.
    """

    name = "dnsx"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build a DNSx command.

        Args:
            domain_file: Path to file containing one domain per line.
            output_file: Path where DNSx writes JSON output.
                         Created and owned by the calling module.
        """
        domain_file: str = kwargs.get("domain_file", "")
        output_file: Path | str = kwargs.get("output_file", "")

        cmd = ["dnsx", "-l", domain_file, "-j", "-silent", "-a", "-aaaa", "-cname"]
        if output_file:
            cmd.extend(["-o", str(output_file)])
        return cmd

    def parse_output_file(self, path: Path) -> list[DNSRecord]:
        """Parse DNSx JSONL output. Each line is an independent JSON record."""
        records: list[DNSRecord] = []
        try:
            if not path.exists() or path.stat().st_size == 0:
                return records

            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        data: dict[str, Any] = json.loads(line)
                        host: str = data.get("host", "")

                        for a_rec in data.get("a", []):
                            records.append(DNSRecord(
                                scan_id="", hostname=host, record_type="A",
                                value=str(a_rec), source="dnsx",
                            ))
                        for aaaa_rec in data.get("aaaa", []):
                            records.append(DNSRecord(
                                scan_id="", hostname=host, record_type="AAAA",
                                value=str(aaaa_rec), source="dnsx",
                            ))
                        for cname_rec in data.get("cname", []):
                            records.append(DNSRecord(
                                scan_id="", hostname=host, record_type="CNAME",
                                value=str(cname_rec), source="dnsx",
                            ))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

        return records

    def parse(self, result: CommandResult) -> list[Any]:
        """Required by ToolAdapter base class — not used for DNSx."""
        return []
