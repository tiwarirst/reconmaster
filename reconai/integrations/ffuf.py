"""FFuF adapter — stateless, correct JSON key mapping.

Fixes applied:
  BUG 1: Removed self.tmp_out — same concurrent-overwrite race as Nuclei/Dalfox.
         The module now creates and owns the output file path.
  BUG 5: Fixed wrong JSON key `content-type` (hyphen) → `content_type` (underscore).
         FFuF's JSON output uses underscore. The hyphen key silently returned
         empty string for every discovered URL, so content type was never stored.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import URLRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class FfufAdapter(ToolAdapter):
    """Stateless FFuF directory fuzzing adapter.

    Concurrency contract:
      - build_command() does NOT mutate self.
      - parse_output_file() is a pure function of the given path.
      - Multiple concurrent calls with different paths are fully safe.
    """

    name = "ffuf"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build an FFuF command.

        Args:
            target:      Base URL. FUZZ placeholder appended automatically.
            wordlist:    Path to the wordlist file.
            output_file: Path where FFuF writes JSON output.
                         Created and owned by the calling module.
        """
        target: str = kwargs.get("target", "")
        wordlist: str = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        output_file: Path | str = kwargs.get("output_file", "")

        url = target.rstrip("/") + "/FUZZ"
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-of", "json", "-s"]
        if output_file:
            cmd.extend(["-o", str(output_file)])
        return cmd

    def parse_output_file(self, path: Path) -> list[URLRecord]:
        """Parse FFuF's JSON output file.

        FFuF writes a single JSON object with a top-level "results" array.
        If FFuF is killed mid-run the file may be truncated; we guard with
        a broad except and return whatever was parsed successfully.

        Args:
            path: Output file path given to build_command.
        """
        urls: list[URLRecord] = []
        try:
            if not path.exists() or path.stat().st_size == 0:
                return urls

            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data: dict[str, Any] = json.load(fh)

            for entry in data.get("results", []):
                status = entry.get("status")
                if status and int(status) < 400:
                    urls.append(
                        URLRecord(
                            scan_id="",  # Set by module
                            url=entry.get("url", ""),
                            method="GET",
                            status_code=int(status),
                            content_length=entry.get("length", 0),
                            # Fix BUG 5: FFuF uses underscore, not hyphen
                            content_type=entry.get("content_type", ""),
                            source="ffuf",
                        )
                    )
        except Exception:
            pass

        return urls

    def parse(self, result: CommandResult) -> list[Any]:
        """Required by ToolAdapter base class — not used for FFuF.

        FFuF writes to a JSON file via -o; the module calls parse_output_file().
        """
        return []
