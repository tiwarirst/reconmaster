"""WafW00f adapter — stateless, no shared instance state.

BUG FIX: Removed self.tmp_out shared state. The module now owns the temp
file lifecycle. Also handles plain-text wafw00f output (when JSON mode
fails or isn't supported by the installed version).

wafw00f --output / -o with JSON flag:
  wafw00f <url> -o output.json
  The JSON output format is:
    [{"url": "https://...", "detected": true, "firewall": "Cloudflare", ...}]
  But older wafw00f versions write plain-text instead — we handle both.
"""
from __future__ import annotations

import json
import re
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
        target: str = kwargs["target"]
        output_file: Path = kwargs["output_file"]
        return ["wafw00f", target, "-o", str(output_file), "-f", "json"]

    def parse_output_file(self, path: Path) -> list[dict]:
        """Parse wafw00f output file — handles both JSON and plain-text.

        Stateless: caller owns the file lifecycle.
        """
        wafs: list[dict] = []
        if not path.exists() or path.stat().st_size == 0:
            return wafs

        raw = path.read_text(errors="replace").strip()
        if not raw:
            return wafs

        # Try JSON first
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for entry in data:
                    fw = entry.get("firewall") or entry.get("waf")
                    if fw and str(fw).lower() not in ("none", "no waf", ""):
                        wafs.append({"url": entry.get("url", ""), "firewall": fw})
            return wafs
        except json.JSONDecodeError:
            pass

        # Fall back to plain-text parsing:
        # "The site https://example.com is behind Cloudflare Web Application Firewall"
        for line in raw.splitlines():
            match = re.search(
                r"is behind\s+(.+?)\s+(?:Web Application Firewall|WAF|firewall)",
                line, re.IGNORECASE,
            )
            if match:
                wafs.append({"url": "", "firewall": match.group(1).strip()})

        return wafs

    # Legacy shim
    def parse(self, result: CommandResult) -> list[dict]:
        return []
