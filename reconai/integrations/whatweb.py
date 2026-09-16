"""WhatWeb adapter — stateless, concurrent-safe.

Fix applied (BUG 4):
  Removed self.tmp_out from build_command(). TechnologyModule runs with
  Semaphore(5), so up to 5 concurrent build_command() calls would overwrite
  self.tmp_out 5 times — only the last path would be read by parse(),
  losing 4 out of 5 fingerprint results silently.

  Pattern: module creates and owns the temp file, passes path via kwargs,
  calls parse_output_file(path). Adapter is fully stateless.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class WhatWebAdapter(ToolAdapter):
    """Stateless WhatWeb technology fingerprinting adapter.

    Concurrency contract:
      - build_command() does NOT mutate self.
      - parse_output_file() is a pure function of the given path.
      - Multiple concurrent calls with different paths are fully safe.
    """

    name = "whatweb"

    # Plugin names that add noise without conveying technology stack info
    _SKIP_PLUGINS: frozenset[str] = frozenset({
        "Country", "IP", "Title", "X-UA-Compatible",
        "Meta-Author", "Script", "HTML5",
    })

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build a WhatWeb command.

        Args:
            url:         Target URL to fingerprint.
            output_file: Path where WhatWeb writes JSON log.
                         Created and owned by the calling module.
        """
        url: str = kwargs.get("url", "")
        output_file: Path | str = kwargs.get("output_file", "")

        cmd = ["whatweb", "--color=NEVER", "-a", "1"]
        if output_file:
            cmd.append(f"--log-json={output_file}")
        cmd.append(url)
        return cmd

    def parse_output_file(self, path: Path) -> list[dict[str, Any]]:
        """Parse WhatWeb's JSON log output.

        WhatWeb writes a JSON array. Returns a list of technology dicts
        with keys: name, version, confidence.

        Args:
            path: Output file path given to build_command.
        """
        techs: list[dict[str, Any]] = []
        try:
            if not path.exists() or path.stat().st_size == 0:
                return techs

            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data: Any = json.load(fh)

            if not isinstance(data, list) or not data:
                return techs

            plugins: dict[str, Any] = data[0].get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                if plugin_name in self._SKIP_PLUGINS:
                    continue

                version = ""
                versions = plugin_data.get("version", [])
                if isinstance(versions, list) and versions:
                    version = str(versions[0])

                techs.append({
                    "name":       plugin_name,
                    "version":    version,
                    "confidence": 100.0,
                })

        except Exception:
            pass

        return techs

    def parse(self, result: CommandResult) -> list[Any]:
        """Required by ToolAdapter base class — not used for WhatWeb.

        WhatWeb writes to a JSON log file via --log-json; the module
        calls parse_output_file() directly.
        """
        return []
