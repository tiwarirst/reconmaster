"""Arjun HTTP Parameter Discovery Adapter.

Arjun finds hidden GET/POST HTTP query parameters.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import APIEndpoint, URLRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class ArjunAdapter(ToolAdapter):
    name = "arjun"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target: str = kwargs["target"]
        output_file: Path = kwargs["output_file"]
        method: str = kwargs.get("method", "GET").upper()
        threads: int = kwargs.get("threads", 10)

        cmd = [
            "arjun",
            "-u", target,
            "-m", method,
            "-oJ", str(output_file),
            "-t", str(threads),
            "--passive",
        ]
        return cmd

    def parse_output_file(self, path: Path) -> tuple[list[APIEndpoint], list[URLRecord]]:
        """Parse Arjun JSON output containing discovered parameters."""
        endpoints: list[APIEndpoint] = []
        urls: list[URLRecord] = []

        if not path.exists() or path.stat().st_size == 0:
            return endpoints, urls

        try:
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            data = json.loads(content)
            # Arjun JSON schema: dict mapping url -> list of param names or dict with params
            for url, params in data.items():
                if not isinstance(params, list):
                    if isinstance(params, dict):
                        params = list(params.keys())
                    else:
                        continue

                host = url.split("://")[-1].split("/")[0].split(":")[0]
                path_part = "/" + url.split("://")[-1].split("/", 1)[-1] if "/" in url.split("://")[-1] else "/"

                # Build parameterized URL
                query_string = "&".join(f"{p}=FUZZ" for p in params)
                full_param_url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"

                endpoints.append(APIEndpoint(
                    scan_id="",
                    host=host,
                    method="GET",
                    path=path_part,
                    full_url=full_param_url,
                    source="arjun",
                    api_type="rest",
                ))

                urls.append(URLRecord(
                    scan_id="",
                    url=full_param_url,
                    method="GET",
                    source="arjun",
                ))

        except Exception:
            pass

        return endpoints, urls

    def parse(self, result: CommandResult) -> list[APIEndpoint]:
        return []
