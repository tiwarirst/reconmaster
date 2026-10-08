"""ProjectDiscovery httpx tool adapter.

High-performance HTTP probing and technology identification.
Translates JSON-lines output from httpx CLI into URLRecord and TechnologyRecord models.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.models import TechnologyRecord, URLRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class HttpxAdapter(ToolAdapter):
    name = "httpx"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target: str = kwargs.get("target", "")
        targets_file: Path | None = kwargs.get("targets_file")
        output_file: Path = kwargs["output_file"]
        threads: int = kwargs.get("threads", 50)

        cmd = [
            "httpx",
            "-silent",
            "-json",
            "-o", str(output_file),
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-follow-redirects",
            "-threads", str(threads),
            "-timeout", "10",
        ]

        if targets_file:
            cmd.extend(["-l", str(targets_file)])
        elif target:
            cmd.extend(["-u", target])

        return cmd

    def parse_output_file(self, path: Path) -> tuple[list[URLRecord], list[TechnologyRecord]]:
        """Parse httpx JSON-lines output file into URL and Technology records."""
        urls: list[URLRecord] = []
        techs: list[TechnologyRecord] = []

        if not path.exists() or path.stat().st_size == 0:
            return urls, techs

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        raw_url = data.get("url") or data.get("input")
                        if not raw_url:
                            continue

                        status = int(data.get("status_code", 0) or data.get("status-code", 0))
                        title = data.get("title", "")
                        cl = int(data.get("content_length", 0) or data.get("content-length", 0))
                        ctype = data.get("content_type", "") or data.get("content-type", "")
                        final_url = data.get("final_url", "") or data.get("final-url", "")
                        host = data.get("host", "") or raw_url.split("://")[-1].split("/")[0].split(":")[0]

                        urls.append(URLRecord(
                            scan_id="",
                            url=raw_url,
                            method="GET",
                            status_code=status,
                            content_type=ctype,
                            content_length=cl,
                            title=title,
                            redirect_url=final_url if final_url != raw_url else "",
                            source="httpx_cli",
                        ))

                        # Parse extracted technologies
                        detected_techs = data.get("tech") or data.get("technologies") or []
                        for tech_name in detected_techs:
                            techs.append(TechnologyRecord(
                                scan_id="",
                                host=host,
                                name=tech_name,
                                category="web",
                                confidence="high",
                                source="httpx_cli",
                                evidence={"url": raw_url, "status": status},
                            ))

                    except (json.JSONDecodeError, ValueError):
                        continue
        except Exception:
            pass

        return urls, techs

    def parse(self, result: CommandResult) -> list[URLRecord]:
        return []
