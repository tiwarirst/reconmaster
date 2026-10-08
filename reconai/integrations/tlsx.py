"""tlsx adapter — ProjectDiscovery TLS/SSL grabber & SAN subdomain extractor."""
from __future__ import annotations

import json
import shutil
from typing import Any

from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class TlsxAdapter(ToolAdapter):
    """Adapter for projectdiscovery/tlsx."""

    name: str = "tlsx"

    async def is_available(self) -> bool:
        """Check if tlsx is installed and accessible."""
        if shutil.which("tlsx"):
            return True
        avail, _ = await self.runner.check_tool("tlsx")
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build tlsx command with rich TLS probes.

        Parameters:
            targets (list[str] | str): Domain(s) or host(s) to probe
            input_file (str | Path): Input file with targets
            concurrency (int): Worker threads (default: 20)
            timeout (int): Per-host probe timeout (default: 5)
        """
        targets = kwargs.get("targets")
        input_file = kwargs.get("input_file")
        concurrency = kwargs.get("concurrency", 20)
        timeout = kwargs.get("timeout", 5)

        cmd = [
            "tlsx",
            "-json",
            "-san",
            "-cn",
            "-resp-version",
            "-jarm",
            "-expired",
            "-silent",
            "-timeout", str(timeout),
        ]
        if concurrency:
            cmd.extend(["-c", str(concurrency)])

        if input_file:
            cmd.extend(["-l", str(input_file)])
        elif targets:
            if isinstance(targets, list):
                cmd.extend(["-u", ",".join(targets)])
            else:
                cmd.extend(["-u", str(targets)])
        return cmd

    def parse(self, result: CommandResult) -> list[dict[str, Any]]:
        """Parse JSON output from tlsx into structured TLS intelligence."""
        if result.failed or not result.has_output:
            return []

        entries: list[dict[str, Any]] = []
        for line in result.output_lines:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                sans = data.get("subject_an", []) or []
                if isinstance(sans, str):
                    sans = [sans]

                issuer_org = data.get("issuer_org", []) or []
                if isinstance(issuer_org, str):
                    issuer_org = [issuer_org]

                entries.append({
                    "host": data.get("host", ""),
                    "port": data.get("port", 443),
                    "ip": data.get("ip", ""),
                    "subject_cn": data.get("subject_cn", ""),
                    "subject_an": sans,
                    "issuer_cn": data.get("issuer_cn", ""),
                    "issuer_org": issuer_org,
                    "tls_version": data.get("tls_version", ""),
                    "cipher": data.get("cipher", ""),
                    "jarm": data.get("jarm", ""),
                    "expired": bool(data.get("expired", False)),
                })
            except Exception:
                continue
        return entries
