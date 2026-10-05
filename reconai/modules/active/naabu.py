"""Fast Port Scanning Module.

Uses Naabu for extremely fast open-port discovery.

FIXES APPLIED:
  BUG 1 (Race condition): Each _scan_host() call now creates its own
    isolated temp file and passes the path to build_command + parse_output_file.
    The adapter is now fully stateless — no shared self.tmp_out.
  BUG 2 (Missing duration telemetry): module_complete() now receives
    actual wall-clock duration.
  BUG 3 (return_exceptions missing): asyncio.gather now has
    return_exceptions=True so one failing host doesn't cancel others.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.naabu import NaabuAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class NaabuPortScanModule(ReconModule):
    config = ModuleConfig(
        name="naabu_ports",
        category="active",
        description="Extremely fast SYN port scanning using Naabu",
        requires_tools=["naabu"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        hosts = list(kwargs.get("hosts", []))
        if not hosts:
            ips_records = self.db.get_ips(self.scan_id)
            hosts = [record["ip"] for record in ips_records]

        if not hosts:
            return

        adapter = NaabuAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("Naabu not available. Skipping fast port scan.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(hosts)} hosts")
        start = time.monotonic()

        semaphore = asyncio.Semaphore(2)
        tasks = [self._scan_host(adapter, semaphore, host) for host in hosts]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name, duration=time.monotonic() - start)

    async def _scan_host(self, adapter: NaabuAdapter, semaphore: asyncio.Semaphore, host: str) -> None:
        async with semaphore:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False, prefix="naabu_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=host, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=300)

                port_records = adapter.parse_output_file(tmp_path)

                for port_record in port_records:
                    port_record.scan_id = self.scan_id
                    self.db.insert_port(port_record)

                    await self.events.emit_discovery(
                        event_type=EventType.PORT_DISCOVERED,
                        source=self.config.name,
                        data={"host": port_record.host, "port": port_record.port, "protocol": port_record.protocol},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

                self.logger.info(
                    f"Naabu found {len(port_records)} open port(s) on {host}",
                    module=self.config.name,
                )

            except Exception as exc:
                self.logger.debug(f"Naabu scan failed for {host}: {exc}", module=self.config.name)
            finally:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
