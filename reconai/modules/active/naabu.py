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
        description="Extremely fast SYN port scanning using Naabu (with TCP connect fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        hosts = list(kwargs.get("hosts", []))
        if not hosts:
            ips_records = self.db.get_ips(self.scan_id)
            hosts = [record["ip"] for record in ips_records]

        if not hosts and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                hosts = [clean]

        if not hosts:
            return

        adapter = NaabuAdapter(self.runner)
        has_naabu = await adapter.is_available()

        self.logger.module_start(self.config.name, target=f"{len(hosts)} hosts")
        start = time.monotonic()

        if has_naabu:
            semaphore = asyncio.Semaphore(5)
            tasks = [self._scan_host(adapter, semaphore, host) for host in hosts[:150]]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            self.record_warning(
                "Naabu not installed in PATH. Install: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'. "
                "Ran built-in TCP socket probe fallback."
            )
            await self._fast_socket_probe(hosts[:150])

        self.logger.module_complete(self.config.name, duration=time.monotonic() - start)

    async def _fast_socket_probe(self, hosts: list[str]) -> None:
        """Fast TCP probe across top web and administration ports."""
        from reconai.core.database.models import PortRecord
        ports = [80, 443, 8080, 8443, 22, 3306, 5432, 8000, 8888, 9000]
        semaphore = asyncio.Semaphore(30)
        found_records: list[PortRecord] = []
        lock = asyncio.Lock()

        async def _check(host: str, port: int) -> None:
            async with semaphore:
                try:
                    conn = asyncio.open_connection(host, port)
                    _, writer = await asyncio.wait_for(conn, timeout=1.8)
                    writer.close()
                    await writer.wait_closed()
                    rec = PortRecord(
                        scan_id=self.scan_id,
                        host=host,
                        port=port,
                        protocol="tcp",
                        state="open",
                        service="http" if port in (80, 8080, 8000, 8888) else "https" if port in (443, 8443) else "ssh" if port == 22 else "service",
                        source="naabu_fallback",
                    )
                    async with lock:
                        found_records.append(rec)
                    await self.events.emit_discovery(
                        event_type=EventType.PORT_DISCOVERED,
                        source=self.config.name,
                        data={"host": host, "port": port, "protocol": "tcp"},
                        scan_id=self.scan_id,
                        target=self.target,
                    )
                except Exception:
                    pass

        tasks = [_check(h, p) for h in hosts for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)

        if found_records:
            self.db.insert_ports_batch(found_records)

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
                for pr in port_records:
                    pr.scan_id = self.scan_id

                if port_records:
                    self.db.insert_ports_batch(port_records)

                for port_record in port_records:
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
