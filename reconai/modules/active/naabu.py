"""Fast Port Scanning Module.

Uses Naabu for extremely fast open-port discovery.
"""
from __future__ import annotations

import asyncio
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
        hosts = kwargs.get("hosts", [])
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

        semaphore = asyncio.Semaphore(2)
        tasks = [self._scan_host(adapter, semaphore, host) for host in hosts]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _scan_host(self, adapter: NaabuAdapter, semaphore: asyncio.Semaphore, host: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=host)
                result = await self.runner.run(command=cmd, timeout=300)
                
                port_records = adapter.parse(result)
                
                for port_record in port_records:
                    port_record.scan_id = self.scan_id
                    self.db.insert_port(port_record)
                    
                    await self.events.emit_discovery(
                        event_type=EventType.PORT_DISCOVERED,
                        source=self.config.name,
                        data={"host": port_record.host, "port": port_record.port, "protocol": port_record.protocol},
                        scan_id=self.scan_id,
                        target=self.target
                    )
                        
            except Exception as e:
                self.logger.debug(f"Naabu scan failed for {host}: {e}")
