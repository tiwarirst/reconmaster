"""Port Scanning Module.

Uses Nmap to scan discovered IP addresses/hosts.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from reconai.core.config.defaults import SCAN_PROFILES
from reconai.core.events.types import EventType
from reconai.integrations.nmap import NmapAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class PortScanModule(ReconModule):
    config = ModuleConfig(
        name="ports",
        category="active",
        description="Port scanning and service detection using Nmap",
        requires_tools=["nmap"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        profile_name = kwargs.get("profile", "quick")
        hosts = kwargs.get("hosts", [])
        
        if not hosts:
            ips_records = self.db.get_ips(self.scan_id)
            hosts = [record["ip"] for record in ips_records]
            
        if not hosts:
            return

        adapter = NmapAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("Nmap not available. Skipping port scan.", module=self.config.name)
            return

        profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["quick"])
        nmap_args = profile["nmap_args"]

        self.logger.module_start(self.config.name, target=f"{len(hosts)} hosts with profile '{profile_name}'")

        # Concurrency limit for Nmap instances (nmap is already concurrent internally, so keep this low)
        concurrency = 2
        semaphore = asyncio.Semaphore(concurrency)

        tasks = [self._scan_host(adapter, semaphore, host, nmap_args) for host in hosts]
        await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _scan_host(self, adapter: NmapAdapter, semaphore: asyncio.Semaphore, host: str, args: list[str]) -> None:
        async with semaphore:
            # Create a temporary file for Nmap XML output
            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp_file:
                xml_path = Path(tmp_file.name)
                
            try:
                cmd = adapter.build_command(target=host, args=args, output_xml=xml_path)
                
                # Determine appropriate timeout based on args
                timeout = 120
                if "-p-" in args:
                    timeout = 600
                elif "-sC" in args:
                    timeout = 300
                    
                result = await self.runner.run(command=cmd, timeout=timeout)
                
                if xml_path.exists() and xml_path.stat().st_size > 0:
                    parsed = adapter.parse_xml(xml_path, self.scan_id)
                    
                    # Store ports and emit events
                    for port_record in parsed.get("ports", []):
                        self.db.insert_port(port_record)
                        await self.events.emit_discovery(
                            event_type=EventType.PORT_DISCOVERED,
                            source=self.config.name,
                            data={"host": host, "port": port_record.port, "protocol": port_record.protocol},
                            scan_id=self.scan_id,
                            target=self.target
                        )
                        
                    # Store services and emit events
                    for svc_record in parsed.get("services", []):
                        self.db.insert_service(svc_record)
                        await self.events.emit_discovery(
                            event_type=EventType.SERVICE_DISCOVERED,
                            source=self.config.name,
                            data={"host": host, "port": svc_record.port, "service": svc_record.service, "product": svc_record.product},
                            scan_id=self.scan_id,
                            target=self.target
                        )
                        
            except Exception as e:
                self.logger.debug(f"Nmap scan failed for {host}: {e}")
            finally:
                if xml_path.exists():
                    xml_path.unlink(missing_ok=True)
