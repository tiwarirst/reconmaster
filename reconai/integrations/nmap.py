"""Nmap adapter."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from reconai.core.database.models import PortRecord, ServiceRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    name = "nmap"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        target = kwargs.get("target", "")
        profile_args = kwargs.get("args", ["-T4", "--top-ports", "100"])
        output_xml = kwargs.get("output_xml", "")
        
        cmd = ["nmap", *profile_args]
        if output_xml:
            cmd.extend(["-oX", str(output_xml)])
        
        cmd.append(target)
        return cmd

    def parse(self, result: CommandResult) -> list[Any]:
        # If an output_xml file was specified and exists, parse that.
        # Otherwise, we would need to try parsing stdout, which is hard.
        return []

    def parse_xml(self, xml_path: Path | str, scan_id: str) -> dict[str, list[Any]]:
        """Parse Nmap XML output into Database Models."""
        results: dict[str, list[Any]] = {"ports": [], "services": []}
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall("host"):
                # Check if host is up
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue
                    
                # Get IP
                address = host.find("address")
                if address is None:
                    continue
                ip = address.get("addr", "")
                
                # Parse ports
                ports_tag = host.find("ports")
                if ports_tag is not None:
                    for port in ports_tag.findall("port"):
                        state_tag = port.find("state")
                        if state_tag is None or state_tag.get("state") != "open":
                            continue
                            
                        port_id = int(port.get("portid", 0))
                        protocol = port.get("protocol", "tcp")
                        
                        service_tag = port.find("service")
                        service_name = ""
                        product = ""
                        version = ""
                        cpe = ""
                        extra = ""
                        
                        if service_tag is not None:
                            service_name = service_tag.get("name", "")
                            product = service_tag.get("product", "")
                            version = service_tag.get("version", "")
                            extra = service_tag.get("extrainfo", "")
                            
                            cpe_tag = service_tag.find("cpe")
                            if cpe_tag is not None and cpe_tag.text:
                                cpe = cpe_tag.text
                        
                        port_record = PortRecord(
                            scan_id=scan_id,
                            host=ip,
                            port=port_id,
                            protocol=protocol,
                            state="open",
                            service=service_name,
                            product=product,
                            version=version,
                            cpe=cpe,
                            source="nmap"
                        )
                        results["ports"].append(port_record)
                        
                        if product or version:
                            svc_record = ServiceRecord(
                                scan_id=scan_id,
                                host=ip,
                                port=port_id,
                                protocol=protocol,
                                service=service_name,
                                product=product,
                                version=version,
                                extra_info=extra,
                                source="nmap"
                            )
                            results["services"].append(svc_record)
                            
        except Exception:
            pass
            
        return results
