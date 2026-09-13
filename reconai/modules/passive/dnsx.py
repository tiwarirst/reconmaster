"""High-Speed DNS Resolution Module.

Uses DNSx for extremely fast domain resolution and wildcard filtering.
"""
from __future__ import annotations

import os
import tempfile
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.dnsx import DnsxAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class DnsxModule(ReconModule):
    config = ModuleConfig(
        name="dnsx",
        category="passive",
        description="High-speed wildcard-aware DNS resolution using DNSx",
        requires_tools=["dnsx"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        subs = self.db.get_subdomains(self.scan_id)
        subdomains = [s["subdomain"] for s in subs]
        
        if not subdomains:
            return

        adapter = DnsxAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("dnsx not available. Skipping high-speed DNS resolution.", module=self.config.name)
            return

        self.logger.module_start(self.config.name, target=f"{len(subdomains)} subdomains")

        # Write subdomains to temp file for dnsx
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(subdomains))
            domain_file = f.name
            
        try:
            cmd = adapter.build_command(domain_file=domain_file)
            result = await self.runner.run(command=cmd, timeout=300)
            
            records = adapter.parse(result)
            
            for record in records:
                record.scan_id = self.scan_id
                self.db.insert_dns_record(record)
                
                await self.events.emit_discovery(
                    event_type=EventType.HOST_RESOLVED,
                    source=self.config.name,
                    data={"domain": record.hostname, "ip": record.value},
                    scan_id=self.scan_id,
                    target=self.target
                )
        except Exception as e:
            self.logger.debug(f"DNSx failed: {e}")
        finally:
            if os.path.exists(domain_file):
                os.remove(domain_file)

        self.logger.module_complete(self.config.name)
