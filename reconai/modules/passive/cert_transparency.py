"""Certificate Transparency Module.

Queries crt.sh to find subdomains passively.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from reconai.core.database.models import SubdomainRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class CertTransparencyModule(ReconModule):
    config = ModuleConfig(
        name="cert_transparency",
        category="passive",
        description="Extracts subdomains from Certificate Transparency logs (crt.sh)",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = kwargs.get("domains", [])
        if not domains:
            return

        for domain in domains:
            self.logger.module_start(self.config.name, target=domain)
            
            subdomains = await self._query_crtsh(domain)
            
            for sub in subdomains:
                # Add to DB
                record = SubdomainRecord(
                    scan_id=self.scan_id,
                    subdomain=sub,
                    domain=domain,
                    sources=["crt.sh"]
                )
                self.db.insert_subdomain(record)
                
                # Emit event
                await self.events.emit_discovery(
                    event_type=EventType.SUBDOMAIN_DISCOVERED,
                    source=self.config.name,
                    data={"subdomain": sub, "domain": domain, "source": "crt.sh"},
                    scan_id=self.scan_id,
                    target=self.target
                )
                
            self.logger.info(f"Found {len(subdomains)} subdomains via crt.sh for {domain}", module=self.config.name)
            self.logger.module_complete(self.config.name)

    async def _query_crtsh(self, domain: str) -> set[str]:
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        if name:
                            # crt.sh can return multiple domains separated by newlines
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if (sub == domain or sub.endswith(f".{domain}")) and not sub.startswith("*."):
                                    subdomains.add(sub)
        except Exception as e:
            self.logger.warning(f"Failed to query crt.sh for {domain}: {e}", module=self.config.name)
            
        return subdomains
