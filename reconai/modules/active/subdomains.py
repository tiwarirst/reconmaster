"""Subdomain Enumeration Module.

Uses Amass and Subfinder integrations to discover subdomains.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.core.database.models import SubdomainRecord
from reconai.core.events.types import EventType
from reconai.integrations.subfinder import SubfinderAdapter
from reconai.integrations.amass import AmassAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SubdomainModule(ReconModule):
    config = ModuleConfig(
        name="subdomains_active",
        category="active",
        description="Active subdomain enumeration using Subfinder and Amass",
        requires_tools=["subfinder", "amass"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = kwargs.get("domains", [])
        if not domains:
            return

        subfinder = SubfinderAdapter(self.runner)
        amass = AmassAdapter(self.runner)

        for domain in domains:
            self.logger.module_start(self.config.name, target=domain)
            
            subdomains = set()
            
            # Run tools concurrently
            tasks = []
            if await subfinder.is_available():
                tasks.append(self._run_subfinder(subfinder, domain))
            if await amass.is_available():
                tasks.append(self._run_amass(amass, domain))
                
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, set):
                        subdomains.update(res)

            for sub in subdomains:
                # Add to DB
                record = SubdomainRecord(
                    scan_id=self.scan_id,
                    subdomain=sub,
                    domain=domain,
                    sources=["active_tools"]
                )
                self.db.insert_subdomain(record)
                
                # Emit event
                await self.events.emit_discovery(
                    event_type=EventType.SUBDOMAIN_DISCOVERED,
                    source=self.config.name,
                    data={"subdomain": sub, "domain": domain, "source": "active_tools"},
                    scan_id=self.scan_id,
                    target=self.target
                )
                
            self.logger.info(f"Found {len(subdomains)} unique subdomains via active tools for {domain}", module=self.config.name)
            self.logger.module_complete(self.config.name)

    async def _run_subfinder(self, adapter: SubfinderAdapter, domain: str) -> set[str]:
        cmd = adapter.build_command(domain=domain)
        result = await self.runner.run(command=cmd, timeout=120)
        return set(adapter.parse(result))

    async def _run_amass(self, adapter: AmassAdapter, domain: str) -> set[str]:
        cmd = adapter.build_command(domain=domain, passive=True)
        result = await self.runner.run(command=cmd, timeout=300)
        return set(adapter.parse(result))
