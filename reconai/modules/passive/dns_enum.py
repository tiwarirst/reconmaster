"""DNS Enumeration Module.

Queries A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR, SRV records.
"""
from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver
import dns.resolver

from reconai.core.database.models import DNSRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class DNSEnumModule(ReconModule):
    config = ModuleConfig(
        name="dns_enum",
        category="passive",
        description="Comprehensive DNS record enumeration",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = kwargs.get("domains", [])
        if not domains:
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 5.0

        records_to_check = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
        
        for domain in domains:
            self.logger.module_start(self.config.name, target=domain)
            
            tasks = []
            for record_type in records_to_check:
                tasks.append(self._query_record(resolver, domain, record_type))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    for record in result:
                        self.db.insert_dns_record(record)
                        
                        # Emit event if we found an IP (A/AAAA)
                        if record.record_type in ("A", "AAAA"):
                            await self.events.emit_discovery(
                                event_type=EventType.HOST_RESOLVED,
                                source=self.config.name,
                                data={"domain": domain, "ip": record.value},
                                scan_id=self.scan_id,
                                target=self.target
                            )
                            
            self.logger.module_complete(self.config.name)

    async def _query_record(self, resolver: dns.asyncresolver.Resolver, domain: str, record_type: str) -> list[DNSRecord]:
        records = []
        try:
            answers = await resolver.resolve(domain, record_type)
            for rdata in answers:
                val = rdata.to_text().strip('"')
                
                # Basic explanation for TXT/MX/etc can be added here or in intelligence phase
                
                records.append(DNSRecord(
                    scan_id=self.scan_id,
                    hostname=domain,
                    record_type=record_type,
                    value=val,
                    ttl=answers.ttl,
                    source="dns"
                ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass
        except Exception as e:
            self.logger.debug(f"DNS {record_type} error for {domain}: {e}")
            
        return records
