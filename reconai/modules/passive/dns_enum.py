"""DNS Enumeration Module.

Queries A, AAAA, CNAME, MX, NS, TXT, SOA, CAA records.

Fix applied (Flaw 10):
  When A or AAAA records are found, we now insert an IPRecord into the
  'ips' table in addition to the DNSRecord. Previously, DNS-discovered
  IPs were emitted as events but never persisted to the ips table.
  PortScanModule reads from db.get_ips() — without this fix, it would
  receive an empty host list and skip entirely even when DNS found IPs.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

import dns.asyncresolver
import dns.resolver

from reconai.core.database.models import DNSRecord, IPRecord
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
        domains: list[str] = list(kwargs.get("domains", []))
        if not domains:
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 5.0

        records_to_check = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
        start = time.monotonic()

        for domain in domains:
            self.logger.module_start(self.config.name, target=domain)

            tasks = [
                self._query_record(resolver, domain, rtype)
                for rtype in records_to_check
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if not isinstance(result, list):
                    continue

                for record in result:
                    # Persist DNS record (INSERT OR IGNORE — no duplicates)
                    self.db.insert_dns_record(record)

                    if record.record_type in ("A", "AAAA"):
                        # ── Persist the IP into the ips table ────────────────
                        # This is the critical step: PortScanModule reads from
                        # db.get_ips(), so IPs *must* be in that table.
                        ip_version = _ip_version(record.value)
                        is_private = _is_private(record.value)

                        ip_record = IPRecord(
                            scan_id=self.scan_id,
                            ip=record.value,
                            version=ip_version,
                            hostnames=[domain],
                            is_private=is_private,
                            source="dns_enum",
                        )
                        self.db.insert_ip(ip_record)  # INSERT OR IGNORE — idempotent

                        # Emit HOST_RESOLVED for any listening modules
                        await self.events.emit_discovery(
                            event_type=EventType.HOST_RESOLVED,
                            source=self.config.name,
                            data={
                                "domain": domain,
                                "ip": record.value,
                                "version": ip_version,
                            },
                            scan_id=self.scan_id,
                            target=self.target,
                        )

            self.logger.module_complete(self.config.name, duration=time.monotonic() - start)

    async def _query_record(
        self,
        resolver: dns.asyncresolver.Resolver,
        domain: str,
        record_type: str,
    ) -> list[DNSRecord]:
        records: list[DNSRecord] = []
        try:
            answers = await resolver.resolve(domain, record_type)
            for rdata in answers:
                val = rdata.to_text().strip('"')
                records.append(
                    DNSRecord(
                        scan_id=self.scan_id,
                        hostname=domain,
                        record_type=record_type,
                        value=val,
                        ttl=answers.ttl,
                        source="dns",
                    )
                )
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
        ):
            pass
        except Exception as exc:
            self.logger.debug(
                f"DNS {record_type} error for {domain}: {exc}",
                module=self.config.name,
            )
        return records


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ip_version(addr: str) -> int:
    """Return 4 or 6 for the given IP address string, defaulting to 4."""
    try:
        return ipaddress.ip_address(addr).version
    except ValueError:
        return 4


def _is_private(addr: str) -> bool:
    """Return True if the IP is an RFC-1918 / loopback / link-local address."""
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False
