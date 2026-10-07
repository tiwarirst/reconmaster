"""Certificate Transparency Module.

Queries crt.sh to find subdomains passively.
"""
from __future__ import annotations

import json
import time
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
        domains = list(kwargs.get("domains", []))
        if not domains and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                domains = [clean]

        if not domains:
            return

        for domain in domains:
            start = time.monotonic()
            self.logger.module_start(self.config.name, target=domain)

            subdomains = await self._query_crtsh(domain)
            if not subdomains:
                self.logger.info(f"crt.sh returned no results for {domain}; querying secondary passive sources...", module=self.config.name)
                subdomains = await self._query_passive_fallbacks(domain)

            # Ensure baseline domain and www are present if no subdomains found
            if not subdomains:
                subdomains.add(domain)
                subdomains.add(f"www.{domain}")

            for sub in subdomains:
                # Add to DB
                record = SubdomainRecord(
                    scan_id=self.scan_id,
                    subdomain=sub,
                    domain=domain,
                    sources=["crt.sh" if sub in subdomains else "passive_ct"]
                )
                self.db.insert_subdomain(record)

                # Emit event
                await self.events.emit_discovery(
                    event_type=EventType.SUBDOMAIN_DISCOVERED,
                    source=self.config.name,
                    data={"subdomain": sub, "domain": domain, "source": "ct_enum"},
                    scan_id=self.scan_id,
                    target=self.target
                )

            self.logger.info(f"Discovered {len(subdomains)} subdomains for {domain}", module=self.config.name)
            duration = time.monotonic() - start
            self.logger.module_complete(self.config.name, duration=duration)

    async def _query_crtsh(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        if name:
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if (sub == domain or sub.endswith(f".{domain}")) and not sub.startswith("*."):
                                    subdomains.add(sub)
        except Exception as e:
            self.logger.debug(f"crt.sh query for {domain} failed: {e}", module=self.config.name)

        return subdomains

    async def _query_passive_fallbacks(self, domain: str) -> set[str]:
        """Query AlienVault OTX and HackerTarget passive DNS when crt.sh is slow or empty."""
        results: set[str] = set()
        async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": "Mozilla/5.0"}) as client:
            # 1. HackerTarget HostSearch
            try:
                resp = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.splitlines():
                        parts = line.strip().split(",")
                        if parts:
                            sub = parts[0].strip().lower()
                            if sub == domain or sub.endswith(f".{domain}"):
                                results.add(sub)
            except Exception:
                pass

            # 2. AlienVault OTX Passive DNS
            try:
                resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("passive_dns", []):
                        sub = item.get("hostname", "").strip().lower()
                        if sub == domain or sub.endswith(f".{domain}"):
                            results.add(sub)
            except Exception:
                pass

        return results
