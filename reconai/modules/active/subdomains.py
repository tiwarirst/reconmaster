"""Subdomain Enumeration Module.

Uses Subfinder and Amass to discover subdomains.

Fix applied (Flaw 11):
  requires_tools previously listed BOTH "subfinder" and "amass".
  check_requirements() in the base class blocks the entire module if ANY
  listed tool is missing. Amass is a heavy optional dependency — not
  installed by default on many systems.

  Fix: requires_tools now lists only "subfinder" (the reliable baseline).
  Amass availability is checked at runtime and used opportunistically.
  The module runs with whatever tools are available rather than failing
  because a secondary tool is missing.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from reconai.core.database.models import SubdomainRecord
from reconai.core.events.types import EventType
from reconai.integrations.amass import AmassAdapter
from reconai.integrations.subfinder import SubfinderAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SubdomainModule(ReconModule):
    config = ModuleConfig(
        name="subdomains_active",
        category="active",
        description="Active subdomain enumeration using Subfinder (+ Amass if available) with DNS brute-force fallback",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains: list[str] = list(kwargs.get("domains", []))
        if not domains and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                domains = [clean]

        if not domains:
            return

        subfinder = SubfinderAdapter(self.runner)
        amass = AmassAdapter(self.runner)

        for domain in domains:
            start = time.monotonic()
            self.logger.module_start(self.config.name, target=domain)

            subdomains: set[str] = set()

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

            if not tasks:
                self.record_warning(
                    "Subfinder / Amass not installed. Install: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'. "
                    "Ran async DNS prefix discovery fallback."
                )

            # If external tools are not installed or returned no results, run fast DNS resolution
            if not subdomains:
                self.logger.info(
                    f"External tools produced 0 subdomains for {domain}; running high-speed DNS prefix discovery...",
                    module=self.config.name,
                )
                brute_subs = await self._brute_dns_prefixes(domain)
                subdomains.update(brute_subs)

            records = [
                SubdomainRecord(
                    scan_id=self.scan_id,
                    subdomain=sub,
                    domain=domain,
                    sources=["active_tools"],
                )
                for sub in subdomains
            ]
            self.db.insert_subdomains_batch(records)

            for sub in subdomains:
                await self.events.emit_discovery(
                    event_type=EventType.SUBDOMAIN_DISCOVERED,
                    source=self.config.name,
                    data={"subdomain": sub, "domain": domain, "source": "active_tools"},
                    scan_id=self.scan_id,
                    target=self.target,
                )

            self.logger.info(
                f"Found {len(subdomains)} unique subdomains via active tools for {domain}",
                module=self.config.name,
            )
            duration = time.monotonic() - start
            self.logger.module_complete(self.config.name, duration=duration)

    async def _run_subfinder(self, adapter: SubfinderAdapter, domain: str) -> set[str]:
        cmd = adapter.build_command(domain=domain)
        result = await self.runner.run(command=cmd, timeout=60)
        return set(adapter.parse(result))

    async def _run_amass(self, adapter: AmassAdapter, domain: str) -> set[str]:
        cmd = adapter.build_command(domain=domain, passive=True)
        result = await self.runner.run(command=cmd, timeout=60)
        return set(adapter.parse(result))

    async def _brute_dns_prefixes(self, domain: str) -> set[str]:
        """Resolve top high-value subdomains using asynchronous DNS with public nameservers."""
        import dns.asyncresolver
        prefixes = [
            "www", "mail", "api", "dev", "app", "vpn", "admin", "portal",
            "staging", "test", "auth", "corp", "cdn", "support", "shop",
            "status", "git", "jenkins", "m", "mobile", "beta", "cloud",
            "secure", "remote", "login", "mx", "ns1", "ns2", "cpanel", "webmail",
            "sso", "dashboard", "grafana", "gitlab", "backend", "db", "stage"
        ]
        found: set[str] = set()
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        resolver.timeout = 1.0
        resolver.lifetime = 2.0

        semaphore = asyncio.Semaphore(20)

        async def _probe(prefix: str) -> None:
            candidate = f"{prefix}.{domain}"
            async with semaphore:
                try:
                    answers = await resolver.resolve(candidate, "A")
                    if answers:
                        found.add(candidate)
                except Exception:
                    pass

        tasks = [_probe(p) for p in prefixes]
        await asyncio.gather(*tasks, return_exceptions=True)
        return found

