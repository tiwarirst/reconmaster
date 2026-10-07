"""High-Speed DNS Resolution Module.

Uses DNSx for fast domain resolution and wildcard filtering.

Fixes applied:
  BUG 3: DNSx-resolved IPs are now inserted into the `ips` table.
    Previously, A/AAAA records were emitted as HOST_RESOLVED events but
    never persisted to the ips table. PortScanModule reads from
    db.get_ips() — so these IPs were invisible to the port scanner.

  BUG 10: Fixed NameError in finally block.
    Previously, `domain_file` was assigned inside `with NamedTemporaryFile()`
    and referenced in the `finally` block. If NamedTemporaryFile raised,
    domain_file was never set, causing NameError in finally which masked
    the real exception. Fixed by pre-initializing domain_file = None.

  Adapter: Updated to use new stateless DnsxAdapter.parse_output_file(path).
"""
from __future__ import annotations

import ipaddress
import tempfile
import time
from pathlib import Path
from typing import Any

from reconai.core.database.models import IPRecord
from reconai.core.events.types import EventType
from reconai.integrations.dnsx import DnsxAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class DnsxModule(ReconModule):
    config = ModuleConfig(
        name="dnsx",
        category="passive",
        description="High-speed wildcard-aware DNS resolution using DNSx (with async Python fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        subs = self.db.get_subdomains(self.scan_id)
        subdomains: list[str] = [str(s["subdomain"]) for s in subs]

        if not subdomains and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                subdomains = [clean]

        if not subdomains:
            return

        adapter = DnsxAdapter(self.runner)
        if not await adapter.is_available():
            self.record_warning(
                "DNSx not installed in PATH. Install: 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'. "
                "Ran async Python DNS resolver fallback."
            )
            await self._python_dns_resolve(subdomains)
            return

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(subdomains)} subdomains")

        # Pre-initialise to None so the finally block never hits NameError
        # even if NamedTemporaryFile itself raises (e.g. disk full).
        domain_file: str | None = None
        output_path: Path | None = None

        try:
            # Write subdomains to input file for dnsx
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="dnsx_in_"
            ) as in_f:
                in_f.write("\n".join(subdomains))
                domain_file = in_f.name

            # Output file — managed by us, not by the adapter
            with tempfile.NamedTemporaryFile(
                suffix=".json", delete=False, prefix="dnsx_out_"
            ) as out_f:
                output_path = Path(out_f.name)

            cmd = adapter.build_command(
                domain_file=domain_file,
                output_file=output_path,
            )
            await self.runner.run(command=cmd, timeout=300)

            records = adapter.parse_output_file(output_path)

            for record in records:
                record.scan_id = self.scan_id
                # Persist DNS record
                self.db.insert_dns_record(record)

                # ── Critical fix: also persist to ips table ───────────────
                # PortScanModule reads from db.get_ips(). Without this,
                # IPs discovered exclusively via DNSx are never port-scanned.
                if record.record_type in ("A", "AAAA"):
                    ip_record = IPRecord(
                        scan_id=self.scan_id,
                        ip=record.value,
                        version=_ip_version(record.value),
                        hostnames=[record.hostname],
                        is_private=_is_private(record.value),
                        source="dnsx",
                    )
                    self.db.insert_ip(ip_record)  # INSERT OR IGNORE — idempotent

                    await self.events.emit_discovery(
                        event_type=EventType.HOST_RESOLVED,
                        source=self.config.name,
                        data={
                            "domain": record.hostname,
                            "ip": record.value,
                            "version": ip_record.version,
                        },
                        scan_id=self.scan_id,
                        target=self.target,
                    )

        except Exception as exc:
            self.logger.debug(f"DNSx run failed: {exc}", module=self.config.name)
        finally:
            # Safe cleanup — none of these raise even if the paths are None
            if domain_file:
                Path(domain_file).unlink(missing_ok=True)
            if output_path:
                output_path.unlink(missing_ok=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _python_dns_resolve(self, subdomains: list[str]) -> None:
        """Pure-Python async DNS resolver fallback when dnsx CLI is not installed."""
        import dns.asyncresolver
        from reconai.core.database.models import DNSRecord
        import asyncio

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 4.0
        semaphore = asyncio.Semaphore(15)
        resolved_count = 0

        async def _resolve_host(sub: str) -> None:
            nonlocal resolved_count
            async with semaphore:
                try:
                    answers = await resolver.resolve(sub, "A")
                    for rdata in answers:
                        ip_str = rdata.to_text()
                        dns_rec = DNSRecord(
                            scan_id=self.scan_id,
                            hostname=sub,
                            record_type="A",
                            value=ip_str,
                            ttl=answers.ttl,
                            source="python_dns",
                        )
                        self.db.insert_dns_record(dns_rec)

                        ip_rec = IPRecord(
                            scan_id=self.scan_id,
                            ip=ip_str,
                            version=_ip_version(ip_str),
                            hostnames=[sub],
                            is_private=_is_private(ip_str),
                            source="python_dns",
                        )
                        self.db.insert_ip(ip_rec)

                        await self.events.emit_discovery(
                            event_type=EventType.HOST_RESOLVED,
                            source=self.config.name,
                            data={"domain": sub, "ip": ip_str, "version": ip_rec.version},
                            scan_id=self.scan_id,
                            target=self.target,
                        )
                        resolved_count += 1
                except Exception:
                    pass

        tasks = [_resolve_host(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.info(
            f"Resolved {resolved_count} IP records for {len(subdomains)} hostnames via Python DNS fallback",
            module=self.config.name,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ip_version(addr: str) -> int:
    try:
        return ipaddress.ip_address(addr).version
    except ValueError:
        return 4


def _is_private(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False
