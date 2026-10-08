"""Autonomous ASN & BGP Prefix Discovery Module.

Discovers Autonomous System Numbers (ASNs), BGP routing prefixes,
and CIDR network blocks owned or used by the target organization using
100% free, public OSINT (BGPView API and HackerTarget ASN lookup).

Zero API keys or paid subscriptions required.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from typing import Any

import httpx

from reconai.core.database.models import IPRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class ASNEnumModule(ReconModule):
    """Discovers ASNs, BGP routing prefixes, and CIDR ranges."""

    config = ModuleConfig(
        name="asn_enum",
        category="passive",
        description="Autonomous ASN & BGP prefix discovery via free public OSINT (BGPView / HackerTarget)",
        requires_tools=[],
        supports_timeout=True,
        supports_streaming=True,
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.asn_data: list[dict[str, Any]] = []

    async def run(self) -> None:
        """Run ASN & BGP prefix discovery."""
        self.logger.info(f"Starting autonomous ASN & BGP prefix discovery for target: {self.target}", module=self.config.name)

        discovered_asns: set[str] = set()
        resolved_ips: set[str] = set()

        # Step 1: Resolve root target to IP if it's a domain
        try:
            primary_ip = socket.gethostbyname(self.target)
            if primary_ip:
                resolved_ips.add(primary_ip)
        except Exception:
            pass

        # Also pull any already resolved IPs from the DB
        existing_ips = self.db.get_ips(self.scan_id)
        for entry in existing_ips:
            ip_val = entry.get("ip")
            if ip_val:
                resolved_ips.add(str(ip_val))

        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "ReconAI/2.0 OSINT"}) as client:
            # Step 2: Query BGPView API for resolved IPs to find ASN
            for ip in list(resolved_ips)[:5]:
                try:
                    resp = await client.get(f"https://api.bgpview.io/ip/{ip}")
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        for asn_info in data.get("rir_allocation", {}).get("asns", []) or []:
                            discovered_asns.add(str(asn_info))
                        ptr = data.get("ptr_record")
                        prefixes = data.get("prefixes", [])
                        for p in prefixes:
                            asn_obj = p.get("asn", {})
                            asn_num = f"AS{asn_obj.get('asn')}" if asn_obj.get("asn") else ""
                            asn_name = asn_obj.get("name", "")
                            prefix_cidr = p.get("prefix", "")
                            if asn_num:
                                discovered_asns.add(asn_num)
                                self._record_asn_info(asn_num, asn_name, prefix_cidr, ip)
                except Exception as exc:
                    self.logger.debug(f"BGPView IP query skipped for {ip}: {exc}", module=self.config.name)

            # Step 3: Query BGPView search using target organization or domain keyword
            search_term = self.target.split(".")[0]
            if len(search_term) >= 3:
                try:
                    search_resp = await client.get(f"https://api.bgpview.io/search?query_term={search_term}")
                    if search_resp.status_code == 200:
                        data = search_resp.json().get("data", {})
                        asns = data.get("asns", [])
                        for a in asns[:5]:
                            asn_num = f"AS{a.get('asn')}" if a.get("asn") else ""
                            asn_name = a.get("name", "")
                            asn_desc = a.get("description", "")
                            if asn_num:
                                discovered_asns.add(asn_num)
                                self._record_asn_info(asn_num, f"{asn_name} - {asn_desc}", "", "")
                except Exception as exc:
                    self.logger.debug(f"BGPView search query skipped: {exc}", module=self.config.name)

            # Step 4: Fallback / Enrichment via HackerTarget free ASN lookup
            for ip in list(resolved_ips)[:3]:
                try:
                    ht_resp = await client.get(f"https://api.hackertarget.com/aslookup/?q={ip}")
                    if ht_resp.status_code == 200 and "API count exceeded" not in ht_resp.text:
                        # Output format: "IP","ASN","Range / Description"
                        lines = [ln.strip() for ln in ht_resp.text.splitlines() if ln.strip()]
                        for ln in lines:
                            parts = [p.strip().strip('"') for p in ln.split(",")]
                            if len(parts) >= 3:
                                asn_num = parts[1] if parts[1].startswith("AS") else f"AS{parts[1]}"
                                asn_name = parts[2]
                                discovered_asns.add(asn_num)
                                self._record_asn_info(asn_num, asn_name, "", ip)
                except Exception as exc:
                    self.logger.debug(f"HackerTarget lookup skipped for {ip}: {exc}", module=self.config.name)

        self.logger.info(
            f"ASN & BGP discovery complete: discovered {len(discovered_asns)} ASNs for target perimeter",
            module=self.config.name,
        )

    def _record_asn_info(self, asn: str, org: str, prefix: str, ip: str) -> None:
        """Persist ASN intelligence to database and emit events."""
        if not asn:
            return
        entry = {
            "asn": asn,
            "org": org,
            "prefix": prefix,
            "ip": ip,
        }
        self.asn_data.append(entry)

        # Update IP record in DB if matching IP
        if ip:
            try:
                ip_rec = IPRecord(
                    scan_id=self.scan_id,
                    ip=ip,
                    asn=asn,
                    asn_org=org,
                    source="asn_enum",
                )
                self.db.insert_ip(ip_rec)
            except Exception:
                pass

        # Emit asset discovery event
        try:
            self.event_bus.emit_sync(
                EventType.ASSET_DISCOVERED,
                source=self.config.name,
                data={
                    "type": "asn",
                    "asn": asn,
                    "organization": org,
                    "prefix": prefix,
                    "ip": ip,
                },
            )
        except Exception:
            pass
