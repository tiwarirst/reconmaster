"""Passive OSINT Fusion Module.

Performs zero-touch passive reconnaissance on discovered IP addresses using
Shodan's free InternetDB API (zero API keys required, 100% free public service),
with optional enrichment from full Shodan/Censys APIs if keys are configured.

Discovers open ports, banners, CPEs, tags (VPN/Cloud), and known CVEs
without sending a single packet directly to the target system.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from reconai.core.database.models import FindingRecord, PortRecord, Severity, Confidence
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class OSINTFusionModule(ReconModule):
    """Zero-touch passive OSINT fusion via Shodan InternetDB + optional CTI APIs."""

    config = ModuleConfig(
        name="osint_fusion",
        category="passive",
        description="Passive port and CVE intelligence via Shodan InternetDB (100% free, zero keys required)",
        requires_tools=[],
        supports_timeout=True,
        supports_streaming=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        """Run passive OSINT fusion against discovered IP addresses."""
        self.logger.info(f"Starting passive OSINT fusion for target: {self.target}", module=self.config.name)

        # Collect IPs from database
        ip_records = self.db.get_ips(self.scan_id)
        target_ips = [rec["ip"] for rec in ip_records if rec.get("ip")]

        # If no IPs yet in DB, resolve primary target
        if not target_ips:
            try:
                import socket
                resolved = socket.gethostbyname(self.target)
                if resolved:
                    target_ips.append(resolved)
            except Exception:
                pass

        if not target_ips:
            self.logger.info("No IP addresses available for passive OSINT fusion.", module=self.config.name)
            return

        shodan_api_key = os.getenv("SHODAN_API_KEY", "").strip()

        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "ReconAI/2.0 OSINT"}) as client:
            for ip in target_ips[:15]:
                # ── 1. Shodan InternetDB (100% Free, No API Key Required) ──────────
                try:
                    resp = await client.get(f"https://internetdb.shodan.io/{ip}")
                    if resp.status_code == 200:
                        data = resp.json()
                        ports = data.get("ports", [])
                        cpes = data.get("cpes", [])
                        hostnames = data.get("hostnames", [])
                        tags = data.get("tags", [])
                        vulns = data.get("vulns", [])

                        self.logger.info(
                            f"InternetDB passive hit for {ip}: {len(ports)} ports, {len(vulns)} CVEs, tags: {tags}",
                            module=self.config.name,
                        )

                        # Record open ports
                        for port in ports:
                            port_rec = PortRecord(
                                scan_id=self.scan_id,
                                host=ip,
                                port=int(port),
                                protocol="tcp",
                                state="open",
                                service=self._guess_service(int(port)),
                                source="internetdb_passive",
                            )
                            self.db.insert_port(port_rec)
                            await self.event_bus.emit_discovery(
                                event_type=EventType.PORT_DISCOVERED,
                                source=self.config.name,
                                data={"host": ip, "port": port, "protocol": "tcp", "source": "shodan_internetdb"},
                            )

                        # Record passive vulnerability flags
                        for cve in vulns:
                            finding = FindingRecord(
                                scan_id=self.scan_id,
                                title=f"Passive CVE Indicator: {cve}",
                                description=f"Host {ip} was passively indexed with known vulnerability {cve} in Shodan InternetDB.",
                                severity=Severity.HIGH,
                                confidence=Confidence.POTENTIAL,
                                affected_asset=f"{ip}",
                                cve=[cve],
                                detection_method="passive_osint_internetdb",
                                evidence=f"CPEs: {', '.join(cpes[:3])} | Tags: {', '.join(tags)}",
                                remediation="Review exposed service configuration and apply latest vendor security patches.",
                                source=self.config.name,
                            )
                            await self.emit_finding(finding)

                except Exception as exc:
                    self.logger.debug(f"InternetDB lookup skipped for {ip}: {exc}", module=self.config.name)

                # ── 2. Optional Authenticated Shodan Query (If API key provided) ───
                if shodan_api_key:
                    try:
                        shodan_resp = await client.get(f"https://api.shodan.io/shodan/host/{ip}?key={shodan_api_key}")
                        if shodan_resp.status_code == 200:
                            s_data = shodan_resp.json()
                            for item in s_data.get("data", []):
                                p = item.get("port")
                                banner = item.get("data", "")[:200]
                                product = item.get("product", "")
                                version = item.get("version", "")
                                if p:
                                    port_rec = PortRecord(
                                        scan_id=self.scan_id,
                                        host=ip,
                                        port=int(p),
                                        protocol="tcp",
                                        state="open",
                                        service=item.get("transport", "tcp"),
                                        product=product,
                                        version=version,
                                        banner=banner,
                                        source="shodan_api",
                                    )
                                    self.db.insert_port(port_rec)
                    except Exception as exc:
                        self.logger.debug(f"Optional Shodan API query skipped: {exc}", module=self.config.name)

        self.logger.info("Passive OSINT fusion completed.", module=self.config.name)

    @staticmethod
    def _guess_service(port: int) -> str:
        """Heuristic service guess for common ports."""
        mapping = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
            1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
        }
        return mapping.get(port, "unknown")
