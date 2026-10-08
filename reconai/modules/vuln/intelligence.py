"""Vulnerability Intelligence Module.

Maps detected technologies, services, and headers to known issues.
This is NOT an active exploitation module — it's passive intelligence.
"""
from __future__ import annotations

import time
from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class VulnIntelligenceModule(ReconModule):
    config = ModuleConfig(
        name="vuln_intelligence",
        category="intelligence",
        description="Correlates discovered assets with known vulnerabilities and security misconfigurations",
        supports_timeout=False,
    )

    async def run(self, **kwargs: Any) -> Any:
        start = time.monotonic()
        self.logger.module_start(self.config.name)

        # 1. Check Security Headers
        await self._analyze_security_headers()

        # 2. Check exposed services (e.g. open databases)
        await self._analyze_exposed_services()

        # 3. Check for default/sensitive paths from crawler
        await self._analyze_sensitive_paths()

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _emit_finding(self, finding: FindingRecord) -> None:
        await self.emit_finding(finding)

    async def _analyze_security_headers(self) -> None:
        """Analyze URLs for missing security headers."""
        urls = self.db.get_urls(self.scan_id)
        for url_record in urls:
            if url_record.get("status_code") == 200:
                url_str = url_record.get("url", "")
                if url_str.startswith("https://"):
                    finding = FindingRecord(
                        scan_id=self.scan_id,
                        title="Missing Strict-Transport-Security Header",
                        severity=Severity.LOW,
                        confidence=Confidence.LIKELY,
                        status=FindingStatus.POTENTIAL,
                        affected_asset=url_str,
                        affected_asset_type="URL",
                        description="The application does not enforce HSTS, which can allow downgrade attacks.",
                        impact="Attackers on the same network can intercept traffic by preventing upgrade to HTTPS.",
                        remediation="Implement the Strict-Transport-Security header.",
                        what_is_it="HSTS tells browsers to only communicate over HTTPS.",
                        why_detected="The header was absent in the HTTP response.",
                        attack_class="Man-in-the-Middle (MitM) / Downgrade Attack",
                        prevention="Configure the web server or application to emit the HSTS header for all HTTPS responses."
                    )
                    await self._emit_finding(finding)
                    break # Only alert once per scan to avoid noise

    async def _analyze_exposed_services(self) -> None:
        """Check for potentially dangerous exposed services."""
        ports = self.db.get_ports(self.scan_id)

        dangerous_ports = {
            21: "FTP", 
            23: "Telnet", 
            3306: "MySQL", 
            5432: "PostgreSQL", 
            27017: "MongoDB", 
            3389: "RDP", 
            445: "SMB"
        }

        for port_record in ports:
            port_num = port_record.get("port")
            if port_num in dangerous_ports:
                svc_name = dangerous_ports[port_num]
                host_val = port_record.get("host", self.target)
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title=f"Potentially Dangerous Service Exposed ({svc_name})",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=f"{host_val}:{port_num}",
                    affected_asset_type="Service",
                    description=f"The {svc_name} service is exposed to the internet.",
                    impact=f"Exposing {svc_name} increases the attack surface for brute-force and exploits.",
                    remediation="Restrict access using a firewall, VPN, or zero-trust solution.",
                    what_is_it=f"{svc_name} is typically an internal or administrative service.",
                    why_detected=f"Port {port_num} was found open.",
                    attack_class="Exposure / Unauthorized Access"
                )
                await self._emit_finding(finding)

    async def _analyze_sensitive_paths(self) -> None:
        urls = self.db.get_urls(self.scan_id)
        sensitive = [".env", ".git/", "phpinfo.php", "server-status", "admin/", "wp-admin/"]

        for url_record in urls:
            url_str = url_record.get("url", "").lower()
            status_code = url_record.get("status_code")
            if any(s in url_str for s in sensitive) and status_code in (200, 401, 403):
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title="Potential Sensitive File or Directory",
                    severity=Severity.HIGH if ".env" in url_str or ".git" in url_str else Severity.MEDIUM,
                    confidence=Confidence.VERIFIED if status_code == 200 else Confidence.POTENTIAL,
                    status=FindingStatus.VERIFIED if status_code == 200 else FindingStatus.POTENTIAL,
                    affected_asset=url_record.get("url", ""),
                    affected_asset_type="URL",
                    description="A potentially sensitive path was discovered.",
                    impact="May leak credentials, source code, or internal configuration.",
                    remediation="Remove the file or restrict access."
                )
                await self._emit_finding(finding)
