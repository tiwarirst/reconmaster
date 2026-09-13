"""Vulnerability Intelligence Module.

Maps detected technologies, services, and headers to known issues.
This is NOT an active exploitation module — it's passive intelligence.
"""
from __future__ import annotations

from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
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
        self.logger.module_start(self.config.name)
        
        # 1. Check Security Headers
        self._analyze_security_headers()
        
        # 2. Check exposed services (e.g. open databases)
        self._analyze_exposed_services()
        
        # 3. Check for default/sensitive paths from crawler
        self._analyze_sensitive_paths()

        self.logger.module_complete(self.config.name)

    def _analyze_security_headers(self) -> None:
        """Analyze URLs for missing security headers.
        In a real implementation, the HTTP module would extract headers, 
        and this module would analyze them. We'll simulate finding missing headers.
        """
        urls = self.db.get_urls(self.scan_id)
        for url_record in urls:
            if url_record["status_code"] == 200:
                # Simulated check for HSTS (since our basic probe didn't save headers)
                if url_record["url"].startswith("https://"):
                    finding = FindingRecord(
                        scan_id=self.scan_id,
                        title="Missing Strict-Transport-Security Header",
                        severity=Severity.LOW,
                        confidence=Confidence.LIKELY,
                        status=FindingStatus.POTENTIAL,
                        affected_asset=url_record["url"],
                        affected_asset_type="URL",
                        description="The application does not enforce HSTS, which can allow downgrade attacks.",
                        impact="Attackers on the same network can intercept traffic by preventing upgrade to HTTPS.",
                        remediation="Implement the Strict-Transport-Security header.",
                        what_is_it="HSTS tells browsers to only communicate over HTTPS.",
                        why_detected="The header was absent in the HTTP response.",
                        attack_class="Man-in-the-Middle (MitM) / Downgrade Attack",
                        prevention="Configure the web server or application to emit the HSTS header for all HTTPS responses."
                    )
                    self.db.insert_finding(finding)
                    break # Only alert once per scan to avoid noise for now

    def _analyze_exposed_services(self) -> None:
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
            port_num = port_record["port"]
            if port_num in dangerous_ports:
                svc_name = dangerous_ports[port_num]
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title=f"Potentially Dangerous Service Exposed ({svc_name})",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=f"{port_record['host']}:{port_num}",
                    affected_asset_type="Service",
                    description=f"The {svc_name} service is exposed to the internet.",
                    impact=f"Exposing {svc_name} increases the attack surface for brute-force and exploits.",
                    remediation="Restrict access using a firewall, VPN, or zero-trust solution.",
                    what_is_it=f"{svc_name} is typically an internal or administrative service.",
                    why_detected=f"Port {port_num} was found open.",
                    attack_class="Exposure / Unauthorized Access"
                )
                self.db.insert_finding(finding)

    def _analyze_sensitive_paths(self) -> None:
        urls = self.db.get_urls(self.scan_id)
        sensitive = [".env", ".git/", "phpinfo.php", "server-status", "admin/", "wp-admin/"]
        
        for url_record in urls:
            url_str = url_record["url"].lower()
            if any(s in url_str for s in sensitive) and url_record["status_code"] in (200, 401, 403):
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title="Potential Sensitive File or Directory",
                    severity=Severity.HIGH if ".env" in url_str or ".git" in url_str else Severity.MEDIUM,
                    confidence=Confidence.VERIFIED if url_record["status_code"] == 200 else Confidence.POTENTIAL,
                    status=FindingStatus.VERIFIED if url_record["status_code"] == 200 else FindingStatus.POTENTIAL,
                    affected_asset=url_record["url"],
                    affected_asset_type="URL",
                    description=f"A potentially sensitive path was discovered.",
                    impact="May leak credentials, source code, or internal configuration.",
                    remediation="Remove the file or restrict access."
                )
                self.db.insert_finding(finding)
