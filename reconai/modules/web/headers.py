"""Security Headers Analysis Module.

Analyzes HTTP responses for missing or misconfigured security headers.
"""
from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import httpx

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SecurityHeadersModule(ReconModule):
    config = ModuleConfig(
        name="headers",
        category="web",
        description="Analyzes HTTP responses for security headers",
        supports_timeout=True,
    )

    REQUIRED_HEADERS: ClassVar[dict[str, dict[str, Any]]] = {
        "Strict-Transport-Security": {
            "severity": Severity.LOW,
            "description": "Enforces secure (HTTP over SSL/TLS) connections to the server.",
            "impact": "Leaves users vulnerable to man-in-the-middle attacks.",
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "Helps detect and mitigate certain types of attacks, including XSS.",
            "impact": "Increases susceptibility to Cross-Site Scripting (XSS) attacks.",
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "description": "Prevents the browser from interpreting files as a different MIME type.",
            "impact": "Can allow MIME-sniffing attacks.",
        },
        "X-Frame-Options": {
            "severity": Severity.LOW,
            "description": "Provides clickjacking protection.",
            "impact": "Application may be vulnerable to Clickjacking.",
        },
    }

    async def run(self, **kwargs: Any) -> Any:
        urls = kwargs.get("urls", [])
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [r["url"] for r in url_records if r["status_code"] and r["status_code"] < 400]
            
        if not urls:
            return

        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            tasks = [self._check_headers(client, url) for url in urls[:20]] # Limit to 20 to avoid spam
            await asyncio.gather(*tasks)

        self.logger.module_complete(self.config.name)

    async def _check_headers(self, client: httpx.AsyncClient, url: str) -> None:
        try:
            response = await client.head(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header, info in self.REQUIRED_HEADERS.items():
                if header.lower() not in headers:
                    severity: Severity = info["severity"]  # already a Severity enum
                    finding = FindingRecord(
                        scan_id=self.scan_id,
                        title=f"Missing Security Header: {header}",
                        severity=severity,
                        confidence=Confidence.VERIFIED,
                        status=FindingStatus.VERIFIED,
                        affected_asset=url,
                        affected_asset_type="URL",
                        description=f"The {header} header is missing. {info['description']}",
                        impact=info["impact"],
                        remediation=f"Configure the web server to include the {header} header.",
                        detection_method="HTTP response header analysis",
                    )
                    self.db.insert_finding(finding)
        except Exception as e:
            self.logger.debug(f"Header check failed for {url}: {e}")
