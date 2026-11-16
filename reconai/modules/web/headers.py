"""Security Headers Analysis Module.

Analyzes HTTP responses for missing or misconfigured security headers.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, ClassVar
from urllib.parse import urlparse as _urlparse

import httpx

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.events.types import EventType
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
        # BUG-015 FIX: add missing modern security headers commonly checked in security audits
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "description": "Controls browser feature access (camera, microphone, geolocation).",
            "impact": "May allow unauthorized access to sensitive browser APIs.",
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "description": "Controls referrer information sent in cross-origin requests.",
            "impact": "Sensitive URL parameters may leak to third-party sites via Referer header.",
        },
        "Cross-Origin-Opener-Policy": {
            "severity": Severity.LOW,
            "description": "Mitigates Spectre/XS-Leaks cross-origin attacks.",
            "impact": "Application may be vulnerable to cross-origin information leakage.",
        },
        "Cross-Origin-Resource-Policy": {
            "severity": Severity.LOW,
            "description": "Controls which origins can load this resource.",
            "impact": "Resources may be loaded by unauthorized cross-origin pages.",
        },
    }

    async def run(self, **kwargs: Any) -> Any:
        urls = list(kwargs.get("urls", []))
        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [
                r["url"] for r in url_records
                if r.get("status_code") and r["status_code"] < 400
            ]

        if not urls and self.target:
            urls = [self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"]

        if not urls:
            return

        # BUG-015 FIX: deduplicate URLs by origin so every distinct host gets checked; raise cap from 20 to 50
        _seen_origins: set[str] = set()
        urls_to_check: list[str] = []
        for _u in urls:
            try:
                _parsed = _urlparse(_u)
                _origin = f"{_parsed.scheme}://{_parsed.netloc}"
                if _origin not in _seen_origins:
                    _seen_origins.add(_origin)
                    urls_to_check.append(_u)
                if len(urls_to_check) >= 50:
                    break
            except Exception:
                continue

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls_to_check)} unique origins")

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10.0) as client:
            tasks = [self._check_headers(client, url) for url in urls_to_check]
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _check_headers(self, client: httpx.AsyncClient, url: str) -> None:
        try:
            try:
                response = await client.head(url)
                if response.status_code in (403, 405) or not response.headers:
                    response = await client.get(url)
            except Exception:
                response = await client.get(url)

            headers = {k.lower(): v for k, v in response.headers.items()}
            is_https = str(response.url).startswith("https://") or url.startswith("https://")

            for header, info in self.REQUIRED_HEADERS.items():
                # HSTS is only applicable to HTTPS endpoints
                if header == "Strict-Transport-Security" and not is_https:
                    continue

                if header.lower() not in headers:
                    severity: Severity = info["severity"]
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
                        source=self.config.name,
                    )
                    await self.emit_finding(finding)
        except Exception as e:
            self.logger.debug(f"Header check failed for {url}: {e}")
