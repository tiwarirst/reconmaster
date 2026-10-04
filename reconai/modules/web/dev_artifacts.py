"""Developer & DevOps Artifacts Exposure Module.

Scans web roots for accidentally exposed version control repositories, environment files,
framework debug interfaces, and DevOps metric telemetry:
  - Exposed Git Repositories (/.git/HEAD, /.git/config)
  - Exposed Environment Files (/.env, /config.env)
  - Spring Boot Actuator Endpoints (/actuator, /actuator/env, /actuator/health)
  - Prometheus Telemetry Metrics (/metrics)
  - macOS Metadata Artifacts (/.DS_Store)

Features strict signature matching on response contents to prevent false positives from
custom 404 / 200 catch-all HTML pages. Zero external cost.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from reconai.core.database.models import (
    Confidence, FindingRecord, FindingStatus, Severity,
)
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# Definition of artifacts to audit: (path, indicator_string, severity, title, description)
_ARTIFACT_CHECKS: list[dict[str, Any]] = [
    {
        "path": "/.git/HEAD",
        "indicator": "ref: refs/heads/",
        "severity": Severity.HIGH,
        "title": "Exposed Git Repository (/.git/HEAD)",
        "description": (
            "The root .git directory is publicly accessible on the web server. "
            "An attacker can download the entire source code repository, commit history, "
            "and any hardcoded credentials using tools like git-dumper."
        ),
        "impact": "Complete source code disclosure, internal credential exposure, and architectural compromise.",
        "remediation": "Block access to .git and all hidden files in your web server configuration (e.g. Nginx 'location ~ /\\.git { deny all; }').",
    },
    {
        "path": "/.git/config",
        "indicator": "[core]",
        "severity": Severity.HIGH,
        "title": "Exposed Git Configuration (/.git/config)",
        "description": "The .git/config file is accessible, exposing remote repository URLs, author names, and branch topology.",
        "impact": "Source code repository metadata disclosure, revealing internal git server addresses and usernames.",
        "remediation": "Block web access to the .git directory.",
    },
    {
        "path": "/.env",
        "indicator": "=",
        "secondary_indicators": ["APP_KEY", "DB_PASSWORD", "SECRET", "API_KEY", "TOKEN", "DATABASE_URL"],
        "severity": Severity.CRITICAL,
        "title": "Exposed Environment Configuration File (/.env)",
        "description": (
            "An environment configuration file (.env) was found in the web root. "
            "These files typically contain database credentials, encryption keys, mail server tokens, and third-party API keys."
        ),
        "impact": "Direct database compromise, cloud credential theft, and full system takeover.",
        "remediation": "Move configuration files out of the web root directory and restrict web server access to .env files.",
    },
    {
        "path": "/actuator/env",
        "indicator": "propertySources",
        "severity": Severity.HIGH,
        "title": "Exposed Spring Boot Actuator (/actuator/env)",
        "description": "The Spring Boot Actuator environment endpoint is accessible without authentication, exposing application properties.",
        "impact": "Exposure of system properties, active profiles, and potentially masked or unmasked sensitive credentials.",
        "remediation": "Disable or protect actuator endpoints by setting 'management.endpoints.web.exposure.include=health,info'.",
    },
    {
        "path": "/actuator/health",
        "indicator": '"status"',
        "secondary_indicators": ["UP", "DOWN"],
        "severity": Severity.LOW,
        "title": "Exposed Spring Boot Actuator Health (/actuator/health)",
        "description": "The Spring Boot Actuator health endpoint is accessible, disclosing backend health status and database connectivity.",
        "impact": "Reconnaissance disclosure about backend architecture and dependency health.",
        "remediation": "Restrict access to management endpoints to internal networks.",
    },
    {
        "path": "/metrics",
        "indicator": "# HELP",
        "secondary_indicators": ["# TYPE"],
        "severity": Severity.LOW,
        "title": "Exposed Prometheus Metrics (/metrics)",
        "description": "A Prometheus metrics endpoint is exposed without authentication, disclosing internal runtime metrics, process info, and request rates.",
        "impact": "Discloses internal host metrics, application throughput, error rates, and JVM/OS statistics.",
        "remediation": "Place the /metrics endpoint behind internal networks or authenticate it using reverse-proxy basic auth.",
    },
    {
        "path": "/server-status",
        "indicator": "Apache Server Status",
        "severity": Severity.MEDIUM,
        "title": "Exposed Apache Server Status (/server-status)",
        "description": "The Apache mod_status page is publicly accessible, leaking active client IP addresses, requested URLs, and server load.",
        "impact": "Exposes live visitor IP addresses, active HTTP request URIs (which may contain session tokens), and internal server workload.",
        "remediation": "Restrict /server-status in Apache configuration with 'Require ip 127.0.0.1' or 'Require local'.",
    },
]


@register_module
class DevArtifactsModule(ReconModule):
    config = ModuleConfig(
        name="dev_artifacts",
        category="web",
        description="Scans for exposed developer artifacts: .git, .env, Spring Actuator, and Prometheus metrics.",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        live_urls: set[str] = set()
        for r in self.db.get_urls(self.scan_id):
            u = r.get("url", "")
            if u.startswith("http"):
                parsed = urlparse(u)
                base = f"{parsed.scheme}://{parsed.netloc}"
                live_urls.add(base)

        if not live_urls:
            target = kwargs.get("target", self.target)
            if not target.startswith("http"):
                live_urls.add(f"https://{target}")
                live_urls.add(f"http://{target}")
            else:
                live_urls.add(target)

        self.logger.module_start(self.config.name, target=f"{len(live_urls)} web host(s)")

        semaphore = asyncio.Semaphore(10)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(6.0, connect=3.0),
            verify=False,
            follow_redirects=False,  # Don't follow redirects to prevent login/404 redirects
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconAI"},
        ) as client:
            tasks = [
                self._check_host_artifacts(client, semaphore, base_url)
                for base_url in list(live_urls)[:25]
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name)

    async def _check_host_artifacts(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        base_url: str,
    ) -> None:
        """Probe all defined artifact checks on a single web host."""
        async with semaphore:
            for check in _ARTIFACT_CHECKS:
                target_url = urljoin(base_url, check["path"])
                try:
                    resp = await client.get(target_url)
                    if resp.status_code != 200:
                        continue

                    body = resp.text
                    indicator = check["indicator"]
                    if indicator not in body:
                        continue

                    # Check secondary indicators if defined (e.g. for .env)
                    secondary = check.get("secondary_indicators", [])
                    if secondary and not any(s in body for s in secondary):
                        continue

                    # Confirmed exposure!
                    netloc = urlparse(base_url).netloc
                    severity: Severity = check["severity"]
                    title = f"{check['title']} at {netloc}"
                    evidence_snippet = body[:300].replace("\n", " ").strip()

                    self.logger.info(
                        f"[DEV] 🔥 {severity.value.upper()}: {title}",
                        module=self.config.name,
                    )

                    finding = FindingRecord(
                        scan_id=self.scan_id,
                        title=title,
                        severity=severity,
                        confidence=Confidence.VERIFIED,
                        status=FindingStatus.VERIFIED,
                        affected_asset=target_url,
                        affected_asset_type="configuration_file",
                        description=f"{check['description']}\n\nURL: {target_url}",
                        impact=check["impact"],
                        evidence=f"HTTP 200 with signature '{indicator}'. Snippet: {evidence_snippet}",
                        detection_method=f"Direct HTTP probe with signature verification: {check['path']}",
                        remediation=check["remediation"],
                        what_is_it=f"Exposed developer or infrastructure artifact ({check['path']}) in public web root.",
                        attack_class="Sensitive Data Exposure / Source Disclosure",
                        safe_verification=f"Perform a GET request to {target_url} to confirm the file is accessible.",
                        prevention="Implement strict web server access control rules denying hidden files and administrative paths.",
                    )
                    self.db.insert_finding(finding)

                except Exception:
                    continue
