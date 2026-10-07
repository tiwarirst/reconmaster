"""Nuclei Vulnerability Scanning Module.

Uses Nuclei for template-based vulnerability scanning.

Fixes applied:
  - Temp file is owned by the *module*, not the adapter.
    Each concurrent _scan_url() call creates its own isolated temp file
    and passes the path to build_command + parse_output_file.
    Adapter state is never shared between concurrent calls.
  - Scans URLs at depth 0 AND depth 1 (crawler-discovered endpoints).
    Depth-0-only previously missed all authenticated/internal API paths.
  - Temp file cleanup is guaranteed via try/finally.
  - Added duration telemetry and real-time finding discovery events.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.nuclei import NucleiAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class NucleiModule(ReconModule):
    config = ModuleConfig(
        name="nuclei_vuln",
        category="vuln",
        description="Template-based vulnerability scanning using Nuclei (with pure-Python fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        urls: list[str] = list(kwargs.get("urls", []))

        if not urls:
            url_records = self.db.get_urls(self.scan_id)
            urls = [
                r["url"] for r in url_records
                if r.get("status_code") == 200 and r.get("depth", 0) <= 1
            ]

        if not urls and self.target:
            base = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
            urls = [base]

        if not urls:
            return

        adapter = NucleiAdapter(self.runner)
        has_nuclei = await adapter.is_available()

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} URLs")

        if has_nuclei:
            semaphore = asyncio.Semaphore(2)
            tasks = [self._scan_url(adapter, semaphore, url) for url in urls]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            self.record_warning(
                "Nuclei not installed in PATH. Install: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' (or 'sudo apt install nuclei'). "
                "Ran pure-Python vulnerability and exposure probing fallback."
            )
            await self._python_vuln_probes(urls[:15])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _scan_url(
        self,
        adapter: NucleiAdapter,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> None:
        """Scan a single URL.

        Temp file lifecycle:
          1. Created here, before build_command.
          2. Path passed to adapter — adapter writes to it via -o flag.
          3. Path passed to parse_output_file after process exits.
          4. Always deleted in finally — no leaks.
        """
        async with semaphore:
            tmp_path: Path | None = None
            try:
                # Create isolated output file for this specific invocation
                with tempfile.NamedTemporaryFile(
                    suffix=".jsonl", delete=False, prefix="nuclei_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=url, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=600)

                # parse_output_file works correctly even if Nuclei timed out —
                # every JSONL line written before the kill is independently valid.
                findings = adapter.parse_output_file(tmp_path)

                for finding in findings:
                    finding.scan_id = self.scan_id
                    self.db.insert_finding(finding)
                    await self.events.emit_discovery(
                        event_type=EventType.FINDING_DISCOVERED,
                        source=self.config.name,
                        data={
                            "title": finding.title,
                            "severity": finding.severity.value,
                            "asset": finding.affected_asset,
                            "cve": finding.cve_id or "",
                        },
                        scan_id=self.scan_id,
                        target=self.target,
                    )

            except Exception as exc:
                self.logger.debug(
                    f"Nuclei scan failed for {url}: {exc}",
                    module=self.config.name,
                )
            finally:
                # Guaranteed cleanup — no temp files left on disk
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)

    async def _python_vuln_probes(self, urls: list[str]) -> None:
        """Pure-Python high-value vulnerability, misconfiguration, and exposure probe."""
        import httpx
        from urllib.parse import urlparse
        from reconai.core.database.models import FindingRecord, Severity, Confidence, FindingStatus

        VULN_PATHS = [
            ("/phpinfo.php", "phpinfo()", Severity.MEDIUM, "PHPInfo Information Disclosure", "Exposes PHP configuration, internal paths, and server environment variables."),
            ("/.env", "DB_PASSWORD", Severity.CRITICAL, "Exposed Environment Configuration (.env)", "Exposes database passwords and API tokens in the web root."),
            ("/server-status", "Apache Server Status", Severity.LOW, "Exposed Apache server-status Page", "Discloses active client IP addresses and requested URLs."),
            ("/.git/HEAD", "ref: refs/", Severity.HIGH, "Exposed Git Repository (.git)", "Allows unauthorized downloading of application source code."),
            ("/swagger.json", '"swagger":', Severity.LOW, "Exposed Swagger/OpenAPI Documentation", "Publicly documents internal API endpoints and parameters."),
            ("/wp-json/wp/v2/users", '"slug":', Severity.LOW, "WordPress User Enumeration Endpoint", "Publicly lists valid author usernames on the site."),
        ]

        # Deduplicate base URLs
        base_urls = set()
        for u in urls:
            parsed = urlparse(u)
            base_urls.add(f"{parsed.scheme}://{parsed.netloc}")

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            for base in list(base_urls)[:10]:
                for path, indicator, sev, title, desc in VULN_PATHS:
                    target_endpoint = f"{base.rstrip('/')}{path}"
                    try:
                        resp = await client.get(target_endpoint)
                        if resp.status_code == 200 and indicator in resp.text:
                            finding = FindingRecord(
                                scan_id=self.scan_id,
                                title=title,
                                severity=sev,
                                confidence=Confidence.VERIFIED,
                                status=FindingStatus.VERIFIED,
                                affected_asset=target_endpoint,
                                affected_asset_type="url",
                                description=desc,
                                impact="Direct exposure of sensitive system internals or source code.",
                                remediation=f"Block public HTTP access to {path}.",
                                source=self.config.name,
                            )
                            self.db.insert_finding(finding)
                            await self.events.emit_discovery(
                                event_type=EventType.FINDING_DISCOVERED,
                                source=self.config.name,
                                data={
                                    "title": finding.title,
                                    "severity": finding.severity.value,
                                    "asset": finding.affected_asset,
                                },
                                scan_id=self.scan_id,
                                target=self.target,
                            )
                            self.logger.info(f"[VULN] Discovered {title} at {target_endpoint}", module=self.config.name)
                    except Exception:
                        pass

