"""Automated XSS Detection Module.

Uses Dalfox to safely test discovered parameters for XSS.

Fix applied (BUG 1):
  Temp file is now owned by the module, not the adapter.
  Each concurrent _test_xss() call creates its own isolated file,
  passes the path to build_command + parse_output_file, and cleans
  up in a finally block. No shared adapter state → no race conditions.
  Added duration telemetry and real-time finding discovery events.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.dalfox import DalfoxAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class DalfoxModule(ReconModule):
    config = ModuleConfig(
        name="dalfox",
        category="vuln",
        description="Automated XSS detection using Dalfox (with pure-Python fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        url_records = self.db.get_urls(self.scan_id)
        urls: list[str] = [
            r["url"] for r in url_records
            if "?" in r.get("url", "") and "=" in r.get("url", "")
        ]

        if not urls and self.target:
            base = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
            urls = [f"{base}/?q=test", f"{base}/?search=test"]

        if not urls:
            return

        adapter = DalfoxAdapter(self.runner)
        has_dalfox = await adapter.is_available()

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} parameterized URLs")

        if has_dalfox:
            semaphore = asyncio.Semaphore(3)
            tasks = [self._test_xss(adapter, semaphore, url) for url in urls]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            self.record_warning(
                "Dalfox not installed in PATH. Install: 'go install github.com/hahwul/dalfox/v2@latest' (or 'sudo apt install dalfox'). "
                "Ran pure-Python XSS reflection probe fallback."
            )
            await self._python_xss_probe(urls[:10])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _python_xss_probe(self, urls: list[str]) -> None:
        """Pure-Python XSS parameter reflection test probe."""
        import httpx
        from reconai.core.database.models import FindingRecord, Severity, Confidence, FindingStatus

        probe_token = "reconai7xss<imgsrc=x>"
        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            for url in urls:
                test_url = url + probe_token
                try:
                    resp = await client.get(test_url)
                    if probe_token in resp.text:
                        finding = FindingRecord(
                            scan_id=self.scan_id,
                            title=f"Reflected Cross-Site Scripting (XSS) Potential in {url.split('?')[0]}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LIKELY,
                            status=FindingStatus.POTENTIAL,
                            affected_asset=url,
                            affected_asset_type="url",
                            description=f"Raw HTML reflection detected for injected payload '{probe_token}' without proper sanitization.",
                            impact="Session hijacking, credential theft, and unauthorized client-side actions.",
                            remediation="Encode all user-supplied input before rendering into HTML responses (contextual output encoding).",
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
                        self.logger.info(f"[XSS] Discovered unencoded parameter reflection on {url}", module=self.config.name)
                except Exception:
                    pass

    async def _test_xss(
        self,
        adapter: DalfoxAdapter,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> None:
        """Scan a single URL for XSS.

        Temp file lifecycle:
          1. Created here, before build_command.
          2. Path passed to adapter — adapter writes output to it via -o.
          3. Path passed to parse_output_file after process exits.
          4. Always deleted in finally — no leaks, no shared state.
        """
        async with semaphore:
            tmp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False, prefix="dalfox_"
                ) as tmp:
                    tmp_path = Path(tmp.name)

                cmd = adapter.build_command(target=url, output_file=tmp_path)
                await self.runner.run(command=cmd, timeout=60)

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
                        },
                        scan_id=self.scan_id,
                        target=self.target,
                    )

            except Exception as exc:
                self.logger.debug(f"Dalfox scan failed for {url}: {exc}", module=self.config.name)
            finally:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
