"""Secret Scanning Module.

Uses TruffleHog to scan downloaded JS files and other assets for secrets.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from reconai.core.events.types import EventType
from reconai.integrations.trufflehog import TrufflehogAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SecretsModule(ReconModule):
    config = ModuleConfig(
        name="secrets",
        category="vuln",
        description="Scans scripts and assets for leaked secrets using TruffleHog (with pure-Python fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        url_records = self.db.get_urls(self.scan_id)
        # Find all JS files and high-value endpoints
        js_urls = [
            r["url"] for r in url_records
            if r.get("url", "").endswith(".js") or ".js?" in r.get("url", "")
        ]

        # If no JS files found, fallback to live HTML endpoints
        if not js_urls:
            js_urls = [r["url"] for r in url_records if r.get("status_code") == 200][:10]

        if not js_urls and self.target:
            base = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
            js_urls = [base]

        if not js_urls:
            return

        adapter = TrufflehogAdapter(self.runner)
        has_trufflehog = await adapter.is_available()

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(js_urls)} targets")

        if has_trufflehog:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                    tasks = [self._download_file(client, url, tmp_path) for url in js_urls[:50]]
                    await asyncio.gather(*tasks, return_exceptions=True)

                cmd = adapter.build_command(path=str(tmp_path))
                result = await self.runner.run(command=cmd, timeout=120)

                findings = adapter.parse(result)
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
        else:
            # Check Gitleaks as alternative fast binary secret scanner
            from reconai.integrations.gitleaks import GitleaksAdapter
            g_adapter = GitleaksAdapter(self.runner)
            has_gitleaks = await g_adapter.is_available()

            if has_gitleaks:
                with tempfile.TemporaryDirectory() as tmp_dir:
                    tmp_path = Path(tmp_dir)
                    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                        tasks = [self._download_file(client, url, tmp_path) for url in js_urls[:50]]
                        await asyncio.gather(*tasks, return_exceptions=True)

                    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf_report:
                        rep_path = Path(tf_report.name)
                    try:
                        cmd = g_adapter.build_command(target_dir=tmp_path, output_file=rep_path)
                        await self.runner.run(command=cmd, timeout=120)
                        findings = g_adapter.parse_output_file(rep_path)
                        for finding in findings:
                            finding.scan_id = self.scan_id
                            await self.emit_finding(finding)
                    finally:
                        rep_path.unlink(missing_ok=True)
            else:
                self.record_warning(
                    "TruffleHog / Gitleaks not installed in PATH. Install: 'go install github.com/trufflesecurity/trufflehog/v3@latest' "
                    "or 'brew/apt install gitleaks'. Ran pure-Python regex secrets detection fallback."
                )
                await self._python_regex_secret_scan(js_urls[:20])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _python_regex_secret_scan(self, urls: list[str]) -> None:
        """Pure-Python high-confidence secret and token signature detection."""
        import re
        from reconai.core.database.models import FindingRecord, Severity, Confidence, FindingStatus

        SECRET_PATTERNS = [
            (re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, "Exposed AWS Access Key ID", "Amazon Web Services"),
            (re.compile(r"ghp_[0-9a-zA-Z]{36}"), Severity.CRITICAL, "Exposed GitHub Personal Access Token", "GitHub"),
            (re.compile(r"AIza[0-9A-Za-z-_]{35}"), Severity.HIGH, "Exposed Google API Key", "Google Cloud"),
            (re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"), Severity.HIGH, "Exposed Slack Incoming Webhook", "Slack"),
            (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), Severity.CRITICAL, "Exposed Private Cryptographic Key", "PKI"),
            (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), Severity.MEDIUM, "Exposed Hardcoded JWT Token", "Authentication"),
        ]

        async with httpx.AsyncClient(verify=False, timeout=8.0, headers={"User-Agent": "Mozilla/5.0"}) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                    text = resp.text
                    for pattern, sev, title, provider in SECRET_PATTERNS:
                        matches = pattern.findall(text)
                        if matches:
                            finding = FindingRecord(
                                scan_id=self.scan_id,
                                title=f"{title} in {url.split('/')[-1] or url}",
                                severity=sev,
                                confidence=Confidence.VERIFIED,
                                status=FindingStatus.VERIFIED,
                                affected_asset=url,
                                affected_asset_type="url",
                                description=f"Hardcoded sensitive secret/credential found ({provider}). Match sample: {str(matches[0])[:8]}...",
                                impact="Unauthorized access to target cloud APIs, repos, or internal systems.",
                                remediation="Revoke the exposed key immediately and store secrets in environment variables or vault.",
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
                            self.logger.info(f"[SECRETS] Discovered {title} on {url}", module=self.config.name)
                except Exception:
                    pass

    async def _download_file(self, client: httpx.AsyncClient, url: str, target_dir: Path) -> None:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
                file_path = target_dir / safe_name
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
        except Exception:
            pass
