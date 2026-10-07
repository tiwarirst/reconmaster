"""Automated SQL Injection Detection Module.

Uses SQLMap to safely test discovered parameters for SQLi.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from reconai.core.events.types import EventType
from reconai.integrations.sqlmap import SqlmapAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SqlmapModule(ReconModule):
    config = ModuleConfig(
        name="sqlmap",
        category="vuln",
        description="Automated SQL Injection detection using SQLMap (with pure-Python fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        url_records = self.db.get_urls(self.scan_id)
        urls = [
            r["url"] for r in url_records
            if "?" in r.get("url", "") and "=" in r.get("url", "")
        ]

        if not urls and self.target:
            base = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
            urls = [f"{base}/?id=1", f"{base}/?q=test"]

        if not urls:
            return

        adapter = SqlmapAdapter(self.runner)
        has_sqlmap = await adapter.is_available()

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(urls)} parameterized URLs")

        if has_sqlmap:
            semaphore = asyncio.Semaphore(1)
            tasks = [self._test_sqli(adapter, semaphore, url) for url in urls[:10]]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            self.record_warning(
                "SQLMap not installed in PATH. Install: 'pip install sqlmap' (or 'sudo apt install sqlmap'). "
                "Ran pure-Python SQL error signature probe fallback."
            )
            await self._python_sqli_probe(urls[:10])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _python_sqli_probe(self, urls: list[str]) -> None:
        """Pure-Python SQL injection error signature probe."""
        import httpx
        from reconai.core.database.models import FindingRecord, Severity, Confidence, FindingStatus

        SQL_ERROR_SIGS = [
            ("SQL syntax", "MySQL / MariaDB"),
            ("mysql_fetch", "MySQL"),
            ("PostgreSQL query failed", "PostgreSQL"),
            ("pg_exec", "PostgreSQL"),
            ("ORA-01756", "Oracle"),
            ("SQLite/JDBCDriver", "SQLite"),
            ("System.Data.OleDb.OleDbException", "MSSQL / Access"),
            ("Unclosed quotation mark", "Microsoft SQL Server"),
        ]

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            for url in urls:
                test_url = url + "'"
                try:
                    resp = await client.get(test_url)
                    for err_sig, db_name in SQL_ERROR_SIGS:
                        if err_sig.lower() in resp.text.lower():
                            finding = FindingRecord(
                                scan_id=self.scan_id,
                                title=f"Potential SQL Injection Error ({db_name})",
                                severity=Severity.HIGH,
                                confidence=Confidence.LIKELY,
                                status=FindingStatus.POTENTIAL,
                                affected_asset=url,
                                affected_asset_type="url",
                                description=f"Database error indicator '{err_sig}' exposed upon injecting single-quote into parameter.",
                                impact="Potential unauthorized database extraction or modification.",
                                remediation="Use parameterized queries / prepared statements (ORM) rather than string concatenation.",
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
                            self.logger.info(f"[SQLI] Discovered potential SQL error signature on {url}", module=self.config.name)
                            break
                except Exception:
                    pass

    async def _test_sqli(self, adapter: SqlmapAdapter, semaphore: asyncio.Semaphore, url: str) -> None:
        async with semaphore:
            try:
                cmd = adapter.build_command(target=url)
                result = await self.runner.run(command=cmd, timeout=300)

                findings = adapter.parse(result, target_url=url)

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

            except Exception as e:
                self.logger.debug(f"SQLMap scan failed for {url}: {e}", module=self.config.name)
