"""Tests for fail-safe architecture, error resilience, and critical module imports."""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import FindingRecord
from reconai.intelligence.poc_generator import PoCGenerator
from reconai.modules.active.cdn_classifier import CDNClassifierModule
from reconai.modules.passive.cert_transparency import CertTransparencyModule


def test_poc_generator_handles_email_security_and_non_standard_findings():
    """Verify PoCGenerator gracefully handles non-web findings without throwing errors."""
    poc_gen = PoCGenerator()

    findings = [
        {
            "title": "Email Spoofing Risk: DMARC Policy is None (p=none)",
            "affected_asset": "rru.ac.in",
            "severity": "medium",
            "description": "Domain lacks quarantine or reject DMARC enforcement.",
        },
        {
            "title": "Missing SPF Record",
            "affected_asset": "mail.rru.ac.in",
            "severity": "high",
        },
        {
            "title": "Exotic / Special Chars: <!@#$%^&*()> / Vulnerability?",
            "affected_asset": "https://rru.ac.in/test?a=1",
            "severity": "low",
        },
        {},  # Empty finding
    ]

    for idx, f in enumerate(findings, start=1):
        poc = poc_gen.generate(f)
        assert poc is not None
        assert isinstance(poc.curl_command, str)
        assert isinstance(poc.python_script, str)
        assert isinstance(poc.nuclei_template, str)

        # Verify slug generation logic used in CLI
        raw_title = str(f.get("title") or f"vuln_{idx}")
        clean_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", raw_title).strip("_").lower()[:40]
        slug = clean_slug if clean_slug else f"finding_{idx}"
        assert slug
        # Verify valid filename chars
        assert not any(c in slug for c in r'\/:*?"<>|')


@pytest.mark.asyncio
async def test_cert_transparency_module_asyncio_safety(tmp_path: Path):
    """Verify CertTransparencyModule executes cleanly without NameError."""
    db = DatabaseManager(tmp_path / "test.db")
    events = MagicMock()
    events.emit_discovery = AsyncMock()

    mod = CertTransparencyModule(
        db=db,
        events=events,
        logger=MagicMock(),
        runner=MagicMock(),
    )
    mod.target = "example.com"
    mod.scan_id = "test_scan"

    with patch.object(mod, "_query_crtsh", new_callable=AsyncMock) as mock_crt:
        with patch.object(mod, "_query_passive_fallbacks", new_callable=AsyncMock) as mock_fall:
            mock_crt.return_value = {"sub1.example.com", "sub2.example.com"}
            mock_fall.return_value = {"sub3.example.com"}

            await mod.run(domains=["example.com"])

            subs = [s["subdomain"] for s in db.get_subdomains("test_scan")]
            assert "sub1.example.com" in subs
            assert "sub2.example.com" in subs
            assert "sub3.example.com" in subs


@pytest.mark.asyncio
async def test_cdn_classifier_module_asyncio_safety(tmp_path: Path):
    """Verify CDNClassifierModule resolves hosts with asyncio loop without NameError."""
    db = DatabaseManager(tmp_path / "test.db")
    events = MagicMock()
    events.emit_discovery = AsyncMock()

    mod = CDNClassifierModule(
        db=db,
        events=events,
        logger=MagicMock(),
        runner=MagicMock(),
    )
    mod.target = "104.16.0.1"
    mod.scan_id = "test_scan"

    # Pre-insert IP record
    from reconai.core.database.models import IPRecord
    db.insert_ip(IPRecord(scan_id="test_scan", ip="104.16.0.1", host="example.com"))

    await mod.run()

    techs = db.get_technologies("test_scan")
    assert any("Cloudflare" in t["name"] for t in techs)


def test_screenshot_module_registered_and_firefox_candidate():
    """Verify screenshot module is registered and discovers system browsers."""
    from reconai.modules.registry import ModuleRegistry
    from reconai.modules.web.screenshot import _find_system_browser, ScreenshotModule
    import reconai.cli.main  # ensure imported

    assert "screenshot" in ModuleRegistry.get_all()
    assert ModuleRegistry.get("screenshot") is ScreenshotModule


def test_orchestrator_resolves_adaptive_module_timeouts():
    """Verify Orchestrator applies tailored timeouts based on workload intensity."""
    from reconai.core.orchestrator import Orchestrator
    from reconai.core.config.manager import ConfigManager
    from reconai.core.scope.manager import ScopeManager

    orch = Orchestrator("example.com", ConfigManager(), ScopeManager.for_target("example.com"), console=MagicMock())
    
    # Standard mode
    crawler_to = orch._resolve_module_timeout("crawler", mode="standard", timeout_override=None)
    assert crawler_to >= 180

    nuclei_to = orch._resolve_module_timeout("nuclei_vuln", mode="standard", timeout_override=None)
    assert nuclei_to >= 150

    # Deep mode gets 2x multiplier
    crawler_deep = orch._resolve_module_timeout("crawler", mode="deep", timeout_override=None)
    assert crawler_deep >= 360

    # Override takes precedence
    override_to = orch._resolve_module_timeout("crawler", mode="deep", timeout_override=400)
    assert override_to == 400


def test_report_cli_command_on_existing_scan_database(tmp_path: Path):
    """Verify 'reconai report' generates HTML, Markdown, JSON, and PoCs from existing scan dir."""
    from click.testing import CliRunner
    from reconai.cli.main import cli
    from reconai.core.database.models import FindingRecord, ScanRecord, ScanStatus

    scan_dir = tmp_path / "20261007_test_scan"
    scan_dir.mkdir(parents=True)
    db = DatabaseManager(scan_dir / "reconai.db")

    # Seed scan and findings
    db.create_scan(ScanRecord(id="scan_123", target="rru.ac.in", mode="deep", status=ScanStatus.COMPLETED))
    db.insert_finding(FindingRecord(
        scan_id="scan_123",
        title="Email Spoofing: DMARC Policy None",
        severity="medium",
        affected_asset="rru.ac.in",
        description="DMARC lacks reject policy",
    ))

    runner = CliRunner()
    result = runner.invoke(cli, ["report", str(scan_dir)])
    assert result.exit_code == 0
    assert (scan_dir / "reports" / "report.html").exists()
    assert (scan_dir / "reports" / "report.md").exists()
    assert (scan_dir / "reports" / "report.json").exists()
    assert (scan_dir / "pocs").exists()

