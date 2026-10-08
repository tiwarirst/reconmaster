"""Unit tests for newly added tools, adapters, modules, and config schema."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconai.core.config.manager import ConfigManager
from reconai.core.config.schema import ReconAIConfig, ToolSettingConfig, ToolsConfig
from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import ScanRecord, ScanStatus
from reconai.core.events.bus import EventBus
from reconai.core.executor.command_runner import CommandRunner
from reconai.core.executor.result import CommandResult, CommandStatus
from reconai.core.logging.logger import ReconLogger
from reconai.integrations.gau import GauAdapter
from reconai.integrations.tlsx import TlsxAdapter
from reconai.modules.active.tlsx_probe import TLSProbeModule
from reconai.modules.passive.archive import ArchiveModule
from reconai.modules.registry import ModuleRegistry


def test_config_yaml_loading_and_tools_schema(tmp_path: Path) -> None:
    """Test that config.yaml loads properly with the full tools registry."""
    config_file = Path("config.yaml")
    assert config_file.exists(), "Root config.yaml must exist"

    mgr = ConfigManager(config_file)
    cfg: ReconAIConfig = mgr.config

    assert isinstance(cfg.tools, ToolsConfig)
    assert cfg.tools.httpx.enabled is True
    assert cfg.tools.httpx.threads == 30
    assert "-tech-detect" in cfg.tools.httpx.extra_args

    assert cfg.tools.tlsx.enabled is True
    assert cfg.tools.nuclei.enabled is True
    assert cfg.tools.arjun.enabled is True
    assert cfg.tools.subzy.enabled is True
    assert cfg.tools.gitleaks.enabled is True
    assert cfg.tools.gau.enabled is True

    # Test get_tool lookup helper
    nmap_cfg = cfg.tools.get_tool("nmap")
    assert isinstance(nmap_cfg, ToolSettingConfig)
    assert nmap_cfg.enabled is True


def test_gau_adapter_command_and_parse() -> None:
    """Test GauAdapter command generation and output parsing."""
    runner = MagicMock(spec=CommandRunner)
    adapter = GauAdapter(runner)

    cmd = adapter.build_command(domain="example.com", threads=8, include_subs=True)
    assert "example.com" in cmd
    assert "--subs" in cmd
    assert "--threads" in cmd
    assert "8" in cmd

    raw_output = (
        "https://example.com/login\n"
        "http://sub.example.com/api/v1\n"
        "not-a-url\n"
        "https://example.com/test.js\n"
    )
    res = CommandResult(
        command=cmd,
        status=CommandStatus.SUCCESS,
        stdout=raw_output,
        exit_code=0,
    )
    parsed = adapter.parse(res)
    assert len(parsed) == 3
    assert "https://example.com/login" in parsed
    assert "http://sub.example.com/api/v1" in parsed
    assert "https://example.com/test.js" in parsed


def test_tlsx_adapter_command_and_parse() -> None:
    """Test TlsxAdapter command generation and JSON parsing."""
    runner = MagicMock(spec=CommandRunner)
    adapter = TlsxAdapter(runner)

    cmd = adapter.build_command(targets=["example.com", "api.example.com"], concurrency=25)
    assert "tlsx" in cmd[0]
    assert "-json" in cmd
    assert "-san" in cmd
    assert "-jarm" in cmd
    assert "-c" in cmd
    assert "25" in cmd

    raw_json = (
        '{"host":"example.com","port":443,"subject_cn":"example.com","subject_an":["example.com","www.example.com","api.example.com"],"tls_version":"tls13","expired":false}\n'
        '{"host":"old.example.com","port":443,"subject_cn":"old.example.com","subject_an":["old.example.com"],"tls_version":"tls10","expired":true}\n'
    )
    res = CommandResult(
        command=cmd,
        status=CommandStatus.SUCCESS,
        stdout=raw_json,
        exit_code=0,
    )
    parsed = adapter.parse(res)
    assert len(parsed) == 2
    assert parsed[0]["host"] == "example.com"
    assert "api.example.com" in parsed[0]["subject_an"]
    assert parsed[0]["tls_version"] == "tls13"
    assert parsed[0]["expired"] is False

    assert parsed[1]["host"] == "old.example.com"
    assert parsed[1]["tls_version"] == "tls10"
    assert parsed[1]["expired"] is True


@pytest.mark.asyncio
async def test_tls_probe_module_registration_and_execution(tmp_path: Path) -> None:
    """Test TLSProbeModule registration, pure-Python fallback, and findings creation."""
    assert "tls_probe" in ModuleRegistry.get_all()

    db_path = tmp_path / "test_tls.db"
    db = DatabaseManager(db_path=db_path)
    db.connect()

    scan_id = "test_tls_scan"
    db.create_scan(ScanRecord(id=scan_id, target="example.com", status=ScanStatus.RUNNING))

    events = EventBus()
    logger = MagicMock(spec=ReconLogger)
    runner = MagicMock(spec=CommandRunner)
    runner.check_tool = AsyncMock(return_value=(False, ""))  # Simulate tlsx not installed

    mod = TLSProbeModule(
        db=db,
        events=events,
        logger=logger,
        runner=runner,
        out_dir=tmp_path,
        timeout=30,
    )
    mod.scan_id = scan_id
    mod.target = "example.com"

    # Mock the internal pure-Python probe to return mock cert data
    mock_cert_info = {
        "host": "example.com",
        "port": 443,
        "subject_cn": "example.com",
        "subject_an": ["example.com", "admin.example.com", "vpn.example.com"],
        "issuer_cn": "Let's Encrypt Authority",
        "tls_version": "tls10",  # Weak version -> should trigger Finding
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "expired": True,          # Expired -> should trigger Finding
    }

    with patch.object(mod, "_probe_ssl_python", AsyncMock(return_value=mock_cert_info)):
        await mod.run(domains=["example.com"])

    # Verify newly discovered SAN subdomains were inserted
    subs = db.get_subdomains(scan_id)
    sub_names = [s["subdomain"] if isinstance(s, dict) else s.subdomain for s in subs]
    assert "admin.example.com" in sub_names
    assert "vpn.example.com" in sub_names

    # Verify findings were created for expired certificate and weak TLS
    findings = db.get_findings(scan_id)
    finding_titles = [f["title"] if isinstance(f, dict) else f.title for f in findings]
    assert any("Expired SSL/TLS Certificate" in t for t in finding_titles)
    assert any("Deprecated TLS Protocol" in t for t in finding_titles)

    db.close()


@pytest.mark.asyncio
async def test_archive_module_gau_and_otx_fallback(tmp_path: Path) -> None:
    """Test ArchiveModule works seamlessly with gau and fallback APIs."""
    db_path = tmp_path / "test_archive.db"
    db = DatabaseManager(db_path=db_path)
    db.connect()

    scan_id = "test_arch_scan"
    db.create_scan(ScanRecord(id=scan_id, target="example.com", status=ScanStatus.RUNNING))

    events = EventBus()
    logger = MagicMock(spec=ReconLogger)
    runner = MagicMock(spec=CommandRunner)
    runner.check_tool = AsyncMock(return_value=(False, ""))

    mod = ArchiveModule(
        db=db,
        events=events,
        logger=logger,
        runner=runner,
        out_dir=tmp_path,
        timeout=30,
    )
    mod.scan_id = scan_id
    mod.target = "example.com"

    with patch.object(mod, "_query_cdx_api", AsyncMock(return_value=["https://example.com/arch1"])), \
         patch.object(mod, "_query_otx_api", AsyncMock(return_value=["https://example.com/otx1"])):
        await mod.run(domains=["example.com"])

    urls = db.get_urls(scan_id)
    url_strings = [u["url"] if isinstance(u, dict) else u.url for u in urls]
    assert "https://example.com/arch1" in url_strings
    assert "https://example.com/otx1" in url_strings

    db.close()
