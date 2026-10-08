"""Unit tests for AI Red Team Agent, MCP Server, and new passive modules."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconai.ai.agent import RedTeamAgent
from reconai.ai.verifier import ClosedLoopVerifier
from reconai.core.correlation.engine import CorrelationEngine
from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import FindingRecord, IPRecord, PortRecord, ScanRecord, Severity, Confidence
from reconai.core.events.bus import EventBus
from reconai.core.executor.command_runner import CommandRunner
from reconai.core.logging.logger import ReconLogger
from reconai.mcp.server import handle_tool_call, MCP_TOOLS
from reconai.modules.passive.asn_enum import ASNEnumModule
from reconai.modules.passive.osint_fusion import OSINTFusionModule
from reconai.modules.registry import ModuleRegistry


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "reconai.db"
    return DatabaseManager(db_path=db_file)


def test_asn_enum_registered():
    """Verify asn_enum module is registered in registry."""
    mod = ModuleRegistry.get("asn_enum")
    assert mod is ASNEnumModule
    assert mod.config.category == "passive"


def test_osint_fusion_registered():
    """Verify osint_fusion module is registered in registry."""
    mod = ModuleRegistry.get("osint_fusion")
    assert mod is OSINTFusionModule
    assert mod.config.category == "passive"


@pytest.mark.asyncio
async def test_asn_enum_execution(temp_db: DatabaseManager, tmp_path: Path):
    """Verify ASNEnumModule runs cleanly and handles network calls safely."""
    logger = ReconLogger(log_dir=tmp_path / "logs", debug=False)
    events = EventBus()
    runner = CommandRunner(logger)

    module = ASNEnumModule(
        db=temp_db,
        events=events,
        logger=logger,
        runner=runner,
        out_dir=tmp_path,
    )
    module.scan_id = "test_scan_asn"
    module.target = "cloudflare.com"

    # Mock httpx to test parser logic
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "rir_allocation": {"asns": ["13335"]},
                "prefixes": [{"prefix": "104.16.0.0/12", "asn": {"asn": 13335, "name": "CLOUDFLARENET"}}],
            }
        }
        mock_get.return_value = mock_resp

        await module.run()

    ips = temp_db.get_ips("test_scan_asn")
    assert len(ips) >= 1
    assert any("AS13335" in ip.get("asn", "") for ip in ips)


@pytest.mark.asyncio
async def test_osint_fusion_internetdb_free_tier(temp_db: DatabaseManager, tmp_path: Path):
    """Verify OSINTFusionModule queries free InternetDB and populates ports and vulns."""
    logger = ReconLogger(log_dir=tmp_path / "logs", debug=False)
    events = EventBus()
    runner = CommandRunner(logger)

    # Insert an initial IP
    ip_rec = IPRecord(scan_id="test_osint_scan", ip="1.1.1.1", source="dns")
    temp_db.insert_ip(ip_rec)

    module = OSINTFusionModule(
        db=temp_db,
        events=events,
        logger=logger,
        runner=runner,
        out_dir=tmp_path,
    )
    module.scan_id = "test_osint_scan"
    module.target = "1.1.1.1"

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ports": [80, 443, 853],
            "cpes": ["cpe:/a:cloudflare:dns"],
            "hostnames": ["one.one.one.one"],
            "tags": ["dns", "cloud"],
            "vulns": ["CVE-2020-0001"],
        }
        mock_get.return_value = mock_resp

        await module.run()

    ports = temp_db.get_ports("test_osint_scan")
    assert len(ports) >= 3
    port_nums = [p["port"] for p in ports]
    assert 80 in port_nums and 443 in port_nums and 853 in port_nums

    findings = temp_db.get_findings("test_osint_scan")
    assert len(findings) >= 1
    assert any("CVE-2020-0001" in f["title"] for f in findings)


def test_correlation_engine_find_attack_paths(temp_db: DatabaseManager):
    """Verify attack pathfinding calculates multi-hop paths to sensitive assets."""
    scan_id = "test_paths_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="example.com"))

    # Insert host, port, finding
    from reconai.core.database.models import SubdomainRecord
    temp_db.insert_subdomain(SubdomainRecord(scan_id=scan_id, subdomain="api.example.com"))
    temp_db.insert_port(PortRecord(scan_id=scan_id, host="api.example.com", port=443, service="https"))
    temp_db.insert_finding(FindingRecord(
        scan_id=scan_id,
        title="Remote Code Execution",
        severity=Severity.CRITICAL,
        affected_asset="api.example.com",
    ))

    engine = CorrelationEngine(temp_db, scan_id)
    paths = engine.find_attack_paths()

    assert len(paths) >= 1
    top_path = paths[0]
    assert top_path["severity"] == "CRITICAL"
    assert top_path["score"] == 10
    assert top_path["entry_point"] == "api.example.com"
    assert len(top_path["path_nodes"]) == 5


@pytest.mark.asyncio
async def test_closed_loop_verifier_heuristics(temp_db: DatabaseManager):
    """Verify ClosedLoopVerifier identifies pattern signatures and assigns verified status."""
    scan_id = "test_verify_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="target.com"))

    # Insert candidate secret finding
    temp_db.insert_finding(FindingRecord(
        scan_id=scan_id,
        title="Exposed AWS Key",
        severity=Severity.HIGH,
        confidence=Confidence.POTENTIAL,
        affected_asset="target.com",
        evidence="Found key: AKIAIOSFODNN7EXAMPLE in app.js",
    ))

    verifier = ClosedLoopVerifier(temp_db, scan_id, ai=None)
    results = await verifier.verify_all_findings()

    assert len(results) == 1
    assert results[0]["verified"] is True
    assert results[0]["confidence"] == "verified"

    updated = temp_db.get_findings(scan_id)
    assert updated[0]["confidence"] == "verified"


@pytest.mark.asyncio
async def test_red_team_agent_plan_generation(temp_db: DatabaseManager):
    """Verify RedTeamAgent generates campaign plan with weakest assets and MITRE techniques."""
    scan_id = "test_agent_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="corp.example.com"))
    temp_db.insert_port(PortRecord(scan_id=scan_id, host="vpn.corp.example.com", port=8443, service="vpn"))

    agent = RedTeamAgent(temp_db, scan_id, ai=None)
    result = await agent.run_campaign_analysis()

    assert result["target"] == "corp.example.com"
    assert "Red Team Operation Plan" in result["plan_markdown"]
    assert "T1190" in result["plan_markdown"]


def test_mcp_server_tool_handling(temp_db: DatabaseManager, tmp_path: Path):
    """Verify MCP server handles tool calls for scan summary and subdomains."""
    scan_id = "mcp_test_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="test.com"))
    temp_db.insert_port(PortRecord(scan_id=scan_id, host="test.com", port=80, service="http"))

    # Test get_ports via MCP tool handler
    res = handle_tool_call("get_ports", {"scan_path_or_id": str(tmp_path)})
    assert "content" in res
    assert not res.get("isError")
    ports_data = json.loads(res["content"][0]["text"])
    assert len(ports_data) >= 1
    assert ports_data[0]["port"] == 80
