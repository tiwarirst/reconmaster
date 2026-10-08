"""Unit tests for ReconCopilot conversational assistant."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reconai.ai.copilot import ReconCopilot
from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import FindingRecord, PortRecord, ScanRecord, Severity, SubdomainRecord
from reconai.mcp.server import handle_tool_call


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "reconai.db"
    return DatabaseManager(db_path=db_file)


@pytest.mark.asyncio
async def test_copilot_quick_commands(temp_db: DatabaseManager):
    """Verify copilot responds to /summary, /findings, and /help."""
    scan_id = "test_copilot_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="alpha.example.com"))
    temp_db.insert_subdomain(SubdomainRecord(scan_id=scan_id, subdomain="vpn.example.com"))
    temp_db.insert_port(PortRecord(scan_id=scan_id, host="vpn.example.com", port=443, service="https"))
    temp_db.insert_finding(FindingRecord(
        scan_id=scan_id,
        title="Open SSL Heartbleed",
        severity=Severity.HIGH,
        affected_asset="vpn.example.com",
        description="Memory leakage vulnerability in OpenSSL TLS heartbeat extension.",
        impact="Information disclosure of private keys and active sessions.",
    ))

    copilot = ReconCopilot(temp_db, scan_id, ai=None)

    # Test /summary
    summary_res = await copilot.ask("/summary")
    assert "alpha.example.com" in summary_res
    assert "Findings" in summary_res

    # Test /findings
    findings_res = await copilot.ask("/findings")
    assert "Open SSL Heartbleed" in findings_res
    assert "vpn.example.com" in findings_res

    # Test /help
    help_res = await copilot.ask("/help")
    assert "ReconAI Copilot Commands" in help_res


@pytest.mark.asyncio
async def test_copilot_specific_finding_inquiry(temp_db: DatabaseManager):
    """Verify copilot details a specific finding when requested."""
    scan_id = "test_copilot_finding"
    temp_db.create_scan(ScanRecord(id=scan_id, target="beta.example.com"))
    temp_db.insert_finding(FindingRecord(
        scan_id=scan_id,
        title="SQL Injection on Search Endpoint",
        severity=Severity.CRITICAL,
        affected_asset="https://beta.example.com/search?q=test",
        description="Unsanitized user input concatenated into backend SQL query.",
        impact="Complete database compromise and data exfiltration.",
        safe_verification="Send benign quote or sleep differential probe.",
    ))

    copilot = ReconCopilot(temp_db, scan_id, ai=None)
    reply = await copilot.ask("Can you explain finding 1 in detail and how deep I can penetrate?")

    assert "Finding #1" in reply
    assert "SQL Injection" in reply
    assert "Safe Verification" in reply
    assert "Potential Attack Depth" in reply


def test_copilot_mcp_integration(temp_db: DatabaseManager, tmp_path: Path):
    """Verify ask_copilot tool execution via MCP."""
    scan_id = "test_copilot_mcp"
    temp_db.create_scan(ScanRecord(id=scan_id, target="gamma.example.com"))
    temp_db.insert_subdomain(SubdomainRecord(scan_id=scan_id, subdomain="api.gamma.example.com"))

    res = handle_tool_call("ask_copilot", {
        "scan_path_or_id": str(tmp_path),
        "question": "/summary",
    })

    assert "content" in res
    assert not res.get("isError")
    assert "gamma.example.com" in res["content"][0]["text"]
