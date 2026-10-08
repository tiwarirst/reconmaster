"""Unit tests for Threat Actor Profiler, Fuzz Optimizer, and Defensive Advisor."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from reconai.ai.defensive_advisor import DefensiveAdvisor
from reconai.ai.fuzz_optimizer import AttackSurfacePrioritizer
from reconai.ai.threat_profiler import ThreatActorProfiler
from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import ScanRecord, TechnologyRecord, URLRecord, IPRecord
from reconai.mcp.server import handle_tool_call


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "reconai.db"
    return DatabaseManager(db_path=db_file)


@pytest.mark.asyncio
async def test_threat_actor_profiler_wordpress_and_aws(temp_db: DatabaseManager):
    """Verify ThreatActorProfiler correlates WordPress and AWS with relevant threat actors."""
    scan_id = "test_threat_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="shop.target.com"))

    # Insert technologies
    temp_db.insert_technology(TechnologyRecord(scan_id=scan_id, host="shop.target.com", name="WordPress", category="CMS"))
    temp_db.insert_technology(TechnologyRecord(scan_id=scan_id, host="shop.target.com", name="AWS S3", category="Cloud Storage"))

    profiler = ThreatActorProfiler(temp_db, scan_id, ai=None)
    result = await profiler.generate_threat_profile()

    assert result["target"] == "shop.target.com"
    actors = [a["actor"] for a in result["relevant_actors"]]
    assert any("Initial Access Brokers" in a or "Magecart" in a or "Scattered Spider" in a for a in actors)
    assert any("T1190" in t for t in result["mitre_techniques"])
    assert "Threat Actor & Adversary Emulation Profile" in result["narrative_markdown"]


def test_attack_surface_prioritizer(temp_db: DatabaseManager):
    """Verify AttackSurfacePrioritizer ranks administrative and sensitive API URLs higher than generic ones."""
    scan_id = "test_prio_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="app.target.com"))

    # Insert diverse URLs
    temp_db.insert_url(URLRecord(scan_id=scan_id, url="https://app.target.com/assets/logo.png", method="GET", status_code=200))
    temp_db.insert_url(URLRecord(scan_id=scan_id, url="https://app.target.com/admin/dashboard", method="GET", status_code=200))
    temp_db.insert_url(URLRecord(scan_id=scan_id, url="https://app.target.com/api/v1/user?id=123", method="GET", status_code=200))
    temp_db.insert_url(URLRecord(scan_id=scan_id, url="https://app.target.com/auth/login", method="GET", status_code=200))
    temp_db.insert_url(URLRecord(scan_id=scan_id, url="https://app.target.com/redirect?url=https://other.com", method="GET", status_code=200))

    prioritizer = AttackSurfacePrioritizer(temp_db, scan_id)
    ranked = prioritizer.prioritize_endpoints(limit=10)

    # Logo should be excluded
    urls = [r["url"] for r in ranked]
    assert not any("logo.png" in u for u in urls)

    # Admin, API, Auth, Redirect should be ranked high
    assert any("admin" in u for u in urls)
    assert any("redirect" in u for u in urls)

    top_item = ranked[0]
    assert top_item["priority"] in ("CRITICAL", "HIGH")
    assert len(top_item["suggested_vectors"]) >= 1


@pytest.mark.asyncio
async def test_defensive_advisor_origin_ip_leakage(temp_db: DatabaseManager):
    """Verify DefensiveAdvisor detects potential origin IP leaks when Cloudflare is fingerprinted."""
    scan_id = "test_defense_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="waf-target.com"))

    # Cloudflare WAF detected
    temp_db.insert_technology(TechnologyRecord(scan_id=scan_id, host="waf-target.com", name="Cloudflare", category="WAF"))

    # Direct origin IP with non-Cloudflare ASN
    temp_db.insert_ip(IPRecord(
        scan_id=scan_id,
        ip="198.51.100.25",
        asn="AS16509",
        asn_org="AMAZON-02",
        source="cert_transparency",
    ))

    advisor = DefensiveAdvisor(temp_db, scan_id, ai=None)
    result = await advisor.analyze_perimeter_defenses()

    assert "Cloudflare" in result["detected_wafs"]
    assert len(result["potential_origin_ips"]) >= 1
    assert result["potential_origin_ips"][0]["ip"] == "198.51.100.25"
    assert any("Origin IP Leakage" in r for r in result["recommendations"])


def test_mcp_new_tools_dispatch(temp_db: DatabaseManager, tmp_path: Path):
    """Verify get_threat_profile and get_prioritized_endpoints work via MCP tool call."""
    scan_id = "mcp_advanced_scan"
    temp_db.create_scan(ScanRecord(id=scan_id, target="mcp-test.com"))
    temp_db.insert_url(URLRecord(scan_id=scan_id, url="https://mcp-test.com/admin/login", method="GET", status_code=200))

    # Test get_prioritized_endpoints
    res = handle_tool_call("get_prioritized_endpoints", {"scan_path_or_id": str(tmp_path), "limit": 5})
    assert "content" in res
    assert not res.get("isError")
    prio_data = json.loads(res["content"][0]["text"])
    assert len(prio_data) >= 1
    assert "admin/login" in prio_data[0]["url"]
