"""Unit tests verifying architectural flaw fixes."""
from __future__ import annotations

import asyncio
from pathlib import Path
from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import FindingRecord, ScanRecord, ScanStatus, Severity, Confidence, FindingStatus
from reconai.reports.generator import ReportGenerator
from reconai.core.events.bus import EventBus
from reconai.core.events.types import EventType


def test_finding_upsert_enriches_evidence_and_verification(tmp_path: Path):
    """Verifies that an unverified finding is upgraded by active verification."""
    db = DatabaseManager(db_path=tmp_path / "test.db")
    db.connect()

    scan = ScanRecord(id="scan_upsert", target="target.com", status=ScanStatus.RUNNING)
    db.create_scan(scan)

    # 1. Initial heuristic / passive discovery
    f1 = FindingRecord(
        scan_id="scan_upsert",
        title="SQL Injection",
        severity=Severity.LOW,
        confidence=Confidence.POTENTIAL,
        status=FindingStatus.POTENTIAL,
        affected_asset="http://target.com/item?id=1",
        evidence="",
        verified=False,
        source="heuristics",
    )
    db.insert_finding(f1)

    finds = db.get_findings("scan_upsert")
    assert len(finds) == 1
    assert finds[0]["verified"] == 0
    assert finds[0]["severity"] == "low"

    # 2. Active verification (e.g., sqlmap / nuclei) upgrades finding
    f2 = FindingRecord(
        scan_id="scan_upsert",
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.VERIFIED,
        status=FindingStatus.VERIFIED,
        affected_asset="http://target.com/item?id=1",
        evidence="MySQL error banner 1064 extracted",
        verified=True,
        source="sqlmap",
    )
    db.insert_finding(f2)

    # Verify that the finding was enriched rather than dropped
    updated_finds = db.get_findings("scan_upsert")
    assert len(updated_finds) == 1  # Deduplicated on asset + title
    assert updated_finds[0]["verified"] == 1
    assert updated_finds[0]["severity"] == "high"
    assert "MySQL error" in updated_finds[0]["evidence"]
    assert updated_finds[0]["source"] == "sqlmap"

    db.close()


def test_scan_stats_contains_target(tmp_path: Path):
    """Verifies get_scan_stats returns target so AI analyzer prompts receive actual target."""
    db = DatabaseManager(db_path=tmp_path / "test_target.db")
    db.connect()

    scan = ScanRecord(id="scan_stats_test", target="bank.enterprise.com", status=ScanStatus.RUNNING)
    db.create_scan(scan)

    stats = db.get_scan_stats("scan_stats_test")
    assert "target" in stats
    assert stats["target"] == "bank.enterprise.com"

    db.close()


def test_ai_summary_integrated_into_reports(tmp_path: Path):
    """Verifies ReportGenerator embeds AI threat summary in Markdown and HTML."""
    db = DatabaseManager(db_path=tmp_path / "test_reports.db")
    db.connect()

    scan = ScanRecord(id="scan_ai_rep", target="cybercorp.io", status=ScanStatus.COMPLETED)
    db.create_scan(scan)

    out_dir = tmp_path / "output"
    ai_text = "Critical exposure detected on staging API endpoint. Immediate patch required."
    generator = ReportGenerator(db, "scan_ai_rep", out_dir, ai_summary=ai_text, ai_model="llama3-security")
    reports = generator.generate_all()

    # Markdown contains AI section
    md_content = Path(reports["markdown"]).read_text(encoding="utf-8")
    assert "AI Threat Intelligence & Strategic Assessment" in md_content
    assert ai_text in md_content
    assert "llama3-security" in md_content

    # HTML contains AI card
    html_content = Path(reports["html"]).read_text(encoding="utf-8")
    assert "AI Threat Intelligence & Strategic Assessment" in html_content
    assert "Critical exposure detected" in html_content

    # JSON contains AI analysis dict
    json_path = Path(reports["json"])
    import json
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "ai_analysis" in data
    assert data["ai_analysis"]["summary"] == ai_text

    db.close()


def test_event_bus_non_blocking_discovery():
    """Verifies emit_discovery does not block the caller when listeners run."""
    bus = EventBus()
    handled = []

    async def _slow_handler(event):
        await asyncio.sleep(0.01)
        handled.append(event)

    bus.subscribe(EventType.SUBDOMAIN_DISCOVERED, _slow_handler)

    async def _test():
        await bus.emit_discovery(
            event_type=EventType.SUBDOMAIN_DISCOVERED,
            source="test",
            data={"subdomain": "sub.target.com"},
        )
        # Yield to let background task run
        await asyncio.sleep(0.05)
        assert len(handled) == 1

    asyncio.run(_test())


def test_attack_chain_and_pocs_in_reports(tmp_path: Path):
    """Verifies attack chain and PoC reproduction commands are embedded in reports."""
    db = DatabaseManager(db_path=tmp_path / "test_chain.db")
    db.connect()

    scan = ScanRecord(id="scan_chain_test", target="securitycorp.org", status=ScanStatus.COMPLETED)
    db.create_scan(scan)

    # Insert a finding
    f = FindingRecord(
        scan_id="scan_chain_test",
        title="Reflected Cross-Site Scripting (XSS)",
        severity=Severity.HIGH,
        confidence=Confidence.VERIFIED,
        status=FindingStatus.VERIFIED,
        affected_asset="https://securitycorp.org/search?q=test",
        evidence="Canary reflected unencoded in response",
        why_detected="Parameter reflected raw HTML",
        source="dalfox",
    )
    db.insert_finding(f)

    out_dir = tmp_path / "output"
    chain_text = "Phase 1: Initial access via Reflected XSS -> Steal session token -> Impersonate admin."
    generator = ReportGenerator(
        db,
        "scan_chain_test",
        out_dir,
        ai_summary="High severity vulnerability detected on public search endpoint.",
        ai_model="llama3-sec",
        attack_chain=chain_text,
    )
    reports = generator.generate_all()

    # Markdown verifies attack chain and PoC curl command
    md_content = Path(reports["markdown"]).read_text(encoding="utf-8")
    assert "AI Correlated Attack Kill Chain" in md_content
    assert chain_text in md_content
    assert "Reproduction PoC:" in md_content
    assert "curl" in md_content

    # HTML verifies attack chain card and interactive PoC details tag
    html_content = Path(reports["html"]).read_text(encoding="utf-8")
    assert "AI Correlated Attack Kill Chain" in html_content
    assert "Run Verification PoC (Curl)" in html_content
    assert "curl" in html_content

    db.close()


def test_poc_generator_target_normalization():
    """Verifies PoCGenerator safely handles assets without protocol schemes and host extraction."""
    from reconai.intelligence.poc_generator import PoCGenerator

    gen = PoCGenerator()

    # 1. Asset without scheme should be given https:// prefix
    f_no_scheme = {
        "title": "SQL Injection in User Profile",
        "attack_class": "sqli",
        "affected_asset": "app.example.com/profile?id=1",
    }
    poc1 = gen.generate(f_no_scheme)
    assert poc1.curl_command.startswith('curl -sk "https://app.example.com/profile?id=1')

    # 2. Subdomain takeover should extract pure host for socket resolution
    f_takeover = {
        "title": "Dangling Subdomain Takeover",
        "attack_class": "subdomain takeover",
        "affected_asset": "https://blog.example.com",
    }
    poc2 = gen.generate(f_takeover)
    assert 'TARGET_SUBDOMAIN = "blog.example.com"' in poc2.python_script


def test_analyzer_offline_fallback(tmp_path: Path):
    """Verifies Analyzer provides robust PoCs and kill chains even when local LLM is offline."""
    from reconai.ai.adapter import AIAdapter
    from reconai.ai.analyzer import Analyzer

    class OfflineAdapter(AIAdapter):
        async def is_available(self) -> bool:
            return False

        async def analyze(self, prompt: str) -> str:
            return ""  # Simulates offline LLM returning empty string

    db = DatabaseManager(db_path=tmp_path / "test_offline.db")
    db.connect()

    scan = ScanRecord(id="scan_off", target="example.com", status=ScanStatus.COMPLETED)
    db.create_scan(scan)

    f1 = FindingRecord(
        scan_id="scan_off",
        title="Reflected XSS",
        severity=Severity.HIGH,
        confidence=Confidence.VERIFIED,
        status=FindingStatus.VERIFIED,
        affected_asset="https://example.com/search",
        source="scanner",
    )
    f2 = FindingRecord(
        scan_id="scan_off",
        title="Exposed Database Port",
        severity=Severity.MEDIUM,
        confidence=Confidence.VERIFIED,
        status=FindingStatus.VERIFIED,
        affected_asset="example.com:3306",
        source="scanner",
    )
    db.insert_finding(f1)
    db.insert_finding(f2)

    analyzer = Analyzer(OfflineAdapter(), db, "scan_off")

    async def _test():
        findings = db.get_findings("scan_off")
        poc_text = await analyzer.generate_exploit_poc(findings[0])
        assert "OFFENSIVE PoC PACKAGE" in poc_text
        assert "CURL VERIFICATION COMMAND:" in poc_text
        assert "Deterministic reproduction PoC package generated" in poc_text

        chain = await analyzer.generate_attack_chain()
        assert "Correlated Multi-Vector Attack Surface" in chain
        assert "Reflected XSS" in chain

    asyncio.run(_test())
    db.close()


def test_event_technology_detected_is_discovery():
    """Verifies that TECHNOLOGY_DETECTED is properly categorized as a discovery event."""
    from reconai.core.events.types import Event, EventType

    ev1 = Event(type=EventType.TECHNOLOGY_DETECTED, source="waf", data={"tech": "Cloudflare"})
    assert ev1.is_discovery is True

    ev2 = Event(type=EventType.SUBDOMAIN_DISCOVERED, source="dns", data={"sub": "api.test.com"})
    assert ev2.is_discovery is True

    ev3 = Event(type=EventType.MODULE_STARTED, source="ports", data={})
    assert ev3.is_discovery is False


def test_correlation_engine_cloud_assets_and_dedup(tmp_path: Path):
    """Verifies correlation engine links cloud assets and deduplicates findings per host."""
    from reconai.core.correlation.engine import CorrelationEngine
    from reconai.core.database.models import SubdomainRecord, CloudAssetRecord

    db = DatabaseManager(db_path=tmp_path / "test_corr.db")
    db.connect()

    scan = ScanRecord(id="scan_corr", target="myorg.com", status=ScanStatus.COMPLETED)
    db.create_scan(scan)

    sub = SubdomainRecord(scan_id="scan_corr", subdomain="assets.myorg.com", domain="myorg.com")
    db.insert_subdomain(sub)

    # Cloud asset linked by CNAME metadata
    ca = CloudAssetRecord(
        scan_id="scan_corr",
        provider="aws",
        asset_type="s3_bucket",
        asset_name="myorg-assets-prod",
        url="http://myorg-assets-prod.s3.amazonaws.com",
        is_public=True,
        metadata={"cname_from": "assets.myorg.com"},
    )
    db.insert_cloud_asset(ca)

    # Duplicate findings on different paths of same host
    f1 = FindingRecord(
        scan_id="scan_corr",
        title="Missing Security Headers",
        severity=Severity.LOW,
        affected_asset="http://assets.myorg.com/login",
    )
    f2 = FindingRecord(
        scan_id="scan_corr",
        title="Missing Security Headers",
        severity=Severity.LOW,
        affected_asset="http://assets.myorg.com/api",
    )
    db.insert_finding(f1)
    db.insert_finding(f2)

    corr = CorrelationEngine(db, "scan_corr")
    chains = corr.get_correlated_chains()

    assert len(chains) == 1
    ch = chains[0]
    assert ch["host"] == "assets.myorg.com"
    # Verify cloud asset is linked
    assert len(ch["cloud_assets"]) == 1
    assert "myorg-assets-prod" in ch["cloud_assets"][0]
    # Verify findings are deduplicated
    assert len(ch["findings"]) == 1
    assert ch["findings"][0]["title"] == "Missing Security Headers"

    db.close()


