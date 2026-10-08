"""Unit tests verifying project-wide bug fixes and fail-safe robustness."""
import asyncio
from pathlib import Path
import pytest

from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import FindingRecord, ScanRecord, Severity, ScanStatus
from reconai.intelligence.poc_generator import PoCGenerator
from reconai.modules.base import ReconModule, ModuleConfig
from reconai.core.events.bus import EventBus
from reconai.core.logging.logger import ReconLogger
from reconai.core.executor.command_runner import CommandRunner
from reconai.ai.adapter import AIAdapter
from reconai.ai.analyzer import Analyzer


def test_poc_generator_all_attack_classes():
    """Verify that all 17 attack classes generate runnable python_script and curl_command."""
    gen = PoCGenerator()
    attack_classes = [
        "xss", "cross-site scripting", "sqli", "sql injection", "ssrf",
        "server-side request forgery", "idor", "ssti", "lfi", "rce",
        "open redirect", "xxe", "crlf injection", "secret", "exposed",
        "subdomain takeover", "default"
    ]
    for ac in attack_classes:
        f = {
            "title": f"Test {ac} Finding",
            "attack_class": ac,
            "affected_asset": "https://target.corp/api/endpoint?q=1",
        }
        poc = gen.generate(f)
        assert poc.python_script, f"Missing python_script for attack class: {ac}"
        assert poc.curl_command or ac == "subdomain takeover", f"Missing curl_command for attack class: {ac}"


def test_database_manager_create_scan_string_and_record(tmp_path: Path):
    """Verify create_scan handles both string targets and ScanRecord objects seamlessly."""
    db = DatabaseManager(tmp_path / "test_scan_create.db")
    db.connect()
    try:
        # String target
        id1 = db.create_scan("example.com")
        assert isinstance(id1, str) and len(id1) > 0
        s1 = db.get_scan(id1)
        assert s1 is not None and s1["target"] == "example.com"

        # ScanRecord target
        id2 = db.create_scan(ScanRecord(id="custom_id", target="sub.example.com"))
        assert id2 == "custom_id"
        s2 = db.get_scan("custom_id")
        assert s2 is not None and s2["target"] == "sub.example.com"
    finally:
        db.close()


def test_recon_module_base_properties():
    """Verify ReconModule exposes name, description, and category properties."""
    class DummyModule(ReconModule):
        config = ModuleConfig(
            name="dummy_test",
            category="passive",
            description="A dummy test module",
        )
        async def run(self, **kwargs):
            return None

    db = DatabaseManager(":memory:")
    db.connect()
    try:
        mod = DummyModule(
            db=db,
            events=EventBus(),
            logger=ReconLogger(),
            runner=CommandRunner(),
        )
        assert mod.name == "dummy_test"
        assert mod.category == "passive"
        assert mod.description == "A dummy test module"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_analyzer_summarize_findings_fallback_when_findings_present(tmp_path: Path):
    """Verify Analyzer provides a rich fallback summary when LLM is offline and findings exist."""
    class EmptyAIAdapter(AIAdapter):
        async def is_available(self) -> bool:
            return False
        async def analyze(self, prompt: str) -> str:
            return ""

    db = DatabaseManager(tmp_path / "test_summary.db")
    db.connect()
    try:
        scan_id = db.create_scan("corp.target.com")
        db.insert_finding(FindingRecord(
            scan_id=scan_id,
            title="Remote Code Execution",
            severity=Severity.CRITICAL,
            affected_asset="https://corp.target.com/api/cmd",
        ))

        analyzer = Analyzer(EmptyAIAdapter(), db, scan_id)
        summary = await analyzer.summarize_findings()
        assert "Remote Code Execution" in summary or "CRITICAL" in summary.upper() or "vulnerability findings" in summary
        assert len(summary) > 50
    finally:
        db.close()
