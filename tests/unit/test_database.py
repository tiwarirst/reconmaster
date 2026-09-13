"""Unit tests for the DatabaseManager."""
from __future__ import annotations

import pytest
from datetime import datetime

from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import (
    ScanRecord, ScanStatus, SubdomainRecord, PortRecord, FindingRecord, FindingStatus, Severity, Confidence
)


@pytest.fixture
def db():
    """In-memory database for testing."""
    manager = DatabaseManager(db_path=":memory:")
    manager.connect()
    yield manager
    manager.close()


def test_create_scan(db):
    scan = ScanRecord(id="test-001", target="example.com", mode="standard", profile="quick")
    db.create_scan(scan)
    result = db.get_scan("test-001")
    assert result is not None
    assert result["target"] == "example.com"


def test_insert_subdomain(db):
    scan = ScanRecord(id="test-002", target="example.com")
    db.create_scan(scan)
    sub = SubdomainRecord(scan_id="test-002", subdomain="api.example.com", domain="example.com")
    db.insert_subdomain(sub)
    subs = db.get_subdomains("test-002")
    assert len(subs) == 1
    assert subs[0]["subdomain"] == "api.example.com"


def test_insert_port(db):
    scan = ScanRecord(id="test-003", target="192.168.1.1")
    db.create_scan(scan)
    port = PortRecord(scan_id="test-003", host="192.168.1.1", port=443, protocol="tcp", state="open")
    db.insert_port(port)
    ports = db.get_ports("test-003")
    assert len(ports) == 1
    assert ports[0]["port"] == 443


def test_insert_finding(db):
    scan = ScanRecord(id="test-004", target="example.com")
    db.create_scan(scan)
    finding = FindingRecord(
        scan_id="test-004",
        title="Test Finding",
        severity=Severity.HIGH,
        confidence=Confidence.VERIFIED,
        status=FindingStatus.VERIFIED,
        affected_asset="https://example.com",
    )
    db.insert_finding(finding)
    findings = db.get_findings("test-004")
    assert len(findings) == 1
    assert findings[0]["title"] == "Test Finding"


def test_scan_stats(db):
    scan = ScanRecord(id="test-005", target="example.com")
    db.create_scan(scan)
    stats = db.get_scan_stats("test-005")
    assert stats["subdomains"] == 0
    assert stats["findings"] == 0
