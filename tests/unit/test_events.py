"""Unit tests for the event system and EventType enumeration."""
from __future__ import annotations

from reconai.core.events.types import EventType, Event


def test_finding_discovered_event_type_exists():
    assert hasattr(EventType, "FINDING_DISCOVERED")
    assert EventType.FINDING_DISCOVERED == "finding.discovered"


def test_event_instantiation_with_finding_discovered():
    event = Event(
        type=EventType.FINDING_DISCOVERED,
        source="nuclei_vuln",
        scan_id="test-scan-001",
        data={"title": "Exposed API Key", "severity": "HIGH"},
    )
    assert event.type == EventType.FINDING_DISCOVERED
    assert event.source == "nuclei_vuln"
    assert event.data["severity"] == "HIGH"
