"""Unit tests for the DNS normalizer."""
from __future__ import annotations

from reconai.core.normalizer.dns import normalize_dns_records


def test_normalize_a_records():
    records = normalize_dns_records("example.com", "A", ["1.2.3.4"], ttl=300, source="dns", scan_id="test")
    assert len(records) == 1
    assert records[0].value == "1.2.3.4"


def test_normalize_invalid_a_record():
    records = normalize_dns_records("example.com", "A", ["not-an-ip"], ttl=300, source="dns", scan_id="test")
    assert len(records) == 0


def test_normalize_mx_records():
    records = normalize_dns_records("example.com", "MX", ["10 mail.example.com."], ttl=300, source="dns", scan_id="test")
    assert len(records) == 1
