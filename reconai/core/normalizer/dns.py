"""DNS data normalizer.

Normalizes raw DNS query results into structured DNSRecord models.
"""
from __future__ import annotations

import ipaddress

from reconai.core.database.models import DNSRecord


def normalize_dns_records(hostname: str, record_type: str, values: list[str], ttl: int, source: str, scan_id: str) -> list[DNSRecord]:
    """Normalize and validate raw DNS values into DNSRecord models."""
    records = []
    for val in values:
        val = val.strip().strip('"')
        if not val:
            continue

        # Validate IP addresses for A/AAAA records
        if record_type == "A":
            try:
                ipaddress.IPv4Address(val)
            except ValueError:
                continue
        elif record_type == "AAAA":
            try:
                ipaddress.IPv6Address(val)
            except ValueError:
                continue

        records.append(DNSRecord(
            scan_id=scan_id,
            hostname=hostname.lower().rstrip("."),
            record_type=record_type,
            value=val.lower().rstrip(".") if record_type in ("CNAME", "NS", "MX") else val,
            ttl=ttl,
            source=source
        ))

    return records
