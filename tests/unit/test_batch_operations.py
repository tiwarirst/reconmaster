"""Unit tests for high-throughput database batch operations and concurrency helpers."""
from __future__ import annotations

from datetime import datetime

from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import (
    APIEndpoint,
    DNSRecord,
    PortRecord,
    ScanRecord,
    ScanStatus,
    SubdomainRecord,
    TechnologyRecord,
    URLRecord,
)


def test_database_batch_inserts(tmp_path):
    db_file = tmp_path / "batch_test.db"
    db = DatabaseManager(db_path=db_file)
    scan_id = "batch_scan_01"

    scan = ScanRecord(id=scan_id, target="example.com", status=ScanStatus.RUNNING)
    db.create_scan(scan)

    # 1. Test insert_urls_batch
    urls = [
        URLRecord(scan_id=scan_id, url=f"https://example.com/page{i}", method="GET", status_code=200, source="crawler")
        for i in range(25)
    ]
    inserted_urls = db.insert_urls_batch(urls)
    assert inserted_urls == 25
    assert len(db.get_urls(scan_id)) == 25

    # 2. Test insert_subdomains_batch
    subs = [
        SubdomainRecord(scan_id=scan_id, subdomain=f"sub{i}.example.com", domain="example.com", sources=["ct"])
        for i in range(15)
    ]
    inserted_subs = db.insert_subdomains_batch(subs)
    assert inserted_subs == 15
    assert len(db.get_subdomains(scan_id)) == 15

    # 3. Test insert_ports_batch
    ports = [
        PortRecord(scan_id=scan_id, host="example.com", port=p, protocol="tcp", state="open", service="http")
        for p in [80, 443, 8080, 8443, 9000]
    ]
    inserted_ports = db.insert_ports_batch(ports)
    assert inserted_ports == 5
    assert len(db.get_ports(scan_id)) == 5

    # 4. Test insert_api_endpoints_batch
    apis = [
        APIEndpoint(scan_id=scan_id, host="example.com", method="GET", path=f"/api/v1/item/{i}", full_url=f"https://example.com/api/v1/item/{i}", source="spa")
        for i in range(10)
    ]
    inserted_apis = db.insert_api_endpoints_batch(apis)
    assert inserted_apis == 10
    assert len(db.get_api_endpoints(scan_id)) == 10

    # 5. Test insert_technologies_batch
    techs = [
        TechnologyRecord(scan_id=scan_id, host="example.com", name="Nginx", category="Web Server", confidence=90.0, source="http")
    ]
    inserted_techs = db.insert_technologies_batch(techs)
    assert inserted_techs == 1
    assert len(db.get_technologies(scan_id)) == 1

    # 6. Test insert_dns_records_batch
    dns_recs = [
        DNSRecord(scan_id=scan_id, hostname="example.com", record_type="A", value="93.184.216.34", source="dns", timestamp=datetime.utcnow())
    ]
    inserted_dns = db.insert_dns_records_batch(dns_recs)
    assert inserted_dns == 1
    assert len(db.get_dns_records(scan_id)) == 1
