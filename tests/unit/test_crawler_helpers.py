"""Unit tests for crawler domain matching logic."""
from __future__ import annotations

from urllib.parse import urlparse


def _normalize_host(host: str) -> str:
    h = host.lower().strip()
    if h.startswith("www."):
        h = h[4:]
    return h


def test_crawler_domain_normalization():
    start_domain = "example.com"
    norm_start = _normalize_host(start_domain)

    # Valid internal links
    link1 = "https://www.example.com/about"
    host1 = _normalize_host(urlparse(link1).netloc)
    assert host1 == norm_start or host1.endswith("." + norm_start)

    # Subdomain link
    link2 = "https://blog.example.com/post"
    host2 = _normalize_host(urlparse(link2).netloc)
    assert host2 == norm_start or host2.endswith("." + norm_start)

    # External link should be rejected
    link3 = "https://google.com/search"
    host3 = _normalize_host(urlparse(link3).netloc)
    assert not (host3 == norm_start or host3.endswith("." + norm_start))


def test_path_template_collapsing():
    from reconai.modules.web.crawler import _path_template
    assert _path_template("/api/users/123/profile") == "/api/users/{id}/profile"
    assert _path_template("/blog/posts/999") == "/blog/posts/{id}"
    assert _path_template("/items/550e8400-e29b-41d4-a716-446655440000") == "/items/{uuid}"


def test_report_generator_includes_crawled_urls_and_apis(tmp_path):
    from reconai.core.database.manager import DatabaseManager
    from reconai.core.database.models import ScanRecord, ScanStatus, URLRecord, APIEndpoint
    from reconai.reports.generator import ReportGenerator

    db = DatabaseManager(db_path=tmp_path / "test.db")
    scan_id = "test_scan_01"
    scan = ScanRecord(id=scan_id, target="example.com", status=ScanStatus.COMPLETED)
    db.create_scan(scan)

    # Insert test URL and API
    db.insert_url(URLRecord(scan_id=scan_id, url="https://example.com/login", method="GET", status_code=200, source="crawler"))
    db.insert_api_endpoint(APIEndpoint(scan_id=scan_id, host="https://example.com", method="GET", path="/api/v1/auth", source="api_miner"))

    generator = ReportGenerator(db, scan_id, tmp_path)
    reports = generator.generate_all()

    # Verify HTML report
    html_content = reports["html"].read_text(encoding="utf-8")
    assert "Crawled Web Endpoints & URLs" in html_content
    assert "https://example.com/login" in html_content
    assert "Discovered API Routes & Endpoints" in html_content
    assert "/api/v1/auth" in html_content

    # Verify Markdown report
    md_content = reports["markdown"].read_text(encoding="utf-8")
    assert "Crawled Web Endpoints & URLs" in md_content
    assert "https://example.com/login" in md_content

    # Verify CSV files
    assert "urls" in reports["csv"]
    assert "api_endpoints" in reports["csv"]
    assert reports["csv"]["urls"].exists()
