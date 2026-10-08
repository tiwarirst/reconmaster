"""Unit test for CrawlerModule concurrency, form parsing, and batch persistence."""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import ScanRecord, ScanStatus
from reconai.core.events.bus import EventBus
from reconai.modules.web.crawler import CrawlerModule


@pytest.mark.asyncio
async def test_crawler_concurrent_extraction_and_batch_persistence(tmp_path):
    db_file = tmp_path / "crawl_test.db"
    db = DatabaseManager(db_path=db_file)
    scan_id = "crawl_scan_01"

    scan = ScanRecord(id=scan_id, target="testapp.local", status=ScanStatus.RUNNING)
    db.create_scan(scan)

    events = EventBus()
    logger = MagicMock()

    runner = MagicMock()
    crawler = CrawlerModule(
        db=db,
        events=events,
        logger=logger,
        runner=runner,
    )
    crawler.scan_id = scan_id
    crawler.target = "http://testapp.local"

    sample_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Admin & API Portal</title></head>
      <body>
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <script src="/static/app.js"></script>
        <form action="/login" method="POST">
          <input type="text" name="username" />
          <input type="password" name="password" />
        </form>
        <form action="/search" method="GET">
          <input type="text" name="q" />
        </form>
        <script>
          const api = "/api/v1/users";
          fetch("/api/v2/metrics");
        </script>
      </body>
    </html>
    """

    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/html; charset=utf-8"}
    mock_response.text = sample_html
    mock_response.content = sample_html.encode("utf-8")
    mock_response.url = "http://testapp.local"

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)

    # Run crawl host directly with mock client
    await crawler._crawl_host(mock_client, "http://testapp.local", max_depth=2, max_pages=10)

    # Verify URLs were persisted in batch
    crawled_urls = db.get_urls(scan_id)
    url_strings = [u["url"] for u in crawled_urls]
    assert any("testapp.local" in u for u in url_strings)
    assert any("search?q=test" in u for u in url_strings)

    # Verify API endpoints were extracted (Form POST and SPA endpoints)
    api_endpoints = db.get_api_endpoints(scan_id)
    api_paths = [a["path"] for a in api_endpoints]
    assert any("/login" in p for p in api_paths)
    assert any("/api/v1/users" in p for p in api_paths)
    assert any("/api/v2/metrics" in p for p in api_paths)
