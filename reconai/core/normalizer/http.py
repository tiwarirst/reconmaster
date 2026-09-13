"""HTTP data normalizer.

Normalizes httpx/httplib responses into structured URLRecord models.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from reconai.core.database.models import URLRecord


def normalize_url_record(url: str, status: int, content_type: str = "", content_length: int = 0, title: str = "", source: str = "http_probe", scan_id: str = "") -> URLRecord | None:
    """Validate and normalize a URL response into a URLRecord."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
    except Exception:
        return None

    # Extract title from HTML if not provided
    if not title:
        title = ""

    return URLRecord(
        scan_id=scan_id,
        url=url,
        method="GET",
        status_code=status,
        content_type=content_type,
        content_length=content_length,
        title=title[:200],
        source=source
    )


def extract_title(html: str) -> str:
    """Extracts <title> from raw HTML."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:200]
    return ""
