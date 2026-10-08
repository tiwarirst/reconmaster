"""AI Smart Attack Surface & URL Prioritizer.

Filters noise from crawled endpoints and prioritizes high-value targets
(authentication endpoints, sensitive APIs, file upload handlers, administrative interfaces)
so red team fuzzers (Nuclei, Dalfox, FFUF) concentrate on high-leverage entry points.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs
from typing import Any

from reconai.core.database.manager import DatabaseManager


# ── High-Risk Keyword Token Weights ───────────────────────────────────────
_HIGH_VALUE_PATTERNS = [
    (r"(admin|dashboard|portal|root|manager)", 90, "Administrative Interface"),
    (r"(login|signin|auth|oauth|sso|token|jwt|session)", 85, "Authentication / Token Flow"),
    (r"(upload|file|attachment|avatar|import)", 80, "File Upload / Storage Handler"),
    (r"(graphql|api/v\d+|swagger|openapi|actuator)", 75, "API / Schema Exposure"),
    (r"(reset|password|recover|invite)", 70, "Credential Management"),
    (r"(redirect|url|dest|next|forward|return)", 65, "Potential Open Redirect / SSRF"),
    (r"(debug|test|dev|staging|console|trace)", 60, "Development / Debugging Interface"),
    (r"(search|query|find|filter|q)", 50, "Input Reflection / SQLi / XSS"),
]

# ── Noise Extensions to Skip ─────────────────────────────────────────────
_NOISE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".pdf", ".map",
}


class AttackSurfacePrioritizer:
    """Classifies and ranks crawled URLs by offensive red team value."""

    def __init__(self, db: DatabaseManager, scan_id: str) -> None:
        self.db = db
        self.scan_id = scan_id

    def prioritize_endpoints(self, limit: int = 50) -> list[dict[str, Any]]:
        """Extracts and ranks endpoints from database."""
        url_records = self.db.get_urls(self.scan_id)
        api_records = self.db.get_api_endpoints(self.scan_id) if hasattr(self.db, "get_api_endpoints") else []

        candidates: dict[str, dict[str, Any]] = {}

        # 1. Process regular URLs
        for rec in url_records:
            url_str = str(rec.get("url", ""))
            if not url_str or any(url_str.lower().endswith(ext) for ext in _NOISE_EXTENSIONS):
                continue
            scored = self._score_url(url_str, rec)
            if scored["score"] > 20:
                candidates[url_str] = scored

        # 2. Process API endpoints
        for api in api_records:
            full = str(api.get("full_url") or f"https://{api.get('host')}{api.get('path')}")
            scored = self._score_url(full, api, is_api=True)
            candidates[full] = scored

        # Sort by score descending
        sorted_candidates = sorted(candidates.values(), key=lambda x: x["score"], reverse=True)
        return sorted_candidates[:limit]

    def _score_url(self, url_str: str, record: dict[str, Any], is_api: bool = False) -> dict[str, Any]:
        """Calculates risk score and suggested test vectors for a single URL."""
        parsed = urlparse(url_str)
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = f"{path}?{query}"

        score = 30 if is_api else 10
        categories: list[str] = []
        vectors: list[str] = []

        # Check path and query against high-value patterns
        for pattern, weight, label in _HIGH_VALUE_PATTERNS:
            if re.search(pattern, full):
                score = max(score, weight)
                categories.append(label)

        # Query parameter bonuses
        params = parse_qs(parsed.query)
        if params:
            score += min(len(params) * 5, 20)
            param_names = [p.lower() for p in params.keys()]
            if any(p in param_names for p in ["url", "dest", "redirect", "next", "link", "target"]):
                vectors.append("SSRF / Open Redirect")
                score = max(score, 85)
            if any(p in param_names for p in ["id", "uid", "user", "account", "doc", "order"]):
                vectors.append("IDOR / Broken Object Level Auth (BOLA)")
                score = max(score, 80)
            if any(p in param_names for p in ["q", "search", "query", "term"]):
                vectors.append("SQL Injection / Reflected XSS")
            if any(p in param_names for p in ["cmd", "exec", "file", "path", "template"]):
                vectors.append("Command Injection / Path Traversal")
                score = max(score, 90)

        if not vectors:
            if "upload" in full:
                vectors.append("Unrestricted File Upload / Extension Bypass")
            elif "auth" in full or "login" in full:
                vectors.append("Authentication Bypass / Rate-Limit Testing")
            elif is_api:
                vectors.append("API Fuzzing / Broken Function Level Auth")
            else:
                vectors.append("Input Fuzzing & Parameter Tampering")

        return {
            "url": url_str,
            "host": parsed.netloc,
            "path": parsed.path,
            "score": min(score, 100),
            "priority": "CRITICAL" if score >= 85 else ("HIGH" if score >= 70 else "MEDIUM"),
            "categories": list(dict.fromkeys(categories)),
            "suggested_vectors": list(dict.fromkeys(vectors)),
        }
