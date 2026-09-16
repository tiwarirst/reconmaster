"""CVE Intelligence Engine.

Fetches real, live CVE data from:
1. NIST NVD API v2 (authoritative, free, no API key needed)
2. CVE.mitre.org as fallback
3. Local cache to avoid repeated fetches

Returns structured CVE data including CVSS v3 score, attack vector,
attack complexity, privileges required, and exploitability metrics.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


# ─── Optional httpx import ───────────────────────────────────────────────────
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 86400  # 24 hours


class CVERecord:
    """Structured CVE intelligence record."""

    def __init__(self, cve_id: str, data: dict[str, Any]) -> None:
        self.cve_id = cve_id.upper()
        self._data: dict[str, Any] = data

    @property
    def description(self) -> str:
        descs = (
            self._data.get("descriptions", [])
            or self._data.get("cve", {}).get("descriptions", [])
        )
        for d in descs:
            if d.get("lang") == "en":
                return str(d.get("value", ""))
        return ""

    @property
    def cvss_v3_score(self) -> float | None:
        return self._get_cvss_v3().get("baseScore")

    @property
    def cvss_v3_vector(self) -> str:
        return str(self._get_cvss_v3().get("vectorString", ""))

    @property
    def cvss_severity(self) -> str:
        return str(self._get_cvss_v3().get("baseSeverity", "UNKNOWN"))

    @property
    def attack_vector(self) -> str:
        return str(self._get_cvss_v3().get("attackVector", "UNKNOWN"))

    @property
    def attack_complexity(self) -> str:
        return str(self._get_cvss_v3().get("attackComplexity", "UNKNOWN"))

    @property
    def privileges_required(self) -> str:
        return str(self._get_cvss_v3().get("privilegesRequired", "UNKNOWN"))

    @property
    def user_interaction(self) -> str:
        return str(self._get_cvss_v3().get("userInteraction", "UNKNOWN"))

    @property
    def confidentiality_impact(self) -> str:
        return str(self._get_cvss_v3().get("confidentialityImpact", "UNKNOWN"))

    @property
    def cwe_ids(self) -> list[str]:
        weaknesses = self._data.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)
        return cwes

    @property
    def references(self) -> list[str]:
        refs = self._data.get("references", [])
        return [r.get("url", "") for r in refs if r.get("url")]

    @property
    def exploit_db_refs(self) -> list[str]:
        return [r for r in self.references if "exploit-db.com" in r]

    @property
    def github_poc_refs(self) -> list[str]:
        return [r for r in self.references if "github.com" in r]

    @property
    def published(self) -> str:
        return str(self._data.get("published", ""))

    @property
    def is_critical(self) -> bool:
        score = self.cvss_v3_score
        return score is not None and score >= 9.0

    def _get_cvss_v3(self) -> dict[str, Any]:
        metrics: dict[str, Any] = self._data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                return dict(entries[0].get("cvssData", {}))
        return {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v3_vector": self.cvss_v3_vector,
            "cvss_severity": self.cvss_severity,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "confidentiality_impact": self.confidentiality_impact,
            "cwe_ids": self.cwe_ids,
            "references": self.references[:20],
            "exploit_db_refs": self.exploit_db_refs,
            "github_poc_refs": self.github_poc_refs,
            "published": self.published,
        }

    def __repr__(self) -> str:
        score = self.cvss_v3_score or "N/A"
        return f"<CVERecord {self.cve_id} CVSS={score} [{self.cvss_severity}]>"


class CVELookup:
    """Fetches and caches CVE data from NVD."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or Path.home() / ".cache" / "reconai" / "cve"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def lookup(self, cve_id: str) -> CVERecord | None:
        """Look up a single CVE. Uses cache first, then NVD API."""
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            return None

        # Check cache
        cached = self._load_cache(cve_id)
        if cached:
            return CVERecord(cve_id, cached)

        # Fetch from NVD
        data = self._fetch_nvd(cve_id)
        if data:
            self._save_cache(cve_id, data)
            return CVERecord(cve_id, data)

        return None

    def lookup_batch(self, cve_ids: list[str]) -> dict[str, CVERecord]:
        """Look up multiple CVEs. Returns a mapping of cve_id -> CVERecord."""
        results = {}
        for cve_id in cve_ids:
            record = self.lookup(cve_id)
            if record:
                results[cve_id.upper()] = record
        return results

    def _fetch_nvd(self, cve_id: str) -> dict[str, Any] | None:
        if not HAS_HTTPX:
            return None
        try:
            # NVD API rate limit: 5 req/30s without API key
            time.sleep(0.7)
            resp = httpx.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                timeout=15.0,
                headers={"User-Agent": "ReconAI/1.0 (Security Research)"}
            )
            if resp.status_code == 200:
                data: dict[str, Any] = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    return dict(vulns[0].get("cve", {}))
        except Exception:
            pass
        return None

    def _cache_path(self, cve_id: str) -> Path:
        return self.cache_dir / f"{cve_id}.json"

    def _load_cache(self, cve_id: str) -> dict[str, Any] | None:
        path = self._cache_path(cve_id)
        if not path.exists():
            return None
        if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
            return None
        try:
            result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            return result
        except Exception:
            return None

    def _save_cache(self, cve_id: str, data: dict[str, Any]) -> None:
        try:
            self._cache_path(cve_id).write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
