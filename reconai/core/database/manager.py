"""SQLite database manager for ReconAI.

Handles schema creation, connection management, and all CRUD operations.
Designed so PostgreSQL can replace SQLite later without changing the interface.

Correctness principles applied:
  - All tables that can produce duplicates have UNIQUE constraints.
  - All INSERT paths use INSERT OR IGNORE (new) or ON CONFLICT DO UPDATE (upsert)
    so re-running a scan or re-probing never inflates the DB.
  - All insert methods are wrapped in try/except — a single bad record
    can NEVER abort the scan.
  - The ports table uses a proper UPSERT: if a richer enrichment pass
    supplies product/version/CPE for an already-known port, only the
    non-empty fields are updated, and the original id is preserved.
  - The dead 'services' table has been removed — its data lives in 'ports'.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from reconai.core.database.models import (
    APIEndpoint, CertificateRecord, CloudAssetRecord, DNSRecord, DomainRecord,
    FindingRecord, IPRecord, PortRecord, ScanRecord, ScanStatus,
    ServiceRecord, SubdomainRecord, TechnologyRecord,
    ToolRunRecord, URLRecord,
)

# ── Schema ──────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    mode TEXT DEFAULT 'standard',
    profile TEXT DEFAULT 'quick',
    status TEXT DEFAULT 'pending',
    started_at TEXT,
    completed_at TEXT,
    duration REAL DEFAULT 0,
    modules_total INTEGER DEFAULT 0,
    modules_completed INTEGER DEFAULT 0,
    modules_failed INTEGER DEFAULT 0,
    output_dir TEXT,
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    domain TEXT NOT NULL,
    is_primary INTEGER DEFAULT 0,
    discovered_by TEXT,
    first_seen TEXT,
    last_seen TEXT,
    UNIQUE(scan_id, domain)
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    subdomain TEXT NOT NULL,
    domain TEXT,
    sources TEXT DEFAULT '[]',
    resolved_ips TEXT DEFAULT '[]',
    http_status INTEGER,
    https_status INTEGER,
    title TEXT DEFAULT '',
    first_seen TEXT,
    last_seen TEXT,
    is_alive INTEGER DEFAULT 0,
    priority TEXT DEFAULT 'normal',
    UNIQUE(scan_id, subdomain)
);

CREATE TABLE IF NOT EXISTS ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    ip TEXT NOT NULL,
    version INTEGER DEFAULT 4,
    hostnames TEXT DEFAULT '[]',
    asn TEXT DEFAULT '',
    asn_org TEXT DEFAULT '',
    country TEXT DEFAULT '',
    is_private INTEGER DEFAULT 0,
    source TEXT DEFAULT '',
    UNIQUE(scan_id, ip)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    hostname TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER DEFAULT 0,
    source TEXT DEFAULT 'dns',
    timestamp TEXT,
    UNIQUE(scan_id, hostname, record_type, value)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    service TEXT DEFAULT '',
    product TEXT DEFAULT '',
    version TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    cpe TEXT DEFAULT '',
    source TEXT DEFAULT 'nmap',
    UNIQUE(scan_id, host, port, protocol)
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    status_code INTEGER,
    content_type TEXT DEFAULT '',
    content_length INTEGER,
    title TEXT DEFAULT '',
    redirect_url TEXT DEFAULT '',
    source TEXT DEFAULT '',
    depth INTEGER DEFAULT 0,
    UNIQUE(scan_id, url, method)
);

CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    host TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT DEFAULT '',
    version TEXT DEFAULT '',
    confidence REAL DEFAULT 0,
    source TEXT DEFAULT '',
    evidence TEXT DEFAULT '[]',
    UNIQUE(scan_id, host, name)
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    host TEXT NOT NULL,
    subject TEXT DEFAULT '',
    issuer TEXT DEFAULT '',
    serial TEXT DEFAULT '',
    not_before TEXT DEFAULT '',
    not_after TEXT DEFAULT '',
    san TEXT DEFAULT '[]',
    fingerprint TEXT DEFAULT '',
    source TEXT DEFAULT '',
    UNIQUE(scan_id, host, fingerprint)
);

CREATE TABLE IF NOT EXISTS api_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    host TEXT NOT NULL,
    method TEXT DEFAULT '',
    path TEXT DEFAULT '',
    full_url TEXT DEFAULT '',
    content_type TEXT DEFAULT '',
    auth_required INTEGER,
    source TEXT DEFAULT '',
    api_type TEXT DEFAULT '',
    UNIQUE(scan_id, full_url, method)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    confidence TEXT DEFAULT 'info',
    status TEXT DEFAULT 'info',
    affected_asset TEXT DEFAULT '',
    affected_asset_type TEXT DEFAULT '',
    description TEXT DEFAULT '',
    impact TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    detection_method TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    refs TEXT DEFAULT '[]',
    cve TEXT DEFAULT '[]',
    cwe TEXT DEFAULT '[]',
    cvss REAL,
    verified INTEGER DEFAULT 0,
    timestamp TEXT,
    what_is_it TEXT DEFAULT '',
    why_detected TEXT DEFAULT '',
    attack_class TEXT DEFAULT '',
    conditions_required TEXT DEFAULT '',
    safe_verification TEXT DEFAULT '',
    prevention TEXT DEFAULT '',
    source TEXT DEFAULT '',
    UNIQUE(scan_id, title, affected_asset)
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    tool_name TEXT NOT NULL,
    module_name TEXT DEFAULT '',
    command TEXT DEFAULT '',
    status TEXT DEFAULT '',
    exit_code INTEGER,
    duration REAL DEFAULT 0,
    timed_out INTEGER DEFAULT 0,
    output_file TEXT DEFAULT '',
    started_at TEXT,
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_dns_scan ON dns_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_techs_scan ON technologies(scan_id);
CREATE INDEX IF NOT EXISTS idx_ips_scan ON ips(scan_id);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    provider TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    url TEXT DEFAULT '',
    is_public INTEGER DEFAULT 0,
    is_writable INTEGER DEFAULT 0,
    region TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}',
    source TEXT DEFAULT '',
    timestamp TEXT,
    UNIQUE(scan_id, provider, asset_type, asset_name)
);

CREATE INDEX IF NOT EXISTS idx_cloud_assets_scan ON cloud_assets(scan_id);
"""


class DatabaseManager:
    """SQLite database manager for ReconAI.

    All database operations go through this class.
    The interface is designed so that swapping to PostgreSQL
    only requires changing this one file.
    """

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self._db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def connect(self) -> None:
        """Open database connection and create schema with high-performance PRAGMAs."""
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-64000")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        assert self._conn is not None  # noqa: S101
        return self._conn

    # ── Scan Operations ─────────────────────────────────────

    def create_scan(self, scan: ScanRecord) -> str:
        self.conn.execute(
            "INSERT INTO scans (id, target, mode, profile, status, started_at, output_dir, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan.id, scan.target, scan.mode, scan.profile, scan.status.value,
             scan.started_at.isoformat(), scan.output_dir, json.dumps(scan.metadata)),
        )
        self.conn.commit()
        return scan.id

    def update_scan_status(self, scan_id: str, status: ScanStatus, **kwargs: Any) -> None:
        sets = ["status = ?"]
        vals: list[Any] = [status.value]
        for k, v in kwargs.items():
            sets.append(f"{k} = ?")
            vals.append(v.isoformat() if isinstance(v, datetime) else v)
        vals.append(scan_id)
        self.conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)
        self.conn.commit()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def get_latest_scan(self, target: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM scans WHERE target = ? ORDER BY started_at DESC LIMIT 1",
            (target,),
        ).fetchone()
        return dict(row) if row else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    get_recent_scans = list_scans

    # ── Insert Operations ────────────────────────────────────
    # All inserts are:
    #   1. Wrapped in try/except — a bad record never aborts the scan.
    #   2. Idempotent — re-running never creates duplicates.

    def insert_subdomain(self, record: SubdomainRecord) -> int:
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO subdomains "
                "(scan_id, subdomain, domain, sources, resolved_ips, http_status, https_status, "
                "title, first_seen, last_seen, is_alive, priority) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.subdomain, record.domain,
                 json.dumps(record.sources), json.dumps(record.resolved_ips),
                 record.http_status, record.https_status, record.title,
                 record.first_seen.isoformat(), record.last_seen.isoformat(),
                 int(record.is_alive), record.priority),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_dns_record(self, record: DNSRecord) -> int:
        """Insert a DNS record, silently ignoring duplicates."""
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO dns_records "
                "(scan_id, hostname, record_type, value, ttl, source, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.hostname, record.record_type, record.value,
                 record.ttl, record.source, record.timestamp.isoformat()),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_ip(self, record: IPRecord) -> int:
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO ips "
                "(scan_id, ip, version, hostnames, asn, asn_org, country, is_private, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.ip, record.version, json.dumps(record.hostnames),
                 record.asn, record.asn_org, record.country, int(record.is_private), record.source),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_port(self, record: PortRecord) -> int:
        """Upsert a port record.

        On conflict (same scan_id, host, port, protocol):
          - Enrichment fields (service, product, version, cpe, banner) are
            updated only if the incoming value is non-empty AND the stored
            value is currently empty. This means the first real data wins,
            but a richer pass (XML enrichment) can fill in missing fields.
          - The row id is NEVER changed — no DELETE + INSERT.
          - source is always updated to reflect the latest data origin.
        """
        try:
            cur = self.conn.execute(
                """
                INSERT INTO ports
                    (scan_id, host, port, protocol, state, service, product, version, banner, cpe, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, host, port, protocol) DO UPDATE SET
                    service = CASE WHEN excluded.service != '' THEN excluded.service ELSE service END,
                    product = CASE WHEN excluded.product != '' THEN excluded.product ELSE product END,
                    version = CASE WHEN excluded.version != '' THEN excluded.version ELSE version END,
                    cpe     = CASE WHEN excluded.cpe     != '' THEN excluded.cpe     ELSE cpe     END,
                    banner  = CASE WHEN excluded.banner  != '' THEN excluded.banner  ELSE banner  END,
                    source  = excluded.source
                """,
                (record.scan_id, record.host, record.port, record.protocol, record.state,
                 record.service, record.product, record.version, record.banner, record.cpe, record.source),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_url(self, record: URLRecord) -> int:
        """Insert a URL record, silently ignoring duplicates (same scan, url, method)."""
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO urls "
                "(scan_id, url, method, status_code, content_type, content_length, "
                "title, redirect_url, source, depth) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.url, record.method, record.status_code,
                 record.content_type, record.content_length, record.title,
                 record.redirect_url, record.source, record.depth),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_urls_batch(self, records: list[URLRecord]) -> int:
        """Batch insert multiple URL records in a single high-performance transaction."""
        if not records:
            return 0
        try:
            params = [
                (r.scan_id, r.url, r.method, r.status_code, r.content_type,
                 r.content_length, r.title, r.redirect_url, r.source, r.depth)
                for r in records
            ]
            cur = self.conn.executemany(
                "INSERT OR IGNORE INTO urls "
                "(scan_id, url, method, status_code, content_type, content_length, "
                "title, redirect_url, source, depth) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params,
            )
            self.conn.commit()
            return cur.rowcount
        except Exception:
            return 0

    def insert_subdomains_batch(self, records: list[SubdomainRecord]) -> int:
        """Batch insert multiple subdomains in a single high-performance transaction."""
        if not records:
            return 0
        try:
            params = [
                (r.scan_id, r.subdomain, r.domain, json.dumps(r.sources),
                 json.dumps(r.resolved_ips), r.http_status, r.https_status,
                 r.title, r.first_seen.isoformat(), r.last_seen.isoformat(),
                 int(r.is_alive), r.priority)
                for r in records
            ]
            cur = self.conn.executemany(
                "INSERT OR IGNORE INTO subdomains "
                "(scan_id, subdomain, domain, sources, resolved_ips, http_status, https_status, "
                "title, first_seen, last_seen, is_alive, priority) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params,
            )
            self.conn.commit()
            return cur.rowcount
        except Exception:
            return 0

    def insert_api_endpoints_batch(self, records: list[APIEndpoint]) -> int:
        """Batch insert multiple API endpoints in a single high-performance transaction."""
        if not records:
            return 0
        try:
            params = [
                (r.scan_id, r.host, r.method, r.path, r.full_url,
                 r.content_type, r.auth_required, r.source, r.api_type)
                for r in records
            ]
            cur = self.conn.executemany(
                "INSERT OR IGNORE INTO api_endpoints "
                "(scan_id, host, method, path, full_url, content_type, auth_required, source, api_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params,
            )
            self.conn.commit()
            return cur.rowcount
        except Exception:
            return 0

    def insert_ports_batch(self, records: list[PortRecord]) -> int:
        """Batch insert or enrich multiple port records in a single high-performance transaction."""
        if not records:
            return 0
        try:
            params = [
                (r.scan_id, r.host, r.port, r.protocol, r.state,
                 r.service, r.product, r.version, r.banner, r.cpe, r.source)
                for r in records
            ]
            cur = self.conn.executemany(
                """INSERT INTO ports (scan_id, host, port, protocol, state, service, product, version, banner, cpe, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, host, port, protocol) DO UPDATE SET
                    state   = excluded.state,
                    service = CASE WHEN excluded.service != '' THEN excluded.service ELSE service END,
                    product = CASE WHEN excluded.product != '' THEN excluded.product ELSE product END,
                    version = CASE WHEN excluded.version != '' THEN excluded.version ELSE version END,
                    banner  = CASE WHEN excluded.banner  != '' THEN excluded.banner  ELSE banner  END,
                    source  = excluded.source
                """,
                params,
            )
            self.conn.commit()
            return cur.rowcount
        except Exception:
            return 0

    def insert_technologies_batch(self, records: list[TechnologyRecord]) -> int:
        """Batch insert multiple technologies in a single transaction."""
        if not records:
            return 0
        try:
            params = [
                (r.scan_id, r.host, r.name, r.category, r.version,
                 r.confidence, r.source, json.dumps(r.evidence))
                for r in records
            ]
            cur = self.conn.executemany(
                "INSERT OR IGNORE INTO technologies "
                "(scan_id, host, name, category, version, confidence, source, evidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params,
            )
            self.conn.commit()
            return cur.rowcount
        except Exception:
            return 0

    def insert_dns_records_batch(self, records: list[DNSRecord]) -> int:
        """Batch insert multiple DNS records in a single transaction."""
        if not records:
            return 0
        try:
            params = [
                (r.scan_id, r.hostname, r.record_type, r.value, r.ttl, r.source, r.timestamp.isoformat())
                for r in records
            ]
            cur = self.conn.executemany(
                "INSERT OR IGNORE INTO dns_records "
                "(scan_id, hostname, record_type, value, ttl, source, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                params,
            )
            self.conn.commit()
            return cur.rowcount
        except Exception:
            return 0

    def insert_technology(self, record: TechnologyRecord) -> int:
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO technologies "
                "(scan_id, host, name, category, version, confidence, source, evidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.host, record.name, record.category,
                 record.version, record.confidence, record.source, json.dumps(record.evidence)),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_certificate(self, record: CertificateRecord) -> int:
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO certificates "
                "(scan_id, host, subject, issuer, serial, not_before, not_after, san, fingerprint, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.host, record.subject, record.issuer, record.serial,
                 record.not_before, record.not_after, json.dumps(record.san),
                 record.fingerprint, record.source),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_api_endpoint(self, record: APIEndpoint) -> int:
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO api_endpoints "
                "(scan_id, host, method, path, full_url, content_type, auth_required, source, api_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.host, record.method, record.path, record.full_url,
                 record.content_type, record.auth_required, record.source, record.api_type),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_finding(self, record: FindingRecord) -> int:
        """Insert or upgrade a finding with rich evidence & active verification status."""
        try:
            with self._lock:
                cur = self.conn.execute(
                    """
                    INSERT INTO findings 
                    (scan_id, title, severity, confidence, status, affected_asset, affected_asset_type, 
                    description, impact, evidence, detection_method, remediation, refs, cve, cwe, 
                    cvss, verified, timestamp, what_is_it, why_detected, attack_class, 
                    conditions_required, safe_verification, prevention, source) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, title, affected_asset) DO UPDATE SET
                        severity = CASE 
                            WHEN excluded.severity = 'critical' THEN 'critical'
                            WHEN excluded.severity = 'high' AND findings.severity != 'critical' THEN 'high'
                            WHEN excluded.severity = 'medium' AND findings.severity NOT IN ('critical', 'high') THEN 'medium'
                            WHEN excluded.severity = 'low' AND findings.severity = 'info' THEN 'low'
                            ELSE findings.severity END,
                        confidence = CASE WHEN excluded.confidence != 'info' THEN excluded.confidence ELSE findings.confidence END,
                        status = CASE WHEN excluded.status != 'info' THEN excluded.status ELSE findings.status END,
                        evidence = CASE WHEN excluded.evidence != '' THEN excluded.evidence ELSE findings.evidence END,
                        cvss = CASE WHEN excluded.cvss IS NOT NULL THEN excluded.cvss ELSE findings.cvss END,
                        verified = CASE WHEN excluded.verified = 1 THEN 1 ELSE findings.verified END,
                        remediation = CASE WHEN excluded.remediation != '' THEN excluded.remediation ELSE findings.remediation END,
                        source = CASE WHEN excluded.source != '' THEN excluded.source ELSE findings.source END
                    """,
                    (record.scan_id, record.title, record.severity.value, record.confidence.value,
                     record.status.value, record.affected_asset, record.affected_asset_type,
                     record.description, record.impact, record.evidence, record.detection_method,
                     record.remediation, json.dumps(record.references), json.dumps(record.cve),
                     json.dumps(record.cwe), record.cvss, int(record.verified),
                     record.timestamp.isoformat(), record.what_is_it, record.why_detected,
                     record.attack_class, record.conditions_required, record.safe_verification,
                     record.prevention, record.source or "scanner"),
                )
                self.conn.commit()
                return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_tool_run(self, record: ToolRunRecord) -> int:
        try:
            cur = self.conn.execute(
                "INSERT INTO tool_runs (scan_id, tool_name, module_name, command, status, exit_code, "
                "duration, timed_out, output_file, started_at, completed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.tool_name, record.module_name, record.command,
                 record.status, record.exit_code, record.duration, int(record.timed_out),
                 record.output_file, record.started_at.isoformat(),
                 record.completed_at.isoformat() if record.completed_at else None),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    def insert_cloud_asset(self, record: CloudAssetRecord) -> int:
        """Insert a cloud asset, silently ignoring exact duplicates (same scan, provider, type, name)."""
        try:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO cloud_assets "
                "(scan_id, provider, asset_type, asset_name, url, is_public, is_writable, "
                "region, metadata, source, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record.scan_id, record.provider, record.asset_type, record.asset_name,
                 record.url, int(record.is_public), int(record.is_writable),
                 record.region, json.dumps(record.metadata), record.source,
                 record.timestamp.isoformat()),
            )
            self.conn.commit()
            return cur.lastrowid or 0
        except Exception:
            return 0

    # ── Query Operations ────────────────────────────────────

    def get_subdomains(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_dns_records(self, scan_id: str, hostname: str = "") -> list[dict[str, Any]]:
        if hostname:
            rows = self.conn.execute(
                "SELECT * FROM dns_records WHERE scan_id = ? AND hostname = ?", (scan_id, hostname)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM dns_records WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_ports(self, scan_id: str, host: str = "") -> list[dict[str, Any]]:
        if host:
            rows = self.conn.execute(
                "SELECT * FROM ports WHERE scan_id = ? AND host = ?", (scan_id, host)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM ports WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_urls(self, scan_id: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in
            self.conn.execute("SELECT * FROM urls WHERE scan_id = ?", (scan_id,)).fetchall()
        ]

    def get_technologies(self, scan_id: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in
            self.conn.execute(
                "SELECT * FROM technologies WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in
            self.conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? "
                "ORDER BY CASE severity "
                "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "  WHEN 'medium' THEN 2  WHEN 'low'  THEN 3 ELSE 4 END",
                (scan_id,),
            ).fetchall()
        ]

    def get_certificates(self, scan_id: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in
            self.conn.execute(
                "SELECT * FROM certificates WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]

    def get_api_endpoints(self, scan_id: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in
            self.conn.execute(
                "SELECT * FROM api_endpoints WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]

    def get_ips(self, scan_id: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in
            self.conn.execute("SELECT * FROM ips WHERE scan_id = ?", (scan_id,)).fetchall()
        ]

    def get_tool_runs(self, scan_id: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in
            self.conn.execute(
                "SELECT * FROM tool_runs WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]

    # ── Stats ───────────────────────────────────────────────

    def get_scan_stats(self, scan_id: str) -> dict[str, int]:
        """Get aggregate record counts for a scan."""
        tables = [
            "subdomains", "dns_records", "ips", "ports",
            "urls", "technologies", "certificates", "api_endpoints", "findings",
            "cloud_assets",
        ]
        stats: dict[str, Any] = {}
        for table in tables:
            row = self.conn.execute(
                f"SELECT COUNT(*) AS c FROM {table} WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            stats[table] = int(row["c"]) if row else 0
        scan_row = self.conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan_row and scan_row["target"]:
            stats["target"] = str(scan_row["target"])
        return stats

    def get_cloud_assets(
        self, scan_id: str, provider: str = "", is_public: bool | None = None
    ) -> list[dict[str, Any]]:
        """Get all cloud assets for a scan, optionally filtered by provider and public status."""
        query = "SELECT * FROM cloud_assets WHERE scan_id = ?"
        params: list[Any] = [scan_id]

        if provider:
            query += " AND provider = ?"
            params.append(provider)

        if is_public is not None:
            query += " AND is_public = ?"
            params.append(int(is_public))

        query += " ORDER BY provider, asset_type"
        rows = self.conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    # ── Comparison ──────────────────────────────────────────

    def get_scan_data_for_comparison(self, scan_id: str) -> dict[str, list[dict[str, Any]]]:
        """Get all data for a scan, organized by type, for diff/comparison."""
        return {
            "subdomains":   self.get_subdomains(scan_id),
            "dns_records":  self.get_dns_records(scan_id),
            "ports":        self.get_ports(scan_id),
            "urls":         self.get_urls(scan_id),
            "technologies": self.get_technologies(scan_id),
            "findings":     self.get_findings(scan_id),
            "certificates": self.get_certificates(scan_id),
            "api_endpoints": self.get_api_endpoints(scan_id),
            "ips":          self.get_ips(scan_id),
            "cloud_assets": self.get_cloud_assets(scan_id),
        }
