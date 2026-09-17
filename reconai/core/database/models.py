"""Database models — Pydantic models for all stored entities."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    VERIFIED = "verified"
    LIKELY = "likely"
    POTENTIAL = "potential"
    INFO = "info"


class FindingStatus(str, Enum):
    INFO = "info"
    POTENTIAL = "potential"
    LIKELY = "likely"
    VERIFIED = "verified"


class ScanRecord(BaseModel):
    id: str = ""
    target: str = ""
    mode: str = "standard"
    profile: str = "quick"
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: datetime | None = None
    duration: float = 0.0
    modules_total: int = 0
    modules_completed: int = 0
    modules_failed: int = 0
    output_dir: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DomainRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    domain: str = ""
    is_primary: bool = False
    discovered_by: str = ""
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)


class SubdomainRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    subdomain: str = ""
    domain: str = ""
    sources: list[str] = Field(default_factory=list)
    resolved_ips: list[str] = Field(default_factory=list)
    http_status: int | None = None
    https_status: int | None = None
    title: str = ""
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    is_alive: bool = False
    priority: str = "normal"


class IPRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    ip: str = ""
    version: int = 4
    hostnames: list[str] = Field(default_factory=list)
    asn: str = ""
    asn_org: str = ""
    country: str = ""
    is_private: bool = False
    source: str = ""


class DNSRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    hostname: str = ""
    record_type: str = ""
    value: str = ""
    ttl: int = 0
    source: str = "dns"
    timestamp: datetime = Field(default_factory=datetime.now)


class PortRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""
    source: str = "nmap"


class ServiceRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    os_type: str = ""
    source: str = ""


class URLRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    url: str = ""
    method: str = "GET"
    status_code: int | None = None
    content_type: str = ""
    content_length: int | None = None
    title: str = ""
    redirect_url: str = ""
    source: str = ""
    depth: int = 0


class TechnologyRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    host: str = ""
    name: str = ""
    category: str = ""
    version: str = ""
    confidence: float = 0.0
    source: str = ""
    evidence: list[str] = Field(default_factory=list)


class CertificateRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    host: str = ""
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = Field(default_factory=list)
    fingerprint: str = ""
    source: str = ""


class APIEndpoint(BaseModel):
    id: int = 0
    scan_id: str = ""
    host: str = ""
    method: str = ""
    path: str = ""
    full_url: str = ""
    content_type: str = ""
    auth_required: bool | None = None
    source: str = ""
    api_type: str = ""  # REST, GraphQL, WebSocket, etc.


class FindingRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    title: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.INFO
    status: FindingStatus = FindingStatus.INFO
    affected_asset: str = ""
    affected_asset_type: str = ""
    description: str = ""
    impact: str = ""
    evidence: str = ""
    detection_method: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cvss: float | None = None
    verified: bool = False
    timestamp: datetime = Field(default_factory=datetime.now)

    # Explanation fields
    what_is_it: str = ""
    why_detected: str = ""
    attack_class: str = ""
    conditions_required: str = ""
    safe_verification: str = ""
    prevention: str = ""


class ToolRunRecord(BaseModel):
    id: int = 0
    scan_id: str = ""
    tool_name: str = ""
    module_name: str = ""
    command: str = ""
    status: str = ""
    exit_code: int | None = None
    duration: float = 0.0
    timed_out: bool = False
    output_file: str = ""
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: datetime | None = None


class CloudAssetRecord(BaseModel):
    """A discovered cloud resource (bucket, CDN, hosted service, etc.)."""
    id: int = 0
    scan_id: str = ""
    provider: str = ""           # aws, gcp, azure, cloudflare, heroku, vercel, netlify
    asset_type: str = ""         # s3_bucket, gcs_bucket, blob_container, cloudfront, app_service, etc.
    asset_name: str = ""         # actual resource name / identifier
    url: str = ""                # full URL if applicable
    is_public: bool = False      # publicly accessible?
    is_writable: bool = False    # publicly writable? (critical misconfiguration)
    region: str = ""             # cloud region (us-east-1, eu-west-1, etc.)
    metadata: dict[str, Any] = Field(default_factory=dict)  # extra provider-specific data
    source: str = ""             # which module discovered this asset
    timestamp: datetime = Field(default_factory=datetime.now)
