"""Pydantic configuration schemas for ReconAI.

Provides validated, typed configuration models used throughout the platform.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from reconai.core.config.defaults import (
    CACHE,
    CONCURRENCY,
    OUTPUT,
    RATE_LIMITS,
    SCAN_LIMITS,
    TIMEOUTS,
)


class TimeoutConfig(BaseModel):
    """Timeout configuration for all external operations."""
    dns_query: int = TIMEOUTS["dns_query"]
    whois_rdap: int = TIMEOUTS["whois_rdap"]
    http_probe: int = TIMEOUTS["http_probe"]
    nmap_quick: int = TIMEOUTS["nmap_quick"]
    nmap_standard: int = TIMEOUTS["nmap_standard"]
    nmap_service: int = TIMEOUTS["nmap_service"]
    nmap_full: int = TIMEOUTS["nmap_full"]
    web_crawler: int = TIMEOUTS["web_crawler"]
    directory_discovery: int = TIMEOUTS["directory_discovery"]
    technology_detection: int = TIMEOUTS["technology_detection"]
    browser_page: int = TIMEOUTS["browser_page"]
    http_request: int = TIMEOUTS["http_request"]
    certificate_query: int = TIMEOUTS["certificate_query"]
    subdomain_tool: int = TIMEOUTS["subdomain_tool"]
    default: int = TIMEOUTS["default"]

    def get(self, key: str) -> int:
        """Get timeout by key name, falling back to default."""
        return getattr(self, key, self.default)


class ConcurrencyConfig(BaseModel):
    """Concurrency limits for parallel operations."""
    dns: int = CONCURRENCY["dns"]
    http: int = CONCURRENCY["http"]
    crawler: int = CONCURRENCY["crawler"]
    browser: int = CONCURRENCY["browser"]
    subdomain: int = CONCURRENCY["subdomain"]
    port_scan: int = CONCURRENCY["port_scan"]
    directory: int = CONCURRENCY["directory"]
    default: int = CONCURRENCY["default"]

    def get(self, key: str) -> int:
        return getattr(self, key, self.default)


class RateLimitConfig(BaseModel):
    """Rate limiting configuration (requests per second)."""
    http: int = RATE_LIMITS["http"]
    dns: int = RATE_LIMITS["dns"]
    crawler: int = RATE_LIMITS["crawler"]
    directory: int = RATE_LIMITS["directory"]
    default: int = RATE_LIMITS["default"]

    def get(self, key: str) -> int:
        return getattr(self, key, self.default)


class ScanLimitConfig(BaseModel):
    """Hard limits to prevent runaway scanning."""
    max_depth: int = SCAN_LIMITS["max_depth"]
    max_pages: int = SCAN_LIMITS["max_pages"]
    max_urls: int = SCAN_LIMITS["max_urls"]
    max_subdomains: int = SCAN_LIMITS["max_subdomains"]
    max_ports_per_host: int = SCAN_LIMITS["max_ports_per_host"]
    max_directory_depth: int = SCAN_LIMITS["max_directory_depth"]
    max_js_files: int = SCAN_LIMITS["max_js_files"]
    max_requests_per_module: int = SCAN_LIMITS["max_requests_per_module"]


class OutputConfig(BaseModel):
    """Output and storage configuration."""
    base_dir: str = OUTPUT["base_dir"]
    save_raw: bool = OUTPUT["save_raw"]
    save_normalized: bool = OUTPUT["save_normalized"]
    save_logs: bool = OUTPUT["save_logs"]
    report_formats: list[str] = Field(default_factory=lambda: OUTPUT["report_formats"])


class CacheConfig(BaseModel):
    """Caching configuration with TTL values."""
    enabled: bool = CACHE["enabled"]
    ttl_dns: int = CACHE["ttl_dns"]
    ttl_http: int = CACHE["ttl_http"]
    ttl_certificate: int = CACHE["ttl_certificate"]
    ttl_technology: int = CACHE["ttl_technology"]
    ttl_default: int = CACHE["ttl_default"]

    def get_ttl(self, key: str) -> int:
        attr = f"ttl_{key}"
        return getattr(self, attr, self.ttl_default)


class APIKeyConfig(BaseModel):
    """Optional API key configuration — none required for core functionality."""
    shodan: str = ""
    virustotal: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    securitytrails: str = ""

    def is_configured(self, service: str) -> bool:
        val = getattr(self, service, "")
        return bool(val and val.strip())


class ReconAIConfig(BaseModel):
    """Root configuration model for the entire platform."""
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    scan_limits: ScanLimitConfig = Field(default_factory=ScanLimitConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    api_keys: APIKeyConfig = Field(default_factory=APIKeyConfig)
    debug: bool = False
    verbose: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReconAIConfig:
        """Create config from a flat or nested dictionary."""
        return cls(**data)
