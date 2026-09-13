"""Scope data models — defines what's in and out of scope."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ScopeDefinition(BaseModel):
    """Defines the authorized scanning scope.

    Every active module MUST check scope before executing.
    This ensures we never accidentally scan unauthorized targets.
    """

    # Allowed targets
    domains: list[str] = Field(default_factory=list, description="Allowed domains (supports *.domain.com wildcards)")
    ips: list[str] = Field(default_factory=list, description="Allowed IP addresses or CIDR ranges")
    ports: list[int] = Field(default_factory=list, description="Allowed ports (empty = all ports allowed)")

    # Excluded targets
    excluded_domains: list[str] = Field(default_factory=list, description="Explicitly excluded domains")
    excluded_ips: list[str] = Field(default_factory=list, description="Explicitly excluded IPs or CIDR ranges")
    excluded_ports: list[int] = Field(default_factory=list, description="Excluded ports")

    # Operational limits
    rate_limit: int = Field(default=10, description="Max requests per second")
    max_concurrency: int = Field(default=20, description="Max concurrent operations")

    @field_validator("domains", "excluded_domains", mode="before")
    @classmethod
    def normalize_domains(cls, v: list[str]) -> list[str]:
        """Lowercase and strip domains."""
        return [d.lower().strip() for d in v if d.strip()]

    @field_validator("ports", "excluded_ports", mode="before")
    @classmethod
    def validate_ports(cls, v: list[int]) -> list[int]:
        """Ensure ports are in valid range."""
        return [p for p in v if 1 <= p <= 65535]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_yaml(cls, data: dict[str, Any]) -> ScopeDefinition:
        """Create scope from YAML configuration data."""
        scope_data = data.get("scope", data)
        return cls(**scope_data)

    @classmethod
    def for_target(cls, target: str) -> ScopeDefinition:
        """Create a minimal scope for a single target."""
        # Determine if target is an IP or domain
        try:
            ipaddress.ip_address(target)
            return cls(ips=[target])
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target, strict=False)
            return cls(ips=[target])
        except ValueError:
            pass

        # It's a domain
        return cls(domains=[target, f"*.{target}"])
