"""Scope Manager — loads, manages, and enforces scanning scope.

Central authority for what is and isn't allowed.
Every active module must call scope_manager.is_allowed(target) before executing.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from reconai.core.scope.models import ScopeDefinition
from reconai.core.scope.validator import ScopeValidator


class ScopeManager:
    """Manages and enforces authorized scanning scope.

    Usage:
        scope_mgr = ScopeManager.for_target("example.com")
        if scope_mgr.is_allowed("sub.example.com"):
            # proceed with scanning
    """

    def __init__(self, scope: ScopeDefinition):
        self._scope = scope
        self._validator = ScopeValidator(scope)
        self._checked: dict[str, bool] = {}

    @classmethod
    def for_target(cls, target: str) -> ScopeManager:
        """Create a scope manager for a single target."""
        scope = ScopeDefinition.for_target(target)
        return cls(scope)

    @classmethod
    def from_yaml(cls, path: Path) -> ScopeManager:
        """Load scope from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        scope = ScopeDefinition.from_yaml(data)
        return cls(scope)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScopeManager:
        """Create scope from a dictionary."""
        scope = ScopeDefinition.from_yaml(data)
        return cls(scope)

    def is_allowed(self, target: str) -> bool:
        """Check if a target is within scope (cached)."""
        if target in self._checked:
            return self._checked[target]

        result = self._validator.is_target_allowed(target)
        self._checked[target] = result
        return result

    def is_in_scope(self, target: str) -> bool:
        """Alias for is_allowed() — preferred public API."""
        return self.is_allowed(target)

    def is_domain_allowed(self, domain: str) -> bool:
        return self._validator.is_domain_allowed(domain)

    def is_ip_allowed(self, ip: str) -> bool:
        return self._validator.is_ip_allowed(ip)

    def is_port_allowed(self, port: int) -> bool:
        return self._validator.is_port_allowed(port)

    def is_url_allowed(self, url: str) -> bool:
        return self._validator.is_url_allowed(url)

    def check_scope(self, target: str) -> tuple[bool, str]:
        """Check scope and return (allowed, reason)."""
        allowed = self.is_allowed(target)
        if allowed:
            return True, f"Target '{target}' is within scope"
        return False, f"Target '{target}' is OUT OF SCOPE — operation blocked"

    @property
    def scope(self) -> ScopeDefinition:
        return self._scope

    def save(self, path: Path) -> None:
        """Save current scope to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._scope.to_dict(), f, indent=2)

    def summary(self) -> dict[str, Any]:
        """Return a summary of the current scope."""
        return {
            "domains": self._scope.domains,
            "ips": self._scope.ips,
            "ports": self._scope.ports or "all",
            "excluded_domains": self._scope.excluded_domains,
            "excluded_ips": self._scope.excluded_ips,
            "rate_limit": self._scope.rate_limit,
        }
