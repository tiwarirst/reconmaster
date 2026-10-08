"""Unit tests for the Scope Manager."""
from __future__ import annotations

import pytest
from reconai.core.scope.manager import ScopeManager
from reconai.core.scope.models import ScopeDefinition


def test_ip_in_scope():
    scope = ScopeManager.for_target("192.168.1.0/24")
    assert scope.is_in_scope("192.168.1.1")


def test_ip_out_of_scope():
    scope = ScopeManager.for_target("192.168.1.0/24")
    assert not scope.is_in_scope("10.0.0.1")


def test_domain_in_scope():
    scope = ScopeManager.for_target("example.com")
    assert scope.is_in_scope("sub.example.com")


def test_domain_exact_match():
    scope = ScopeManager.for_target("example.com")
    assert scope.is_in_scope("example.com")


def test_domain_out_of_scope():
    scope = ScopeManager.for_target("example.com")
    assert not scope.is_in_scope("evil.com")


def test_wildcard_scope():
    scope = ScopeManager.for_target("*.example.com")
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("evil.com")


def test_recon_module_scope_integration():
    from unittest.mock import MagicMock
    from reconai.modules.base import ReconModule, ModuleConfig

    class DummyModule(ReconModule):
        config = ModuleConfig(name="dummy", category="test", description="dummy")
        async def run(self, **kwargs):
            pass

    mod = DummyModule(
        db=MagicMock(),
        events=MagicMock(),
        logger=MagicMock(),
        runner=MagicMock(),
    )
    # Without scope set -> permissive by default
    assert mod.is_in_scope("sub.example.com")

    # With scope set -> strictly enforces authorized target
    mod.scope = ScopeManager.for_target("example.com")
    assert mod.is_in_scope("sub.example.com")
    assert not mod.is_in_scope("attacker.com")
