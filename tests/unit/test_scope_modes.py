"""Unit tests for Permissive AI Intelligence mode vs Strict Enforced Scope mode."""
from __future__ import annotations

from unittest.mock import MagicMock
from reconai.core.scope.manager import ScopeManager
from reconai.modules.base import ReconModule, ModuleConfig


def test_scope_manager_permissive_mode_allows_broad_intelligence():
    # Permissive mode (default for scans to collect huge data for AI)
    scope = ScopeManager.for_target("target.com", strict=False)
    assert not scope.strict

    # Target itself is allowed
    assert scope.is_in_scope("target.com")
    assert scope.is_in_scope("api.target.com")

    # Connected third-parties, SaaS, and cloud endpoints are also allowed for AI correlation
    assert scope.is_in_scope("auth.sso-provider.net")
    assert scope.is_in_scope("s3.eu-west-1.amazonaws.com")
    assert scope.is_in_scope("192.168.1.50")

    allowed, reason = scope.check_scope("cloud.external-service.io")
    assert allowed
    assert "Permissive AI Intelligence Mode" in reason


def test_scope_manager_strict_mode_enforces_boundaries():
    # Strict mode (enforced when user specifies --strict-scope or a scope YAML file)
    scope = ScopeManager.for_target("target.com", strict=True)
    assert scope.strict

    # In-scope
    assert scope.is_in_scope("target.com")
    assert scope.is_in_scope("api.target.com")

    # Out-of-scope blocked
    assert not scope.is_in_scope("evil.com")
    assert not scope.is_in_scope("other-company.com")


def test_recon_module_respects_permissive_and_strict_modes():
    class TestModule(ReconModule):
        config = ModuleConfig(name="test_mod", category="test", description="test")
        async def run(self, **kwargs):
            pass

    mod = TestModule(
        db=MagicMock(),
        events=MagicMock(),
        logger=MagicMock(),
        runner=MagicMock(),
    )

    # 1. Permissive scope attached
    mod.scope = ScopeManager.for_target("mycorp.com", strict=False)
    assert mod.is_in_scope("auth0.com")  # Allowed for AI synthesis & SaaS discovery

    # 2. Strict scope attached
    mod.scope = ScopeManager.for_target("mycorp.com", strict=True)
    assert mod.is_in_scope("dev.mycorp.com")
    assert not mod.is_in_scope("auth0.com")  # Filtered out in strict mode
