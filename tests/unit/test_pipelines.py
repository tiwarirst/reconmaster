"""Unit tests for scan modes and module pipeline registries."""
from __future__ import annotations

from reconai.core.config.defaults import SCAN_MODES
from reconai.modules.registry import ModuleRegistry

# Force import modules to populate MODULE_REGISTRY
import reconai.modules.passive.dns_enum
import reconai.modules.passive.cert_transparency
import reconai.modules.passive.whois
import reconai.modules.passive.archive
import reconai.modules.passive.paramspider
import reconai.modules.passive.dnsx
import reconai.modules.active.subdomains
import reconai.modules.active.http_probe
import reconai.modules.active.port_scan
import reconai.modules.active.naabu
import reconai.modules.web.crawler
import reconai.modules.web.directory
import reconai.modules.web.technologies
import reconai.modules.web.headers
import reconai.modules.web.javascript
import reconai.modules.web.browser
import reconai.modules.web.waf
import reconai.modules.web.ffuf
import reconai.modules.web.katana
import reconai.modules.vuln.intelligence
import reconai.modules.vuln.nuclei
import reconai.modules.vuln.secrets
import reconai.modules.vuln.sqlmap
import reconai.modules.vuln.dalfox
import reconai.modules.web.host_browser
import reconai.modules.cloud.bucket_enum
import reconai.modules.cloud.cloud_enum
import reconai.modules.cloud.metadata_ssrf
import reconai.modules.cloud.iam_analyzer
import reconai.modules.passive.email_security
import reconai.modules.passive.saas_enum
import reconai.modules.web.api_miner
import reconai.modules.web.dev_artifacts
import reconai.modules.active.cdn_classifier
import reconai.modules.web.screenshot


def test_dedicated_pipelines_exist():
    expected_modes = ["subs", "ports", "web", "vuln", "cloud", "passive", "light", "standard", "deep"]
    for mode in expected_modes:
        assert mode in SCAN_MODES, f"Missing scan mode: {mode}"
        assert len(SCAN_MODES[mode]["modules"]) > 0, f"Mode {mode} has no modules"


def test_all_pipeline_modules_are_registered():
    """Ensure every module name listed in SCAN_MODES is actually registered in ModuleRegistry."""
    registered_names = set(ModuleRegistry.get_all().keys())
    for mode_name, mode_def in SCAN_MODES.items():
        for mod in mode_def["modules"]:
            assert mod in registered_names, f"Module '{mod}' in mode '{mode_name}' is not in ModuleRegistry!"


def test_modules_have_no_blocking_requirements():
    """Verify that scanning modules do not block execution with hard external tool requirements."""
    registered = ModuleRegistry.get_all()
    for name, mod_cls in registered.items():
        assert mod_cls.config.requires_tools == [], (
            f"Module '{name}' still requires tools {mod_cls.config.requires_tools}; "
            f"should be [] with internal pure-Python fallback to prevent 0.0s skipping."
        )


def test_tool_install_guides_coverage():
    """Verify TOOL_INSTALL_GUIDES provides actionable setup commands for tools."""
    from reconai.core.orchestrator import TOOL_INSTALL_GUIDES
    key_tools = ["nmap", "nuclei", "subfinder", "katana", "naabu", "dnsx", "dalfox", "sqlmap", "ffuf", "trufflehog", "gowitness"]
    for tool in key_tools:
        assert tool in TOOL_INSTALL_GUIDES
        assert len(TOOL_INSTALL_GUIDES[tool]) > 5
