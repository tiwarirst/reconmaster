"""Configuration manager — loads, merges, and provides config to all components.

Supports: default values → YAML files → environment variables → CLI overrides.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from reconai.core.config.schema import ReconAIConfig


class ConfigManager:
    """Centralized configuration manager.

    Load order (later overrides earlier):
      1. Built-in defaults (from schema)
      2. config/default.yaml
      3. User-specified config file
      4. Environment variables (RECONAI_*)
      5. CLI overrides
    """

    def __init__(self, config_path: Path | None = None):
        self._config_path = config_path
        self._raw: dict[str, Any] = {}
        self._config: ReconAIConfig | None = None

    @property
    def config(self) -> ReconAIConfig:
        if self._config is None:
            self._config = self._load()
        return self._config

    def _load(self) -> ReconAIConfig:
        """Load configuration from all sources."""
        merged: dict[str, Any] = {}

        # 1. Load default config file
        default_path = self._find_default_config()
        if default_path and default_path.exists():
            merged = self._merge(merged, self._load_yaml(default_path))

        # 2. Load user-specified config file
        if self._config_path and self._config_path.exists():
            merged = self._merge(merged, self._load_yaml(self._config_path))

        # 3. Apply environment variable overrides
        merged = self._merge(merged, self._load_env())

        self._raw = merged
        return ReconAIConfig.from_dict(merged)

    def reload(self) -> ReconAIConfig:
        """Force reload configuration from all sources."""
        self._config = None
        return self.config

    def override(self, **kwargs: Any) -> None:
        """Apply runtime overrides (e.g., from CLI flags)."""
        cfg = self.config
        for key, value in kwargs.items():
            if value is not None and hasattr(cfg, key):
                setattr(cfg, key, value)

    def get_timeout(self, key: str) -> int:
        return self.config.timeouts.get(key)

    def get_concurrency(self, key: str) -> int:
        return self.config.concurrency.get(key)

    def _find_default_config(self) -> Path | None:
        """Look for default config in standard locations."""
        repo_root_config = Path(__file__).resolve().parents[3] / "config.yaml"
        candidates = [
            Path("config.yaml"),
            repo_root_config,
            Path("config/default.yaml"),
            Path("~/.config/reconai/config.yaml").expanduser(),
            Path("/etc/reconai/config.yaml"),
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        """Load a YAML file safely."""
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _load_env() -> dict[str, Any]:
        """Load config from RECONAI_* environment variables."""
        result: dict[str, Any] = {}
        prefix = "RECONAI_"
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                # Support nested keys via double underscore: RECONAI_TIMEOUTS__DNS_QUERY=15
                parts = config_key.split("__")
                if len(parts) == 2:
                    section, setting = parts
                    if section not in result:
                        result[section] = {}
                    result[section][setting] = _auto_type(value)
                else:
                    result[config_key] = _auto_type(value)
        return result

    @staticmethod
    def _merge(base: dict, override: dict) -> dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._merge(result[key], value)
            else:
                result[key] = value
        return result

    def to_dict(self) -> dict[str, Any]:
        """Export current config as a dictionary."""
        return self.config.model_dump()


def _auto_type(value: str) -> int | float | bool | str:
    """Convert string env var values to appropriate Python types."""
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value
