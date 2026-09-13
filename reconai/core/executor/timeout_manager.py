"""Timeout manager — enforces execution time limits on external commands."""
from __future__ import annotations

import asyncio
from typing import Any

from reconai.core.config.defaults import TIMEOUTS


class TimeoutManager:
    """Manages timeouts for external command execution.

    Features:
    - Configurable per-tool timeouts
    - Global timeout override
    - Timeout detection and reporting
    """

    def __init__(self, default_timeout: int = TIMEOUTS["default"]):
        self._default = default_timeout
        self._overrides: dict[str, int] = {}

    def set_override(self, tool_name: str, timeout: int) -> None:
        """Set a timeout override for a specific tool."""
        self._overrides[tool_name] = timeout

    def get_timeout(self, tool_name: str | None = None, custom: int | None = None) -> int:
        """Get the timeout for a tool.

        Priority: custom > override > tool default > global default
        """
        if custom is not None:
            return custom

        if tool_name and tool_name in self._overrides:
            return self._overrides[tool_name]

        if tool_name and tool_name in TIMEOUTS:
            return TIMEOUTS[tool_name]

        return self._default

    def set_global_override(self, timeout: int) -> None:
        """Override the default timeout for all tools."""
        self._default = timeout
