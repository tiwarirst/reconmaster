"""Base interface for external tool adapters.

Adapters translate Tool output (stdout/XML/JSON) into ReconAI Database Models.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from reconai.core.executor.command_runner import CommandRunner
from reconai.core.executor.result import CommandResult


class ToolAdapter(ABC):
    """Base class for parsing output from external tools like Nmap, Amass, etc."""

    name: str

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the tool is installed."""
        pass

    @abstractmethod
    def build_command(self, **kwargs: Any) -> list[str]:
        """Build the command line array."""
        pass

    @abstractmethod
    def parse(self, result: CommandResult) -> list[Any]:
        """Parse the raw command output into structured data."""
        pass
