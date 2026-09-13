"""Base classes for all ReconAI modules.

Every passive and active scanning module inherits from ReconModule.
This enforces a consistent contract for execution, timeouts, and state management.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from reconai.core.database.manager import DatabaseManager
from reconai.core.events.bus import EventBus
from reconai.core.executor.command_runner import CommandRunner
from reconai.core.logging.logger import ReconLogger


class ModuleConfig(BaseModel):
    """Declarative metadata for a module."""
    name: str
    category: str  # passive, active, web, browser, etc.
    description: str
    requires_tools: list[str] = Field(default_factory=list)
    supports_timeout: bool = True
    supports_streaming: bool = True


class ReconModule(ABC):
    """Base class for all reconnaissance modules.

    Modules should be stateless where possible. The orchestrator provides
    the database, event bus, logger, and command runner via the context.
    """

    config: ModuleConfig

    def __init__(self, db: DatabaseManager, events: EventBus, logger: ReconLogger, runner: CommandRunner):
        self.db = db
        self.events = events
        self.logger = logger
        self.runner = runner
        self.scan_id = ""
        self.target = ""

    async def check_requirements(self) -> tuple[bool, str]:
        """Check if external tools or API keys required by this module are available.

        Returns (is_available, reason).
        """
        if not self.config.requires_tools:
            return True, ""

        missing = []
        for tool in self.config.requires_tools:
            available, _ = await self.runner.check_tool(tool)
            if not available:
                missing.append(tool)

        if missing:
            return False, f"Missing required tools: {', '.join(missing)}"

        return True, ""

    @abstractmethod
    async def run(self, **kwargs: Any) -> Any:
        """Execute the module's core logic.

        Must be implemented by subclasses.
        """
        pass
