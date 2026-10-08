"""Base classes for all ReconAI modules.

Every passive and active scanning module inherits from ReconModule.
This enforces a consistent contract for execution, timeouts, and state management.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from reconai.core.database.manager import DatabaseManager
from reconai.core.events.bus import EventBus
from reconai.core.executor.command_runner import CommandRunner
from reconai.core.logging.logger import ReconLogger


class ModuleConfig(BaseModel):
    """Declarative metadata for a module."""
    name: str
    category: str           # passive, active, web, vuln, intelligence
    description: str
    requires_tools: list[str] = Field(default_factory=list)
    supports_timeout: bool = True
    supports_streaming: bool = True


class ReconModule(ABC):
    """Base class for all reconnaissance modules.

    Modules should be stateless where possible. The orchestrator provides
    all runtime context via this base class so every module has access to:
      - self.db          → DatabaseManager
      - self.event_bus   → EventBus  (alias: self.events)
      - self.logger      → ReconLogger
      - self.runner      → CommandRunner  (alias: self.executor)
      - self.scan_id     → str
      - self.target      → str
      - self.out_dir     → Path (output directory for this scan)
      - self.timeout     → int (seconds, per-module default)
    """

    config: ModuleConfig

    def __init__(
        self,
        db: DatabaseManager,
        events: EventBus,
        logger: ReconLogger,
        runner: CommandRunner,
        out_dir: Path | None = None,
        timeout: int = 120,
    ):
        self.db = db

        # Primary names used internally
        self.event_bus: EventBus = events
        self.runner: CommandRunner = runner

        # Friendly aliases so both naming styles work
        self.events: EventBus = events
        self.executor: CommandRunner = runner

        self.logger = logger
        self.scan_id: str = ""
        self.target: str = ""
        self.out_dir: Path = out_dir or Path("output")
        self.timeout: int = timeout
        self.warnings: list[str] = []
        self.scope: Any = None

    def is_in_scope(self, candidate: str) -> bool:
        """Centralized validation against authorized scanning scope boundaries."""
        if not self.scope:
            return True
        if hasattr(self.scope, "strict") and not self.scope.strict:
            return True
        if hasattr(self.scope, "is_in_scope"):
            return bool(self.scope.is_in_scope(candidate))
        return True

    def record_warning(self, message: str) -> None:
        """Record an actionable warning or installation guidance for missing tools / errors."""
        self.warnings.append(message)
        self.logger.warning(message, module=self.config.name)

    async def emit_finding(self, record: Any) -> None:
        """Centralized helper to persist and emit a finding with automatic source attribution."""
        from reconai.core.events.types import EventType
        if hasattr(record, "source") and not record.source:
            record.source = self.config.name
        self.db.insert_finding(record)
        sev_val = getattr(getattr(record, "severity", None), "value", str(getattr(record, "severity", "")))
        await self.events.emit_discovery(
            event_type=EventType.FINDING_DISCOVERED,
            source=self.config.name,
            data={
                "title": getattr(record, "title", ""),
                "severity": sev_val,
                "asset": getattr(record, "affected_asset", ""),
            },
            scan_id=self.scan_id,
            target=self.target,
        )

    async def check_requirements(self) -> tuple[bool, str]:
        """Check if external tools required by this module are available.

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
