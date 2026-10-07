"""Structured result from command execution.

Every external command produces a CommandResult — never raw strings.
This ensures consistent handling of success, failure, timeout, and partial results.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class CommandStatus(str, Enum):
    """Status of a command execution."""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    NOT_FOUND = "not_found"
    PERMISSION_ERROR = "permission_error"
    ERROR = "error"


class CommandResult(BaseModel):
    """Structured result from running an external command.

    Contains everything needed for debugging, auditing, and processing:
    - The command that was run
    - stdout/stderr
    - Exit code
    - Duration
    - Status (success/fail/timeout)
    - Output file path
    """
    command: list[str] = Field(description="The command and arguments that were executed")
    status: CommandStatus = Field(description="Execution status")
    exit_code: int | None = Field(default=None, description="Process exit code")
    stdout: str = Field(default="", description="Standard output")
    stderr: str = Field(default="", description="Standard error")
    duration: float = Field(default=0.0, description="Execution duration in seconds")
    timed_out: bool = Field(default=False, description="Whether the command timed out")
    timeout: int | None = Field(default=None, description="Timeout value that was set")
    output_file: Path | None = Field(default=None, description="Path to saved output file")
    pid: int | None = Field(default=None, description="Process ID")
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: datetime | None = Field(default=None)
    error_message: str = Field(default="", description="Human-readable error message")

    model_config = {"arbitrary_types_allowed": True}

    @property
    def succeeded(self) -> bool:
        return self.status == CommandStatus.SUCCESS

    @property
    def success(self) -> bool:
        return self.succeeded

    @property
    def failed(self) -> bool:
        return self.status in (CommandStatus.FAILED, CommandStatus.ERROR)

    @property
    def has_output(self) -> bool:
        return bool(self.stdout.strip())

    @property
    def output_lines(self) -> list[str]:
        return self.stdout.strip().splitlines() if self.stdout else []

    @property
    def command_str(self) -> str:
        return " ".join(self.command)

    def summary(self) -> dict[str, Any]:
        """Return a summary for logging/reporting."""
        return {
            "command": self.command_str,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration": f"{self.duration:.1f}s",
            "timed_out": self.timed_out,
            "output_lines": len(self.output_lines),
            "error": self.error_message or None,
        }
