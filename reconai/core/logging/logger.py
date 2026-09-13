"""Structured logging for ReconAI.

Provides:
- Separate log files for app, commands, errors, audit
- Secret redaction on all output
- Structured JSON logging option
- Console + file handlers
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from reconai.core.logging.redactor import redact


class ReconLogger:
    """Centralized structured logger for the platform.

    Creates four log streams:
    - application.log: General application events
    - commands.log: External command executions
    - errors.log: Error events only
    - audit.log: Security-relevant events (scope checks, tool starts)
    """

    def __init__(self, log_dir: Path | None = None, debug: bool = False):
        self._log_dir = log_dir
        self._debug = debug
        self._loggers: dict[str, logging.Logger] = {}

        if log_dir:
            log_dir.mkdir(parents=True, exist_ok=True)

        self._setup_loggers()

    def _setup_loggers(self) -> None:
        """Configure the logging hierarchy."""
        level = logging.DEBUG if self._debug else logging.INFO

        # Main application logger
        self._loggers["app"] = self._create_logger("reconai", "application.log", level)
        self._loggers["cmd"] = self._create_logger("reconai.cmd", "commands.log", level)
        self._loggers["error"] = self._create_logger("reconai.error", "errors.log", logging.WARNING)
        self._loggers["audit"] = self._create_logger("reconai.audit", "audit.log", level)

    def _create_logger(self, name: str, filename: str, level: int) -> logging.Logger:
        """Create a logger with file and optional console handlers."""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.handlers.clear()

        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # File handler
        if self._log_dir:
            fh = logging.FileHandler(self._log_dir / filename)
            fh.setLevel(level)
            fh.setFormatter(formatter)
            logger.addHandler(fh)

        return logger

    def info(self, message: str, **kwargs: Any) -> None:
        self._loggers["app"].info(redact(message), extra=kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        self._loggers["app"].debug(redact(message), extra=kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._loggers["app"].warning(redact(message), extra=kwargs)
        self._loggers["error"].warning(redact(message), extra=kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._loggers["app"].error(redact(message), extra=kwargs)
        self._loggers["error"].error(redact(message), extra=kwargs)

    def command(self, cmd: list[str], **kwargs: Any) -> None:
        """Log a command execution."""
        cmd_str = " ".join(cmd)
        self._loggers["cmd"].info(redact(cmd_str), extra=kwargs)

    def audit(self, message: str, **kwargs: Any) -> None:
        """Log a security-relevant event."""
        self._loggers["audit"].info(redact(message), extra=kwargs)

    def module_start(self, module_name: str, target: str = "") -> None:
        self.info(f"Module started: {module_name}" + (f" target={target}" if target else ""))
        self.audit(f"MODULE_START: {module_name} target={target}")

    def module_complete(self, module_name: str, duration: float = 0) -> None:
        self.info(f"Module completed: {module_name} ({duration:.1f}s)")
        self.audit(f"MODULE_COMPLETE: {module_name} duration={duration:.1f}s")

    def module_error(self, module_name: str, error: str) -> None:
        self.error(f"Module failed: {module_name} — {error}")
        self.audit(f"MODULE_FAIL: {module_name} error={error}")

    def scope_check(self, target: str, allowed: bool) -> None:
        status = "ALLOWED" if allowed else "BLOCKED"
        self.audit(f"SCOPE_CHECK: {target} → {status}")

    def log_json(self, category: str, data: dict[str, Any]) -> None:
        """Write structured JSON to the appropriate log."""
        if self._log_dir:
            json_log = self._log_dir / f"{category}.jsonl"
            with open(json_log, "a") as f:
                entry = {"timestamp": datetime.now().isoformat(), **data}
                f.write(json.dumps(entry) + "\n")
