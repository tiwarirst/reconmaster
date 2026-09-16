"""Gowitness adapter — takes screenshots of discovered web pages."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from reconai.core.executor.command_runner import CommandRunner
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class GowitnessAdapter(ToolAdapter):
    """Adapter for sensepost/gowitness screenshot tool."""

    name: str = "gowitness"

    def __init__(self, runner: CommandRunner) -> None:
        super().__init__(runner)

    @property
    def tool_name(self) -> str:
        return self.name

    async def is_available(self) -> bool:
        """Check if gowitness is installed."""
        available, _ = await self.runner.check_tool("gowitness")
        return available

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build the gowitness command.

        Requires:
            urls_file (str): Path to file containing URLs
            out_dir (Path): Output directory for screenshots
            timeout (int): Timeout in seconds
        """
        urls_file = kwargs.get("urls_file")
        out_dir = kwargs.get("out_dir")
        timeout = kwargs.get("timeout", 15)

        if not urls_file or not out_dir:
            raise ValueError("urls_file and out_dir are required for gowitness")

        screenshot_dir = Path(out_dir) / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        return [
            "gowitness", "file",
            "-f", str(urls_file),
            "--screenshot-path", str(screenshot_dir),
            "--timeout", str(timeout),
            "--disable-logging",
        ]

    def parse(self, result: CommandResult) -> list[Any]:
        """Gowitness saves images to disk; no stdout to parse.

        We return an empty list and let the filesystem hold the screenshots.
        """
        return []
