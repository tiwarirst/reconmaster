"""Gowitness adapter.

Takes screenshots of discovered web pages.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.integrations.base import ToolAdapter


class GowitnessAdapter(ToolAdapter):
    """Adapter for sensepost/gowitness screenshot tool."""

    @property
    def name(self) -> str:
        return "gowitness"

    def build_command(self, **kwargs: Any) -> list[str]:
        """
        Build the gowitness command.
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
            "--disable-logging"
        ]

    def parse(self, output: str, **kwargs: Any) -> list[dict]:
        """
        Gowitness saves images to the disk, there is no stdout to parse into DB records.
        We return empty list and let the filesystem hold the screenshots.
        """
        return []
