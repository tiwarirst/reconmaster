"""Unit tests for the command runner."""
from __future__ import annotations

import pytest
from reconai.core.executor.command_runner import CommandRunner


def test_command_runner_is_safe_allows_windows_paths():
    runner = CommandRunner()
    # Windows paths with backslashes and normal brackets or alphanumeric
    assert runner.is_safe(r"C:\Users\AppData\Local\Temp\scan.json")
    assert runner.is_safe(r"C:\Program Files (x86)\Nmap\nmap.exe")
    assert runner.is_safe("https://example.com/api/v1?page=1")
    assert runner.is_safe("-oA")
    assert runner.is_safe("output_file.txt")


def test_command_runner_is_safe_blocks_command_injection():
    runner = CommandRunner()
    # Shell operators must be blocked
    assert not runner.is_safe("foo; bar")
    assert not runner.is_safe("foo && bar")
    assert not runner.is_safe("foo || bar")
    assert not runner.is_safe("foo | bar")
    assert not runner.is_safe("`whoami`")
    assert not runner.is_safe("$(whoami)")
    assert not runner.is_safe("> /dev/null")
    assert not runner.is_safe("< input.txt")


@pytest.mark.asyncio
async def test_command_runner_runs_echo():
    runner = CommandRunner()
    result = await runner.run(["python", "-c", "print('hello recon')"])
    assert result.success
    assert "hello recon" in result.stdout
