"""CommandRunner — the heart of the execution engine.

Runs external commands safely with:
- Argument validation (no shell injection)
- Real-time output streaming
- Configurable timeouts
- Process tree cleanup
- Structured results
- Binary existence checking
- Output file saving
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from reconai.core.executor.process_manager import ProcessManager
from reconai.core.executor.result import CommandResult, CommandStatus
from reconai.core.executor.stream_handler import StreamHandler
from reconai.core.executor.timeout_manager import TimeoutManager


# Characters that should never appear in command arguments
_DANGEROUS_CHARS = re.compile(r'[;&|`$(){}\[\]<>!\\]')


class CommandRunner:
    """Executes external commands safely and asynchronously.

    Usage:
        runner = CommandRunner(module_name="nmap")
        result = await runner.run(
            command=["nmap", "-T4", "--top-ports", "100", target],
            timeout=60,
            output_file=Path("output/nmap.txt"),
        )
    """

    def __init__(
        self,
        module_name: str = "",
        process_manager: ProcessManager | None = None,
        timeout_manager: TimeoutManager | None = None,
        on_output: Callable[[str], None] | None = None,
    ):
        self._module_name = module_name
        self._process_mgr = process_manager or ProcessManager()
        self._timeout_mgr = timeout_manager or TimeoutManager()
        self._on_output = on_output

    async def run(
        self,
        command: list[str],
        timeout: int | None = None,
        output_file: Path | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        validate_args: bool = True,
        shell: bool = False,
    ) -> CommandResult:
        """Execute an external command and return a structured result.

        Args:
            command: Command and arguments as a list (never a string).
            timeout: Timeout in seconds. None uses default.
            output_file: Optional path to save stdout.
            cwd: Working directory.
            env: Additional environment variables.
            validate_args: Whether to validate arguments for dangerous chars.
            shell: Whether to use shell=True (discouraged).

        Returns:
            CommandResult with all execution metadata.
        """
        # ── Validate ────────────────────────────────────────
        if not command:
            return self._error_result(command, "Empty command")

        if validate_args and not shell:
            for arg in command[1:]:
                if _DANGEROUS_CHARS.search(str(arg)):
                    return self._error_result(
                        command,
                        f"Dangerous character detected in argument: '{arg}'. "
                        "Use argument arrays, not shell strings.",
                    )

        # ── Check binary exists ─────────────────────────────
        binary = command[0]
        if not shutil.which(binary):
            return CommandResult(
                command=command,
                status=CommandStatus.NOT_FOUND,
                error_message=f"Binary not found: '{binary}'. Is it installed?",
                started_at=datetime.now(),
            )

        # ── Resolve timeout ─────────────────────────────────
        effective_timeout = self._timeout_mgr.get_timeout(
            self._module_name, timeout
        )

        # ── Prepare environment ─────────────────────────────
        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)

        # ── Execute ─────────────────────────────────────────
        start_time = time.monotonic()
        started_at = datetime.now()

        try:
            async with StreamHandler(
                module_name=self._module_name.upper(),
                output_file=output_file,
                on_stdout=self._on_output,
                on_stderr=self._on_output,
            ) as stream_handler:

                # Start process
                try:
                    if shell:
                        process = await asyncio.create_subprocess_shell(
                            " ".join(command),
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            cwd=str(cwd) if cwd else None,
                            env=proc_env,
                        )
                    else:
                        process = await asyncio.create_subprocess_exec(
                            *command,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            cwd=str(cwd) if cwd else None,
                            env=proc_env,
                            start_new_session=True,
                        )
                except PermissionError:
                    return CommandResult(
                        command=command,
                        status=CommandStatus.PERMISSION_ERROR,
                        error_message=f"Permission denied when executing '{binary}'",
                        started_at=started_at,
                        duration=time.monotonic() - start_time,
                    )
                except FileNotFoundError:
                    return CommandResult(
                        command=command,
                        status=CommandStatus.NOT_FOUND,
                        error_message=f"Binary not found: '{binary}'",
                        started_at=started_at,
                        duration=time.monotonic() - start_time,
                    )

                self._process_mgr.register(process)

                # Stream output with timeout
                try:
                    stdout_task = asyncio.create_task(
                        stream_handler.stream_stdout(process.stdout)
                    )
                    stderr_task = asyncio.create_task(
                        stream_handler.stream_stderr(process.stderr)
                    )

                    await asyncio.wait_for(
                        asyncio.gather(stdout_task, stderr_task, process.wait()),
                        timeout=effective_timeout,
                    )

                    stdout_data = stream_handler.stdout
                    stderr_data = stream_handler.stderr
                    duration = time.monotonic() - start_time

                    return CommandResult(
                        command=command,
                        status=CommandStatus.SUCCESS if process.returncode == 0 else CommandStatus.FAILED,
                        exit_code=process.returncode,
                        stdout=stdout_data,
                        stderr=stderr_data,
                        duration=duration,
                        timeout=effective_timeout,
                        output_file=output_file,
                        pid=process.pid,
                        started_at=started_at,
                        completed_at=datetime.now(),
                    )

                except asyncio.TimeoutError:
                    # ── Timeout handling ─────────────────────
                    duration = time.monotonic() - start_time

                    # Capture partial output before killing
                    stdout_data = stream_handler.stdout
                    stderr_data = stream_handler.stderr

                    # Kill the process tree
                    await self._process_mgr.kill_process(process)

                    if self._on_output:
                        self._on_output(
                            f"[{self._module_name.upper()}] "
                            f"⚠ Timed out after {effective_timeout}s — partial results preserved"
                        )

                    return CommandResult(
                        command=command,
                        status=CommandStatus.TIMEOUT,
                        exit_code=process.returncode,
                        stdout=stdout_data,
                        stderr=stderr_data,
                        duration=duration,
                        timed_out=True,
                        timeout=effective_timeout,
                        output_file=output_file,
                        pid=process.pid,
                        started_at=started_at,
                        completed_at=datetime.now(),
                        error_message=f"Command timed out after {effective_timeout} seconds",
                    )

                finally:
                    if process.pid:
                        self._process_mgr.unregister(process.pid)

        except asyncio.CancelledError:
            return CommandResult(
                command=command,
                status=CommandStatus.CANCELLED,
                duration=time.monotonic() - start_time,
                started_at=started_at,
                completed_at=datetime.now(),
                error_message="Command was cancelled",
            )
        except Exception as e:
            return CommandResult(
                command=command,
                status=CommandStatus.ERROR,
                duration=time.monotonic() - start_time,
                started_at=started_at,
                completed_at=datetime.now(),
                error_message=f"Unexpected error: {type(e).__name__}: {str(e)}",
            )

    async def check_tool(self, binary: str) -> tuple[bool, str]:
        """Check if a tool is available and get its version."""
        path = shutil.which(binary)
        if not path:
            return False, ""

        try:
            result = await self.run(
                command=[binary, "--version"],
                timeout=10,
                validate_args=False,
            )
            version = result.stdout.split("\n")[0].strip() if result.stdout else "unknown"
            return True, version
        except Exception:
            return True, "unknown"

    @staticmethod
    def _error_result(command: list[str], message: str) -> CommandResult:
        """Create an error result without executing anything."""
        return CommandResult(
            command=command,
            status=CommandStatus.ERROR,
            error_message=message,
            started_at=datetime.now(),
        )
