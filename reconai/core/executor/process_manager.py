"""Process manager — handles process lifecycle, cleanup, and zombie prevention."""
from __future__ import annotations

import asyncio
import os
import signal
from typing import Any


class ProcessManager:
    """Manages subprocess lifecycle — creation, monitoring, and cleanup.

    Responsibilities:
    - Track running processes
    - Kill process trees on timeout/cancellation
    - Prevent zombie processes
    - Handle SIGTERM/SIGKILL gracefully
    """

    def __init__(self):
        self._processes: dict[int, asyncio.subprocess.Process] = {}

    def register(self, process: asyncio.subprocess.Process) -> None:
        """Register a process for tracking."""
        if process.pid:
            self._processes[process.pid] = process

    def unregister(self, pid: int) -> None:
        """Unregister a completed process."""
        self._processes.pop(pid, None)

    async def kill_process(self, process: asyncio.subprocess.Process) -> None:
        """Kill a process and its entire process tree.

        Uses SIGTERM first, then SIGKILL if the process doesn't terminate.
        Also kills child processes to prevent orphans.
        """
        if process.returncode is not None:
            return  # Already terminated

        pid = process.pid
        if not pid:
            return

        try:
            # Try to kill the entire process group
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                # Fallback: kill just the process
                try:
                    process.terminate()
                except ProcessLookupError:
                    return

            # Wait briefly for graceful termination
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                # Force kill
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass

                try:
                    await asyncio.wait_for(process.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    pass

        except Exception:
            pass
        finally:
            self.unregister(pid)

    async def kill_all(self) -> None:
        """Kill all tracked processes."""
        for pid, process in list(self._processes.items()):
            await self.kill_process(process)
        self._processes.clear()

    @property
    def active_count(self) -> int:
        return len(self._processes)

    @property
    def active_pids(self) -> list[int]:
        return list(self._processes.keys())
