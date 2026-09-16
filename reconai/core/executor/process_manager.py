"""Process manager — handles process lifecycle, cleanup, and zombie prevention."""
from __future__ import annotations

import asyncio
import os
import signal
import sys


class ProcessManager:
    """Manages subprocess lifecycle — creation, monitoring, and cleanup.

    Responsibilities:
    - Track running processes
    - Kill process trees on timeout/cancellation
    - Prevent zombie processes
    - Handle SIGTERM/SIGKILL gracefully

    Platform notes:
    - On Linux/macOS: uses POSIX process groups (os.killpg/os.getpgid) to kill
      entire process trees atomically, preventing zombie/orphan processes.
    - On Windows: falls back to process.terminate() / process.kill() since
      POSIX process group APIs do not exist on win32.
    """

    def __init__(self) -> None:
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

        Sends SIGTERM first, waits 5 s, then escalates to SIGKILL if needed.
        """
        if process.returncode is not None:
            return  # Already terminated

        pid = process.pid
        if not pid:
            return

        try:
            if sys.platform != "win32":
                # ── POSIX (Linux / macOS): kill the whole process group ──────
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)  # type: ignore[attr-defined]
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        return

                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGKILL)  # type: ignore[attr-defined]
                    except (ProcessLookupError, PermissionError, OSError):
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                    try:
                        await asyncio.wait_for(process.wait(), timeout=3.0)
                    except asyncio.TimeoutError:
                        pass

            else:
                # ── Windows: no process groups, use direct signals ────────────
                try:
                    process.terminate()
                except (ProcessLookupError, OSError):
                    pass

                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    try:
                        process.kill()
                    except (ProcessLookupError, OSError):
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
        for _pid, process in list(self._processes.items()):
            await self.kill_process(process)
        self._processes.clear()

    @property
    def active_count(self) -> int:
        return len(self._processes)

    @property
    def active_pids(self) -> list[int]:
        return list(self._processes.keys())
