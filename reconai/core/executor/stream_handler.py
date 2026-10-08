"""Stream handler — captures and streams stdout/stderr from subprocesses in real-time.

Ensures the terminal never appears frozen by displaying output as it arrives.
"""
from __future__ import annotations

import asyncio
import io
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence


class StreamHandler:
    """Handles real-time streaming of subprocess output.

    Features:
    - Streams lines to terminal callbacks as they arrive
    - Captures full output for later processing (bounded in memory to prevent OOM)
    - Gracefully handles long lines (>64KB) without breaking stream
    - Optionally writes to file in real-time
    - Prefixes each line with module name and timestamp
    """

    def __init__(
        self,
        module_name: str = "",
        output_file: Path | None = None,
        on_stdout: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
        prefix: bool = True,
        max_buffer_lines: int = 10000,
    ) -> None:
        self._module_name = module_name
        self._output_file = output_file
        self._on_stdout = on_stdout
        self._on_stderr = on_stderr
        self._prefix = prefix
        self._stdout_lines: deque[str] = deque(maxlen=max_buffer_lines)
        self._stderr_lines: deque[str] = deque(maxlen=max_buffer_lines)
        self._file_handle: io.TextIOWrapper | None = None

    async def __aenter__(self) -> "StreamHandler":
        if self._output_file:
            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(self._output_file, "w", encoding="utf-8")
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

    async def stream_stdout(self, stream: asyncio.StreamReader) -> str:
        """Read and stream stdout line by line."""
        return await self._stream(stream, self._stdout_lines, self._on_stdout, "stdout")

    async def stream_stderr(self, stream: asyncio.StreamReader) -> str:
        """Read and stream stderr line by line."""
        return await self._stream(stream, self._stderr_lines, self._on_stderr, "stderr")

    async def _stream(
        self,
        stream: asyncio.StreamReader,
        buffer: deque[str],
        callback: Callable[[str], None] | None,
        stream_type: str,
    ) -> str:
        """Internal stream reader with buffer bounds and LimitOverrunError recovery."""
        while True:
            try:
                try:
                    line_bytes = await stream.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    # Line exceeded default 64KB chunk — read a safe block
                    line_bytes = await stream.read(8192)

                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="replace").rstrip("\n\r")
                buffer.append(line)

                # Write to file
                if self._file_handle:
                    self._file_handle.write(line + "\n")
                    self._file_handle.flush()

                # Send to callback
                if callback and line.strip():
                    if self._prefix and self._module_name:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        formatted = f"[{timestamp}] [{self._module_name}] {line}"
                    else:
                        formatted = line
                    callback(formatted)

            except Exception:
                break

        return "\n".join(buffer)

    @property
    def stdout(self) -> str:
        return "\n".join(self._stdout_lines)

    @property
    def stderr(self) -> str:
        return "\n".join(self._stderr_lines)
