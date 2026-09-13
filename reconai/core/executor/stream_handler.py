"""Stream handler — captures and streams stdout/stderr from subprocesses in real-time.

Ensures the terminal never appears frozen by displaying output as it arrives.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Callable


class StreamHandler:
    """Handles real-time streaming of subprocess output.

    Features:
    - Streams lines to terminal callbacks as they arrive
    - Captures full output for later processing
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
    ):
        self._module_name = module_name
        self._output_file = output_file
        self._on_stdout = on_stdout
        self._on_stderr = on_stderr
        self._prefix = prefix
        self._stdout_lines: list[str] = []
        self._stderr_lines: list[str] = []
        self._file_handle = None

    async def __aenter__(self):
        if self._output_file:
            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(self._output_file, "w")
        return self

    async def __aexit__(self, *args):
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
        buffer: list[str],
        callback: Callable[[str], None] | None,
        stream_type: str,
    ) -> str:
        """Internal stream reader."""
        while True:
            try:
                line_bytes = await stream.readline()
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
