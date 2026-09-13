"""Progress and Spinner management for the terminal UI."""
from __future__ import annotations

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.console import Console


def make_progress(console: Console) -> Progress:
    """Create a rich Progress bar suitable for multi-module scan tracking."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
