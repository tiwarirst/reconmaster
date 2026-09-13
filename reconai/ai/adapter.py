"""AI Adapter interface.

Provides a common interface for local LLM backends (Ollama).
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class AIAdapter(ABC):
    """Base interface for AI/LLM backends."""

    @abstractmethod
    async def analyze(self, prompt: str) -> str:
        """Send a prompt and get a response."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the backend is available."""
        pass
