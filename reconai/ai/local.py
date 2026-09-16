"""Ollama local LLM adapter.

Connects to a locally running Ollama instance for AI-powered analysis.
"""
from __future__ import annotations

import httpx

from reconai.ai.adapter import AIAdapter


class OllamaAdapter(AIAdapter):
    """Adapter for Ollama local LLM (http://localhost:11434)."""

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def analyze(self, prompt: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False}
                )
                if resp.status_code == 200:
                    result: dict[str, str] = resp.json()
                    return result.get("response", "")
        except Exception:
            pass
        return ""
