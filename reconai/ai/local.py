"""Ollama local LLM adapter.

Connects to a locally running Ollama instance for AI-powered analysis.
"""
from __future__ import annotations

import os

import httpx

from reconai.ai.adapter import AIAdapter


class OllamaAdapter(AIAdapter):
    """Adapter for Ollama local or remote LLM (http://localhost:11434)."""

    def __init__(self, model: str | None = None, base_url: str | None = None):
        self.model = (model or os.getenv("OLLAMA_MODEL", "llama3")).strip()
        raw_url = (base_url or os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_HOST", "http://localhost:11434")).strip()
        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = f"http://{raw_url}"
        self.base_url = raw_url.rstrip("/")

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
