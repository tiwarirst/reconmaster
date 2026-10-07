"""Ollama local LLM adapter.

Connects to a locally running Ollama instance for AI-powered analysis.
Automatically discovers installed local models if the default is not pulled.
"""
from __future__ import annotations

import os
from typing import Any

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
        self._available_models: list[str] = []

    async def is_available(self) -> bool:
        """Check if Ollama server is running and discover installed models."""
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    data = resp.json()
                    models_list = data.get("models", [])
                    self._available_models = [m.get("name", "") for m in models_list if m.get("name")]

                    if not self._available_models:
                        # Ollama is running, but no models have been pulled yet
                        return False

                    # Check if requested model is present
                    model_names = [m.split(":")[0].lower() for m in self._available_models]
                    target_model = self.model.split(":")[0].lower()

                    if target_model not in model_names:
                        # Auto-select the first available installed model
                        self.model = self._available_models[0]

                    return True
        except Exception:
            pass
        return False

    async def analyze(self, prompt: str) -> str:
        """Send prompt to Ollama and return generated response."""
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False},
                )
                if resp.status_code == 200:
                    result: dict[str, Any] = resp.json()
                    return str(result.get("response", "")).strip()
                elif resp.status_code == 404 and self._available_models:
                    # Retry with first confirmed model
                    self.model = self._available_models[0]
                    retry_resp = await client.post(
                        f"{self.base_url}/api/generate",
                        json={"model": self.model, "prompt": prompt, "stream": False},
                    )
                    if retry_resp.status_code == 200:
                        return str(retry_resp.json().get("response", "")).strip()
        except Exception:
            pass
        return ""
