"""Ollama local LLM adapter.

Connects to a locally running Ollama instance for AI-powered analysis.
Automatically discovers installed local models if the default is not pulled.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from reconai.ai.adapter import AIAdapter


class OllamaAdapter(AIAdapter):
    """Adapter for Ollama local or remote LLM (http://localhost:11434)."""

    def __init__(self, model: str | None = None, base_url: str | None = None):
        # Guard: resolve None values from env before calling .strip()
        raw_model = model or os.getenv("OLLAMA_MODEL") or "llama3"
        self.model = str(raw_model).strip() if raw_model else "llama3"

        raw_url = base_url or os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
        raw_url = str(raw_url).strip() if raw_url else "http://localhost:11434"
        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = f"http://{raw_url}"
        self.base_url = raw_url.rstrip("/")
        self._available_models: list[str] = []
        self.logger = logging.getLogger(__name__)  # BUG-016 FIX: logger for surfacing Ollama errors to operator
        self._http_client = httpx.AsyncClient(timeout=httpx.Timeout(180.0), limits=httpx.Limits(max_keepalive_connections=5))  # BUG-035 FIX: persistent client avoids TCP reconnection overhead per LLM call

    async def close(self) -> None:
        """Gracefully close the persistent HTTP client."""
        await self._http_client.aclose()  # BUG-035 FIX: allow graceful shutdown

    async def is_available(self) -> bool:
        """Check if Ollama server is running and discover installed models."""
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
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
            client = self._http_client  # BUG-035 FIX: reuse persistent client instead of creating a new one per call
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
        except httpx.ConnectError as e:
            self.logger.warning(f"[AI] Ollama unreachable at {self.base_url} — AI features disabled. ({e})")  # BUG-016 FIX: surface Ollama connectivity failures to operator
            return ""
        except httpx.TimeoutException as e:
            self.logger.warning(f"[AI] Ollama request timed out ({e})")  # BUG-016 FIX: surface timeout to operator
            return ""
        except Exception as e:
            self.logger.debug(f"[AI] LLM call failed: {e}")  # BUG-016 FIX: log unexpected errors at debug level
            return ""
        return ""

    async def chat(self, messages: list[dict[str, str]]) -> str:
        """Send multi-turn chat messages to Ollama /api/chat."""
        try:
            client = self._http_client  # BUG-035 FIX: reuse persistent client instead of creating a new one per call
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": False},
            )
            if resp.status_code == 200:
                result: dict[str, Any] = resp.json()
                msg = result.get("message", {})
                return str(msg.get("content", "")).strip()
        except httpx.ConnectError as e:
            self.logger.warning(f"[AI] Ollama unreachable at {self.base_url} — AI features disabled. ({e})")  # BUG-016 FIX: surface Ollama connectivity failures to operator
            return ""
        except httpx.TimeoutException as e:
            self.logger.warning(f"[AI] Ollama request timed out ({e})")  # BUG-016 FIX: surface timeout to operator
            return ""
        except Exception as e:
            self.logger.debug(f"[AI] LLM call failed: {e}")  # BUG-016 FIX: log unexpected errors at debug level
            return ""

        # Fallback to single prompt generate
        combined = "\n\n".join(f"[{m.get('role', 'user').upper()}]: {m.get('content', '')}" for m in messages)
        return await self.analyze(combined)
