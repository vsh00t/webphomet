"""Z.ai API client wrapper."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from src.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Z.ai client
# ---------------------------------------------------------------------------

ZAI_BASE_URL = settings.ZAI_BASE_URL

# Retry configuration
MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 2.0  # seconds
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}


class ZaiClient:
    """Async wrapper around the Z.ai (ZhipuAI) chat completions API.

    Supports tool/function calling to drive the pentesting workflow.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 300.0,
    ) -> None:
        self.api_key = api_key or settings.ZAI_API_KEY
        self.model = model or settings.ZAI_MODEL
        self.base_url = (base_url or settings.ZAI_BASE_URL).rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        """Send a chat completion request, optionally with tool definitions.

        Parameters
        ----------
        messages:
            OpenAI-compatible message list.
        tools:
            Tool / function definitions for tool calling.
        temperature:
            Sampling temperature.
        max_tokens:
            Maximum tokens to generate.

        Returns
        -------
        Raw API response as a dict.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        logger.debug("Z.ai request: model=%s messages=%d", self.model, len(messages))

        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = await self._client.post("/chat/completions", json=payload)
                if response.status_code in RETRY_STATUS_CODES and attempt < MAX_RETRIES:
                    wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                    logger.warning(
                        "Z.ai %d — retry %d/%d in %.1fs",
                        response.status_code, attempt + 1, MAX_RETRIES, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                response.raise_for_status()
                data: dict[str, Any] = response.json()
                logger.debug("Z.ai response: usage=%s", data.get("usage"))
                return data
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if exc.response.status_code in RETRY_STATUS_CODES and attempt < MAX_RETRIES:
                    wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                    logger.warning(
                        "Z.ai %d — retry %d/%d in %.1fs",
                        exc.response.status_code, attempt + 1, MAX_RETRIES, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                    logger.warning(
                        "Z.ai connection error — retry %d/%d in %.1fs: %s",
                        attempt + 1, MAX_RETRIES, wait, exc,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise

        raise last_exc or RuntimeError("Z.ai request failed after retries")

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
