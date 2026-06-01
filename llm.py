"""LLM abstraction layer for BypassEvo.
Uses OpenAI-compatible API — works with Ollama /v1, vLLM, LM Studio, DeepSeek, etc.
"""

import asyncio
import json
import re
import time
import httpx
from typing import Optional

from openai import OpenAI, AsyncOpenAI
from config import LLMConfig


class LLMClient:
    """Unified LLM client via OpenAI-compatible API."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = OpenAI(
            base_url=config.api_base,
            api_key=config.api_key,
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
        # Async client — same config, non-blocking
        self._async_client = AsyncOpenAI(
            base_url=config.api_base,
            api_key=config.api_key,
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
        # Concurrency throttle for parallel async calls
        self._semaphore = asyncio.Semaphore(config.max_parallel_llm_calls)

    def generate(self, system_prompt: str, user_prompt: str, max_retries: int = 3) -> str:
        last_err = None
        for attempt in range(max_retries):
            try:
                resp = self._client.chat.completions.create(
                    model=self.config.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                )
                if not resp.choices:
                    raise RuntimeError("LLM returned empty response (no choices)")
                return resp.choices[0].message.content
            except Exception as e:
                last_err = e
                err = str(e)
                # Non-retryable: 404 (bad config), 401 (bad key)
                if "404" in err:
                    raise RuntimeError(
                        f"LLM API 404: Check api_base='{self.config.api_base}' and model='{self.config.model}'. "
                        f"DeepSeek: api_base='https://api.deepseek.com', model='deepseek-chat'. "
                        f"Ollama: api_base='http://localhost:11434/v1', model='qwen2.5:7b'"
                    ) from e
                if "401" in err or "403" in err:
                    raise RuntimeError(f"LLM API auth error: {err}") from e
                # Retryable: 429, 5xx, timeout, connection errors
                if attempt < max_retries - 1:
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    time.sleep(wait)
                    continue
                raise
        raise last_err  # type: ignore[misc]

    def generate_json(self, system_prompt: str, user_prompt: str) -> dict:
        raw = self.generate(system_prompt, user_prompt)
        return self._extract_json(raw)

    # ── Async methods ──────────────────────────────────────────────

    async def agenerate(self, system_prompt: str, user_prompt: str, max_retries: int = 3) -> str:
        """Async LLM generation with semaphore throttling and retry."""
        last_err = None
        for attempt in range(max_retries):
            try:
                async with self._semaphore:
                    resp = await self._async_client.chat.completions.create(
                        model=self.config.model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=self.config.temperature,
                        max_tokens=self.config.max_tokens,
                    )
                if not resp.choices:
                    raise RuntimeError("LLM returned empty response (no choices)")
                return resp.choices[0].message.content
            except Exception as e:
                last_err = e
                err = str(e)
                # Non-retryable: 404 (bad config), 401 (bad key)
                if "404" in err:
                    raise RuntimeError(
                        f"LLM API 404: Check api_base='{self.config.api_base}' and model='{self.config.model}'."
                    ) from e
                if "401" in err or "403" in err:
                    raise RuntimeError(f"LLM API auth error: {err}") from e
                # Retryable: 429, 5xx, timeout, connection errors
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    await asyncio.sleep(wait)
                    continue
                raise
        raise last_err

    async def agenerate_json(self, system_prompt: str, user_prompt: str) -> dict:
        """Async JSON generation — same parsing as sync version."""
        raw = await self.agenerate(system_prompt, user_prompt)
        return self._extract_json(raw)

    def close(self):
        """Close async client to release HTTP connections."""
        try:
            import asyncio
            asyncio.run(self._async_client.close())
        except Exception:
            pass

    def _extract_json(self, text: str) -> dict:
        """Extract JSON from LLM response, handling markdown code blocks."""
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try markdown code block
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try first { ... } block
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return {"raw_response": text, "parse_error": "Could not extract JSON"}
