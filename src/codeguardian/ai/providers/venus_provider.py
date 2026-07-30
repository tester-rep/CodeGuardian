"""OpenAI-compatible LLM provider — calls any OpenAI-compatible endpoint.

Supports OpenAI, Azure OpenAI, local LLM servers (vLLM, Ollama, LM Studio),
or custom API proxies. Authentication uses a ``Bearer`` token read from the
environment variable specified by ``api_key_env``.

``httpx`` is part of CodeGuardian's core dependencies, so no extra
installation step is required.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class _AsyncTokenBucket:
    """Process-wide async token bucket for client-side TPS throttling.

    Why hand-rolled instead of ``aiolimiter``: avoid a new third-party
    dependency for ~30 lines of logic.

    Behavior:
      - Capacity is fixed at 1 token (no burst). Tokens refill continuously
        at ``rate_per_sec``. This keeps spacing strict: at rate=1.0 callers
        are paced ~1s apart with zero burst margin, which matters because
        upstream gateways often enforce TPS over very short windows
        (sub-second), making any burst trigger 429.
      - ``acquire()`` waits (sleeps) until at least 1 token is available,
        then consumes 1.
      - Single ``asyncio.Lock`` serializes refill+consume so no race.
    """

    def __init__(self, rate_per_sec: float) -> None:
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self._rate = rate_per_sec
        # Fixed capacity = 1: no accumulated burst, strict spacing.
        self._capacity = 1.0
        self._tokens = 1.0
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                if elapsed > 0:
                    self._tokens = min(
                        self._capacity, self._tokens + elapsed * self._rate
                    )
                    self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Compute sleep time outside the lock to not block other waiters.
                deficit = 1.0 - self._tokens
                wait = deficit / self._rate
            await asyncio.sleep(wait)


class _RateLimitError(Exception):
    """Rate limit error carrying the server's Retry-After value.

    Attached as ``__cause__`` on the original httpx exception so upstream
    retry logic can extract the server-provided wait time instead of
    guessing.
    """

    def __init__(self, wait_seconds: int) -> None:
        self.wait_seconds = wait_seconds
        super().__init__(f"Rate limited, retry after {wait_seconds}s")


# Module-level limiter registry, keyed by base_url. All LLMProvider
# instances pointing at the same gateway share a single bucket, so a
# multi-phase scan (deep_review + ai_verify + free_review) collectively
# stays under the TPS quota even when each phase has its own provider.
_LIMITERS: dict[str, _AsyncTokenBucket] = {}
_LIMITERS_LOCK = asyncio.Lock()


async def _get_or_create_limiter(
    base_url: str, rate_per_sec: float
) -> _AsyncTokenBucket | None:
    """Return shared limiter for ``base_url``; ``None`` when throttling disabled.

    First call wins on rate: subsequent providers with a different rate
    against the same base_url reuse the existing bucket. This is intentional
    — a single LLM account has one TPS quota, mixing rates would be
    incoherent. Logged at WARNING when a mismatch is observed.
    """
    if rate_per_sec <= 0:
        return None
    async with _LIMITERS_LOCK:
        existing = _LIMITERS.get(base_url)
        if existing is None:
            _LIMITERS[base_url] = _AsyncTokenBucket(rate_per_sec)
            logger.info(
                "LLM client-side rate limiter installed: base_url=%s rps=%.2f",
                base_url,
                rate_per_sec,
            )
            return _LIMITERS[base_url]
        if abs(existing._rate - rate_per_sec) > 1e-6:
            logger.warning(
                "LLM rate limiter rate mismatch for %s: existing=%.2f rps, "
                "ignoring new=%.2f rps (first call wins)",
                base_url,
                existing._rate,
                rate_per_sec,
            )
        return existing


class VenusProvider:
    """AI provider using OpenAI-compatible API protocol.

    Works with any OpenAI-compatible endpoint: OpenAI, Azure OpenAI,
    local LLM servers (vLLM, Ollama, LM Studio), or custom proxies.
    """

    DEFAULT_BASE_URL = "https://api.openai.com/v1"

    def __init__(
        self,
        *,
        model: str = "gpt-4o",
        api_key_env: str = "CODEGUARDIAN_API_KEY",
        base_url: str | None = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        timeout: float = 300.0,
        requests_per_second: float = 0.0,
    ) -> None:
        token = os.environ.get(api_key_env, "")
        if not token:
            raise ValueError(
                f"AI provider requires environment variable {api_key_env}. "
                f"Set it in your .env file or export it in your shell."
            )

        self._token = token
        self._base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._rps = requests_per_second
        # Limiter is created lazily on first call (needs running event loop).
        self._limiter: _AsyncTokenBucket | None = None
        self._limiter_initialized = False

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._token}",
            },
            timeout=httpx.Timeout(timeout, connect=30.0),
        )

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """Send a prompt to the LLM Chat Completions endpoint."""
        result = await self.generate_with_usage(prompt, **kwargs)
        return result.text

    async def generate_with_usage(self, prompt: str, **kwargs: Any) -> "GenerateResult":
        """Send a prompt and return response with token usage info."""
        from codeguardian.ai.models import GenerateResult, TokenUsage

        system_message = kwargs.get(
            "system_message",
            "You are CodeGuardian, an expert code quality analysis assistant. "
            "Respond concisely in Chinese (简体中文) unless the user requests otherwise. "
            "Focus on actionable, specific observations rather than generic advice.",
        )

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
        }

        try:
            # Client-side TPS throttle (token bucket). No-op when rps <= 0.
            # Lazy-init: needs a running loop, can't build in __init__.
            if not self._limiter_initialized:
                self._limiter = await _get_or_create_limiter(
                    self._base_url, self._rps
                )
                self._limiter_initialized = True
            if self._limiter is not None:
                await self._limiter.acquire()

            logger.debug(
                "LLM request → model=%s, token=%s..., url=%s",
                payload["model"],
                self._token[:8],
                f"{self._base_url}/chat/completions",
            )
            response = await self._client.post("/chat/completions", json=payload)
            logger.debug("LLM response ← status=%s", response.status_code)
            if response.status_code in (401, 403):
                logger.error(
                    "LLM 403/401 detail → model=%s, token_prefix=%s, response_body=%s",
                    payload["model"],
                    self._token[:12],
                    response.text[:500],
                )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            text = content.strip() if content else ""

            # Extract usage from OpenAI-compatible response
            usage_data = data.get("usage", {})
            usage = TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
            )

            return GenerateResult(text=text, usage=usage)
        except httpx.HTTPStatusError as e:
            # Expected, recoverable errors → log concisely, no stack trace.
            # Upstream reviewer/verifier inspects str(exc) for "429" / "rate"
            # and applies its own backoff + concurrency reduction.
            status = e.response.status_code
            if status == 429:
                retry_after_raw = e.response.headers.get("Retry-After", "")
                try:
                    wait_s = int(retry_after_raw)
                except (ValueError, TypeError):
                    wait_s = 5
                logger.warning(
                    "LLM rate-limited (429), retry-after=%ss — upstream will back off",
                    wait_s,
                )
                e.__cause__ = _RateLimitError(wait_s)
            else:
                # 4xx/5xx other than 429 → keep as warning with body snippet,
                # no stack trace (auth errors already logged above).
                logger.warning(
                    "LLM HTTP %d: %s",
                    status,
                    e.response.text[:200],
                )
            raise
        except httpx.TimeoutException as e:
            # Network timeout → recoverable, upstream retries on "timeout".
            logger.warning("LLM request timed out: %s", e)
            raise
        except Exception:
            logger.exception("LLM API call failed")
            raise

    async def close(self) -> None:
        """Close the underlying HTTP client connection pool."""
        await self._client.aclose()
