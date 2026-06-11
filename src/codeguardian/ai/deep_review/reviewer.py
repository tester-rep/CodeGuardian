"""AIReviewer — sends code chunks to the AI provider with retry/backoff.

Implements:
- Exponential backoff on rate limits (429)
- Dynamic concurrency reduction
- JSON response parsing with fallback
- Budget tracking
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any


from codeguardian.ai.deep_review.budget import TokenBudgetManager
from codeguardian.ai.deep_review.context_builder import ContextPackBuilder
from codeguardian.ai.deep_review.models import AIFindingRaw, CodeChunk, ContextPack, ReviewResult
from codeguardian.ai.models import TokenUsage
from codeguardian.ai.prompts.deep_review import SYSTEM_MESSAGE, build_review_prompt


if TYPE_CHECKING:
    from codeguardian.ai.base import AIProvider

logger = logging.getLogger(__name__)

MAX_RETRIES = 4
_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)


class AIReviewer:
    """Orchestrates AI review of code chunks with retry and budget control."""

    def __init__(
        self,
        provider: AIProvider,
        context_builder: ContextPackBuilder,
        budget: TokenBudgetManager,
        max_concurrent: int = 5,
        system_message: str = SYSTEM_MESSAGE,
        prompt_builder: Callable[[ContextPack], str] = build_review_prompt,
    ) -> None:
        self._provider = provider
        self._ctx_builder = context_builder
        self._budget = budget
        self._max_concurrent = max_concurrent
        self._system_message = system_message
        self._prompt_builder = prompt_builder

        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._current_concurrency = max_concurrent
        self._auth_failed = False
        # Accumulated token usage across all chunks
        self._total_usage = TokenUsage()

    @property
    def total_usage(self) -> TokenUsage:
        """Total token usage accumulated across all reviewed chunks."""
        return self._total_usage

    async def review_chunks(self, chunks: list[CodeChunk]) -> list[ReviewResult]:
        """Review all chunks concurrently, respecting concurrency limits."""
        total = len(chunks)
        self._progress_done = 0
        self._progress_total = total
        logger.info("AI review starting: %d chunks (concurrency=%d)", total, self._max_concurrent)
        tasks = [self._review_with_semaphore(chunk) for chunk in chunks]
        return await asyncio.gather(*tasks)

    async def _review_with_semaphore(self, chunk: CodeChunk) -> ReviewResult:
        """Acquire semaphore then review a single chunk."""
        async with self._semaphore:
            if self._budget.exhausted:
                return ReviewResult.skipped(chunk.file_path, "budget_exhausted")
            result = await self._review_chunk(chunk, attempt=0)
            self._progress_done += 1
            logger.info(
                "AI review progress: %d/%d — %s [%s]",
                self._progress_done,
                self._progress_total,
                chunk.file_path,
                result.status,
            )
            return result

    async def _review_chunk(self, chunk: CodeChunk, attempt: int) -> ReviewResult:
        """Review a single chunk with retry logic."""
        context_pack = self._ctx_builder.build(chunk)
        prompt = self._prompt_builder(context_pack)

        try:
            gen_result = await self._provider.generate_with_usage(
                prompt,
                system_message=self._system_message,
            )

            raw_response = gen_result.text
            usage = gen_result.usage

            # Record real token usage (fallback to estimate if API returns 0)
            actual_tokens = usage.total_tokens
            estimated_tokens = (len(prompt) + len(raw_response)) // 4
            if actual_tokens == 0:
                actual_tokens = estimated_tokens
            self._budget.consume(actual_tokens)

            # Accumulate usage stats. When the provider reports zero, fall
            # back to an estimate so total_usage stays consistent with the
            # budget accounting above.
            if usage.total_tokens > 0:
                self._total_usage.prompt_tokens += usage.prompt_tokens
                self._total_usage.completion_tokens += usage.completion_tokens
                self._total_usage.total_tokens += usage.total_tokens
            else:
                est_prompt = len(prompt) // 4
                est_completion = max(estimated_tokens - est_prompt, 0)
                self._total_usage.prompt_tokens += est_prompt
                self._total_usage.completion_tokens += est_completion
                self._total_usage.total_tokens += estimated_tokens

            result = self._parse_response(raw_response, chunk)
            result.tokens_used = actual_tokens
            return result

        except Exception as exc:
            exc_str = str(exc).lower()

            # Auth / permission errors — fail fast, no point retrying
            if "401" in exc_str or "403" in exc_str or "forbidden" in exc_str or "unauthorized" in exc_str:
                if not self._auth_failed:
                    self._auth_failed = True
                    logger.error(
                        "API authentication/permission error (401/403). "
                        "Check your token and model permissions. "
                        "Skipping ALL remaining chunks."
                    )
                self._budget.force_exhaust()
                return ReviewResult.skipped(chunk.file_path, "auth_forbidden")

            # Rate limit handling
            if "429" in exc_str or "rate" in exc_str:
                if attempt >= MAX_RETRIES:
                    logger.warning("Rate limit exceeded after %d retries for %s", MAX_RETRIES, chunk.file_path)
                    return ReviewResult.skipped(chunk.file_path, "rate_limit_exceeded")
                wait = min(2 ** attempt * 1.0, 30.0)
                self._reduce_concurrency()
                await asyncio.sleep(wait)
                return await self._review_chunk(chunk, attempt + 1)

            # Timeout / connection errors
            if "timeout" in exc_str or "connect" in exc_str:
                if attempt >= MAX_RETRIES:
                    logger.warning("API unreachable after %d retries for %s", MAX_RETRIES, chunk.file_path)
                    return ReviewResult.skipped(chunk.file_path, "api_unreachable")
                await asyncio.sleep(2 ** attempt)
                return await self._review_chunk(chunk, attempt + 1)

            # Other errors — log and skip
            logger.exception("Unexpected error reviewing chunk %s", chunk.file_path)
            return ReviewResult.skipped(chunk.file_path, f"error: {type(exc).__name__}")

    def _reduce_concurrency(self) -> None:
        """Dynamically reduce concurrency on rate limits: 5 → 3 → 2 → 1."""
        new_limit = max(1, self._current_concurrency // 2)
        if new_limit < self._current_concurrency:
            self._current_concurrency = new_limit
            self._semaphore = asyncio.Semaphore(new_limit)
            logger.warning("Rate limited, reducing concurrency to %d", new_limit)

    def _parse_response(self, raw: str, chunk: CodeChunk) -> ReviewResult:
        """Parse AI JSON response into a ReviewResult."""
        json_str = self._extract_json(raw)

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Failed to parse AI response JSON for %s", chunk.file_path)
            return ReviewResult(
                chunk_file_path=chunk.file_path,
                chunk_qualified_name=chunk.qualified_name,
                status="failed",
                skip_reason="parse_error",
                summary=raw[:200],
            )

        findings: list[AIFindingRaw] = []
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            findings.append(
                AIFindingRaw(
                    title=item.get("title", ""),
                    category=item.get("category", ""),
                    severity=item.get("severity", "medium"),
                    confidence=int(item.get("confidence", 5)),
                    line_start=int(item.get("line_start", chunk.line_start)),
                    line_end=int(item.get("line_end", chunk.line_end)),
                    description=item.get("description", ""),
                    evidence=item.get("evidence", ""),
                    fix_suggestion=item.get("fix_suggestion", ""),
                    self_reflection=item.get("self_reflection", ""),
                )
            )

        return ReviewResult(
            chunk_file_path=chunk.file_path,
            chunk_qualified_name=chunk.qualified_name,
            findings=findings,
            summary=data.get("summary", ""),
            verified_local_findings=data.get("verified_local_findings", []),
            status="done",
        )

    @staticmethod
    def _extract_json(raw: str) -> str:
        """Extract JSON from AI response, handling markdown code blocks."""
        # Try to find JSON in a code block first
        match = _JSON_BLOCK_RE.search(raw)
        if match:
            return match.group(1).strip()

        # Try the raw text (maybe it's already valid JSON)
        stripped = raw.strip()
        if stripped.startswith("{"):
            return stripped

        # Last resort: find the first { ... } block
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start != -1 and end > start:
            return stripped[start : end + 1]

        return stripped
