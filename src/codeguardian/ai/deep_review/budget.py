"""TokenBudgetManager — manages per-scan token budget allocation.

Allocates chunks by priority (P0 > P1 > P2), stops when budget exhausted.
"""

from __future__ import annotations

import logging

from codeguardian.ai.deep_review.models import CodeChunk

logger = logging.getLogger(__name__)


class TokenBudgetManager:
    """Manages the token budget for a single deep review scan."""

    def __init__(self, max_tokens: int) -> None:
        self._max_tokens = max_tokens
        self._remaining = max_tokens
        self._spent = 0

    @property
    def remaining(self) -> int:
        return self._remaining

    @property
    def spent(self) -> int:
        return self._spent

    @property
    def max_tokens(self) -> int:
        """Return the maximum token budget."""
        return self._max_tokens

    @property
    def exhausted(self) -> bool:
        return self._remaining <= 0

    def allocate(self, chunks: list[CodeChunk]) -> list[CodeChunk]:
        """Select chunks to review within the token budget.

        Chunks are sorted by priority (lower = higher priority), then
        approved one by one.  Unlike a greedy break-on-first-miss strategy,
        we **skip** chunks that exceed remaining budget and continue trying
        smaller ones — similar to a first-fit-decreasing bin packing heuristic.

        Returns
        -------
        list[CodeChunk]
            The subset of chunks approved for AI review.
        """
        sorted_chunks = sorted(chunks, key=lambda c: (c.priority, -c.loc))
        approved: list[CodeChunk] = []
        skipped = 0

        for chunk in sorted_chunks:
            estimated = chunk.estimate_tokens()
            if self._remaining >= estimated:
                approved.append(chunk)
                self._remaining -= estimated
            else:
                skipped += 1

        if skipped > 0:
            logger.info(
                "Token budget allocation: approved %d chunks, skipped %d (too large or budget exhausted)",
                len(approved),
                skipped,
            )

        return approved

    def consume(self, tokens: int) -> None:
        """Record actual token consumption after an API call."""
        self._spent += tokens
        self._remaining = max(0, self._max_tokens - self._spent)

    def force_exhaust(self) -> None:
        """Immediately exhaust the budget (e.g. on auth failure)."""
        self._remaining = 0
