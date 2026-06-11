"""Scheduler — manages parallel execution of engine tasks."""

import asyncio
import time
from collections.abc import Awaitable

from codeguardian.models.scan import EngineResult


class Scheduler:
    """Coordinates parallel execution of analysis engine coroutines."""

    async def run(
        self,
        coroutines: list[Awaitable[EngineResult]],
        concurrency_limit: int | None = None,
    ) -> list[EngineResult]:
        """Execute multiple engine tasks concurrently with error isolation."""
        if not coroutines:
            return []

        limit = max(1, concurrency_limit or len(coroutines))
        semaphore = asyncio.Semaphore(limit)

        async def _safe_run(coro: Awaitable[EngineResult], idx: int) -> EngineResult:
            async with semaphore:
                start = time.monotonic()
                outcome = (await asyncio.gather(coro, return_exceptions=True))[0]
                if isinstance(outcome, Exception):
                    return EngineResult(
                        engine_name=f"task-{idx}",
                        errors=[f"{type(outcome).__name__}: {outcome}"],
                    )
                outcome.duration_ms = (time.monotonic() - start) * 1000
                return outcome


        wrapped = [_safe_run(coro, i) for i, coro in enumerate(coroutines)]
        return await asyncio.gather(*wrapped)
