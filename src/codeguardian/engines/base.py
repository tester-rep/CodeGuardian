"""Base engine interface and common utilities."""

from typing import Protocol

from codeguardian.core.context import ScanContext
from codeguardian.models.scan import EngineResult


class AnalyzerEngine(Protocol):
    """Interface that all analysis engines must implement."""

    @property
    def name(self) -> str: ...

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        """Run the engine's analysis against the given scan context."""
        ...
