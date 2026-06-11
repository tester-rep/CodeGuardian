"""Base reporter interface."""

from pathlib import Path
from typing import Protocol

from codeguardian.models.report import ReportArtifact
from codeguardian.models.scan import ScanResult


class Reporter(Protocol):
    """Interface that all report generators must implement."""

    def render(self, result: ScanResult, output_dir: Path | None) -> ReportArtifact | None:
        """Render a report from the given scan result.

        Returns None if this reporter cannot produce output (e.g., TerminalReporter).
        """
        ...
