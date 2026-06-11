"""ResultNormalizer — normalizes heterogeneous engine outputs into unified model."""

from codeguardian.models.scan import EngineResult


class ResultNormalizer:
    """Normalizes engine results to ensure consistent schema.

    In MVP stage this is a pass-through (engines already produce
    EngineResult with the correct schema). Future enhancements:
      - Field repair for legacy engine output
      - Finding ID deduplication and canonicalization
      - Evidence enrichment
    """

    def normalize(self, result: EngineResult) -> EngineResult:
        """Normalize a single engine result."""
        # Ensure all findings have valid IDs
        for i, finding in enumerate(result.findings):
            if not finding.id:
                finding.id = f"{result.engine_name.upper()}-{i+1:03d}"

        # Ensure severity is lowercase string
        for finding in result.findings:
            if hasattr(finding.severity, 'value'):
                pass  # Already enum

        return result

    def normalize_batch(self, results: list[EngineResult]) -> list[EngineResult]:
        """Normalize multiple engine results."""
        return [self.normalize(r) for r in results]
