"""Finding model — a detected issue, risk, or vulnerability."""

from __future__ import annotations

from pydantic import BaseModel, Field

from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.evidence import Evidence


_EVIDENCE_LEVEL_RANK = {
    "test-confirmed": 5,
    "static-confirmed": 4,
    "likely": 3,
    "suspected": 2,
    "needs-review": 1,
}


class Finding(BaseModel):

    """A single finding/issue/vulnerability detected during analysis.

    This is the core output unit of every analyzer engine.
    """

    id: str  # Unique ID per scan, e.g., "SEC-001", "DEFECT-042"
    title: str
    category: str  # FindingCategory value as string
    severity: Severity
    confidence: Confidence
    location: Location

    evidences: list[Evidence] = Field(default_factory=list)

    # Analysis fields (populated by risk/AI layer)
    root_cause: str | None = None
    impact: str | None = None
    fix_suggestion: str | None = None
    test_suggestion: str | None = None
    monitor_suggestion: str | None = None

    # Priority and gating
    risk_priority: str = "should-fix"  # RiskPriority value as string
    blocks_release: bool = False
    score_impact: float = 0.0  # How much this finding reduces overall score

    # Evidence and verification
    evidence_level: str = "suspected"  # test-confirmed / static-confirmed / likely / suspected / needs-review
    verification_status: str = "unverified"  # unverified / test-generated / syntax-checked / static-confirmed / test-confirmed / not-reproduced / inconclusive / skipped-*

    verification_summary: str | None = None
    verification_artifacts: list[dict[str, object]] = Field(default_factory=list)

    # Provenance

    source_engine: str  # Which engine discovered this
    rule_id: str | None = None  # Specific rule that triggered
    rule_description: str | None = None  # Human-readable rule explanation (中文)
    cwe_ids: list[str] = Field(default_factory=list)  # CWE references
    tags: list[str] = Field(default_factory=list)

    @property
    def evidence_rank(self) -> int:
        return _EVIDENCE_LEVEL_RANK.get(self.evidence_level, 0)

    @property
    def is_blocking(self) -> bool:

        """Whether this finding should block release by default.

        Blocking is intentionally stricter than severity: maintainability,
        complexity, evolution, and most performance findings can be high risk
        without automatically preventing release. Engines may still force a
        block with ``blocks_release=True`` for known release-stopping rules.
        """
        if self.blocks_release:
            return True

        high_confidence = self.confidence == Confidence.HIGH
        if self.category == "security":
            return self.severity in {Severity.CRITICAL, Severity.HIGH} and high_confidence

        if self.category in {"defect", "testing", "config_risk"}:
            return self.severity == Severity.CRITICAL and high_confidence

        return False

