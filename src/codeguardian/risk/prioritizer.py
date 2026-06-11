"""Prioritizer — assigns must-fix/should-fix/can-fix priority to findings."""

from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding


class Prioritizer:
    """Assigns action priority to each finding based on severity and context."""

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Prioritize findings in place and return them sorted by priority."""

        for finding in findings:
            finding.risk_priority = self._classify(finding)

        # Sort: must-fix first, then by severity descending
        priority_order = {"must-fix": 0, "should-fix": 1, "can-fix": 2}
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }

        findings.sort(key=lambda f: (
            priority_order.get(f.risk_priority, 99),
            severity_order.get(f.severity, 99),
            f.confidence != Confidence.HIGH,
        ))

        return findings

    @staticmethod
    def _classify(finding: Finding) -> str:
        """Determine action priority for a single finding."""
        # Blocking always gets must-fix
        if finding.blocks_release:
            return "must-fix"

        # Critical + High confidence = must-fix
        if finding.severity == Severity.CRITICAL and finding.confidence == Confidence.HIGH:
            return "must-fix"

        # Critical or High = should-fix
        if finding.severity in {Severity.CRITICAL, Severity.HIGH}:
            return "should-fix"

        # Medium with high confidence = should-fix
        if finding.severity == Severity.MEDIUM and finding.confidence == Confidence.HIGH:
            return "should-fix"

        # Everything else = can-fix
        return "can-fix"
