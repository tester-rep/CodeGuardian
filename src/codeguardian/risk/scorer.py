"""RiskScorer — calculates overall risk scores from findings.

Implements a practical approximation of the composite risk model from COMBINED.md §五:
  f(severity, reachability, probability, scope, detectability, cost, confidence)
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding

# Default weights from COMBINED.md §5.2 comment
DEFAULT_WEIGHTS = {
    "severity": 0.25,
    "reachability": 0.20,
    "probability": 0.15,
    "scope": 0.15,
    "detectability": 0.08,
    "cost": 0.08,
    "confidence": 0.01,
}

MAX_FINDING_DEDUCTION = 60.0

# Hyperbolic decay constant for aggregating deductions into a 0-100 score.
# score = 100 * K / (K + total_deduction)
#
# Why hyperbolic instead of linear:
#   The previous "100 - sum(deductions)" model collapses to 0 once total
#   deductions reach 100. Even a single medium finding can deduct ~62
#   points, so any project with 2+ medium-severity findings would always
#   score 0 — defeating the purpose of a continuous score.
#
# Choice of K=300 produces these reference points (using current weights):
#   1 medium finding         → ~83/100 (good)
#   1 high blocking finding  → ~80/100 (good/warning border)
#   5 high findings          → ~45/100 (warning)
#   53 mixed (this codebase) → ~10/100 (critical, but not zero)
#
# This keeps small projects healthy while still flagging large issue piles
# as critical, without collapsing to a meaningless flat 0.
SCORE_DECAY_K = 300.0


class RiskScorer:

    """Calculates risk score for findings, modules, and the whole project.

    Score ranges from 0 to 100, where lower = worse.
    """

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = self._merge_weights(weights)

    @staticmethod
    def _merge_weights(weights: dict[str, float] | None) -> dict[str, float]:
        merged = dict(DEFAULT_WEIGHTS)
        if not weights:
            return merged

        for key, value in weights.items():
            if key in merged:
                merged[key] = float(value)
        return merged

    def score(self, findings: list[Finding]) -> float:
        """Calculate overall project risk score (0-100).

        Higher score = healthier project (fewer/severe issues).

        Aggregation uses hyperbolic decay so the score never collapses to
        a flat 0 even when many findings accumulate. See ``SCORE_DECAY_K``
        for the reference points behind the chosen constant.
        """
        if not findings:
            return 100.0

        total_deduction = 0.0
        for finding in findings:
            deduction = min(self._score_finding(finding), MAX_FINDING_DEDUCTION)
            finding.score_impact = round(deduction, 1)
            total_deduction += deduction

        score = 100.0 * SCORE_DECAY_K / (SCORE_DECAY_K + total_deduction)
        return round(score, 1)

    def _score_finding(self, finding: Finding) -> float:
        """Calculate the score impact of a single finding."""
        w = self.weights
        factors = {
            "severity": self._severity_value(finding.severity),
            "reachability": self._reachability_value(finding),
            "probability": self._probability_value(finding),
            "scope": self._scope_value(finding),
            "detectability": self._detectability_value(finding),
            "cost": self._cost_value(finding),
            "confidence": self._confidence_value(finding.confidence),
        }
        weighted_score = sum(factors[name] * w[name] for name in DEFAULT_WEIGHTS)
        deduction = weighted_score * 100.0

        if finding.blocks_release:
            deduction += 8.0
        if finding.risk_priority == "must-fix":
            deduction += 5.0
        elif finding.risk_priority == "should-fix":
            deduction += 2.5

        return deduction

    @staticmethod
    def _severity_value(severity: Severity) -> float:
        values = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.55,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }
        return values.get(severity, 0.55)

    def _reachability_value(self, finding: Finding) -> float:
        path = self._path_lower(finding)
        path_tokens = self._path_tokens(path)
        title = self._text_blob(finding)
        if finding.blocks_release:
            return 1.0
        if finding.category == "security" and (
            path_tokens & _ENTRYPOINT_TOKEN_SET or any(token in title for token in _ENTRYPOINT_TOKENS)
        ):
            return 0.95
        if finding.category in {"security", "defect"}:
            return 0.82
        if path == "project":
            return 0.85
        if path_tokens & _ENTRYPOINT_TOKEN_SET:
            return 0.78
        if finding.category == "testing":
            return 0.68
        return 0.58


    def _probability_value(self, finding: Finding) -> float:
        text = self._text_blob(finding)
        if finding.rule_id in {"GIT-HOTSPOT", "OWNERSHIP-RISK", "LOW-CHANGE-COVERAGE"}:
            return 0.95
        if any(token in text for token in ("hotspot", "coverage", "regression", "frequent", "history", "churn")):
            return 0.88
        if finding.category in {"security", "defect"}:
            return 0.8
        if finding.category == "testing":
            return 0.76
        return 0.6

    def _scope_value(self, finding: Finding) -> float:
        path = self._path_lower(finding)
        if path == "project":
            return 1.0
        if self._directory_tokens(path) & _CORE_PATH_TOKEN_SET:
            return 0.9
        path_parts = [part for part in PurePosixPath(path or ".").parts if part not in {".", ""}]
        if len(path_parts) <= 1:
            return 0.8
        return 0.62


    def _detectability_value(self, finding: Finding) -> float:
        if finding.category == "testing":
            return 0.92
        if finding.category == "security":
            return 0.86
        if not finding.test_suggestion:
            return 0.8
        if finding.confidence == Confidence.LOW:
            return 0.45
        return 0.62

    def _cost_value(self, finding: Finding) -> float:
        path = self._path_lower(finding)
        if finding.blocks_release or finding.category == "security":
            return 0.9
        if self._directory_tokens(path) & _CORE_PATH_TOKEN_SET:
            return 0.82
        if finding.category in {"maintainability", "defect"}:
            return 0.72
        return 0.58


    @staticmethod
    def _confidence_value(confidence: Confidence) -> float:
        values = {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.7,
            Confidence.LOW: 0.4,
        }
        return values.get(confidence, 0.7)

    def module_score(self, module_findings: list[Finding]) -> float:
        """Score a single module's health (0-100)."""
        return self.score(module_findings)

    @staticmethod
    def _path_lower(finding: Finding) -> str:
        return (finding.location.file_path or "").replace("\\", "/").strip().lower()

    @staticmethod
    def _path_tokens(path: str) -> set[str]:
        tokens: set[str] = set()
        for part in PurePosixPath(path or ".").parts:
            if part in {".", ""}:
                continue
            source = PurePosixPath(part).stem if "." in part else part
            tokens.update(token for token in _PATH_TOKEN_RE.split(source) if token)
        return tokens

    @staticmethod
    def _directory_tokens(path: str) -> set[str]:
        tokens: set[str] = set()
        parts = [part for part in PurePosixPath(path or ".").parts if part not in {".", ""}]
        for part in parts[:-1]:
            tokens.update(token for token in _PATH_TOKEN_RE.split(part) if token)
        return tokens

    @classmethod
    def _text_blob(cls, finding: Finding) -> str:
        return " ".join(

            part
            for part in [
                (finding.title or "").lower(),
                (finding.root_cause or "").lower(),
                (finding.impact or "").lower(),
                " ".join(tag.lower() for tag in finding.tags),
            ]
            if part
        )


_ENTRYPOINT_TOKENS = (
    "api",
    "route",
    "routes",
    "controller",
    "handler",
    "service",
    "main",
    "entry",
    "public",
    "web",
)
_ENTRYPOINT_TOKEN_SET = set(_ENTRYPOINT_TOKENS)

_CORE_PATH_TOKENS = (
    "core",
    "shared",
    "common",
    "domain",
    "service",
    "api",
    "controller",
    "handler",
    "infra",
    "platform",
)
_CORE_PATH_TOKEN_SET = set(_CORE_PATH_TOKENS)
_PATH_TOKEN_RE = re.compile(r"[\\/._-]+")
