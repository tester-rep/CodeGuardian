"""Dimension score builder for project-level reporting."""

from __future__ import annotations

from collections import defaultdict

from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric
from codeguardian.models.profile import DimensionScore
from codeguardian.risk.scorer import RiskScorer

ENGINE_DIMENSION_MAP = {
    "structure": "scale",
    "metrics": "scale",
    "complexity": "complexity",
    "defect": "defects",
    "security": "security",
    "performance": "performance",
    "testing": "testing",
    "git": "evolution",
}



CATEGORY_DIMENSION_MAP = {
    "security": "security",
    "defect": "defects",
    "maintainability": "complexity",
    "architecture": "architecture",
    "performance": "performance",
    "testing": "testing",
    "config_risk": "config_risk",
}

DIMENSION_ORDER = [
    "scale",
    "complexity",
    "defects",
    "security",
    "testing",
    "architecture",
    "performance",
    "evolution",
    "config_risk",
]


def build_dimension_scores(
    findings: list[Finding],
    metrics: list[Metric],
) -> list[DimensionScore]:
    """Build project-level dimension score summaries from findings and metrics."""
    metrics_by_dimension: dict[str, list[Metric]] = defaultdict(list)
    findings_by_dimension: dict[str, list[Finding]] = defaultdict(list)

    for metric in metrics:
        dimension = metric.dimension or ENGINE_DIMENSION_MAP.get(metric.source_engine)
        if dimension:
            metrics_by_dimension[dimension].append(metric)

    for finding in findings:
        dimension = ENGINE_DIMENSION_MAP.get(finding.source_engine)
        if not dimension:
            dimension = CATEGORY_DIMENSION_MAP.get(finding.category, "other")
        findings_by_dimension[dimension].append(finding)

    scorer = RiskScorer()
    dimensions = set(metrics_by_dimension) | set(findings_by_dimension)
    scores: list[DimensionScore] = []

    for dimension in dimensions:
        dimension_findings = findings_by_dimension.get(dimension, [])
        dimension_metrics = metrics_by_dimension.get(dimension, [])
        score = scorer.score(dimension_findings) if dimension_findings else 100.0
        top_issues = [finding.title for finding in _sort_findings(dimension_findings)[:3]]

        scores.append(
            DimensionScore(
                dimension=dimension,
                score=score,
                status=_health_status(score),
                findings_count=len(dimension_findings),
                metrics=dimension_metrics,
                top_issues=top_issues,
            )
        )

    return sorted(scores, key=_dimension_sort_key)


def _dimension_sort_key(score: DimensionScore) -> tuple[int, str]:
    try:
        index = DIMENSION_ORDER.index(score.dimension)
    except ValueError:
        index = len(DIMENSION_ORDER)
    return (index, score.dimension)


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.severity.value, 5),
            finding.risk_priority,
            finding.id,
        ),
    )


def _health_status(score: float) -> str:
    # Thresholds intentionally loose: with the hyperbolic-decay aggregation
    # in RiskScorer.score(), a single high-severity finding lands around 80,
    # so the legacy >=80 / >=50 cutoffs were too eager to flag projects as
    # "warning" or "critical". See scorer.SCORE_DECAY_K for reference points.
    if score >= 75:
        return "good"
    if score >= 40:
        return "warning"
    return "critical"
