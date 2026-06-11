"""Tests for project dimension score aggregation."""

from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric, MetricNames
from codeguardian.risk.dimensions import build_dimension_scores


def test_build_dimension_scores_groups_metrics_and_findings() -> None:
    findings = [
        Finding(
            id="SEC-001",
            title="Critical secret leak",
            category="security",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=Location(file_path="app.py", line_start=10),
            source_engine="security",
            blocks_release=True,
        ),
        Finding(
            id="CMP-001",
            title="Deeply nested function",
            category="maintainability",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            location=Location(file_path="core.py", line_start=30),
            source_engine="complexity",
            risk_priority="monitor",
        ),

    ]
    metrics = [
        Metric(
            target_id="project",
            target_type="project",
            metric_name=MetricNames.LOC,
            value=120.0,
            unit="lines",
            source_engine="structure",
            dimension="scale",
        ),
        Metric(
            target_id="project",
            target_type="project",
            metric_name=MetricNames.CYCLOMATIC_COMPLEXITY,
            value=12.0,
            unit="average",
            source_engine="complexity",
            dimension="complexity",
        ),
    ]

    scores = build_dimension_scores(findings, metrics)
    by_dimension = {score.dimension: score for score in scores}

    assert set(by_dimension) >= {"scale", "complexity", "security"}
    assert by_dimension["scale"].score == 100.0
    assert by_dimension["complexity"].findings_count == 1
    assert by_dimension["complexity"].metrics[0].metric_name == MetricNames.CYCLOMATIC_COMPLEXITY
    assert by_dimension["security"].score < by_dimension["complexity"].score
    assert by_dimension["security"].top_issues == ["Critical secret leak"]
