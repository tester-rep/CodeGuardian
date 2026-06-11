"""Tests for the composite heuristic risk scorer."""

from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.risk.scorer import RiskScorer


def _make_finding(
    *,
    fid: str,
    severity: Severity,
    category: str = "defect",
    file_path: str = "src/app.py",
    blocks_release: bool = False,
    risk_priority: str = "should-fix",
) -> Finding:
    return Finding(
        id=fid,
        title=f"{severity.value} issue {fid}",
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        location=Location(file_path=file_path, line_start=1, line_end=1),
        source_engine=category,
        risk_priority=risk_priority,
        blocks_release=blocks_release,
    )


def test_risk_scorer_penalizes_blocking_core_security_more_than_low_testing_issue() -> None:
    scorer = RiskScorer()
    security_finding = Finding(
        id="SEC-001",
        title="SQL injection in core API",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        location=Location(file_path="src/core/api.py", line_start=12, line_end=12),
        source_engine="security",
        rule_id="SQL-INJECTION-RISK",
        risk_priority="must-fix",
        blocks_release=True,
        tags=["hotspot", "api"],
    )
    testing_finding = Finding(
        id="TEST-001",
        title="Missing smoke test",
        category="testing",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="tests/test_quality.py", line_start=5, line_end=5),
        source_engine="testing",
        rule_id="MISSING-TEST",
        risk_priority="monitor",
    )

    security_score = scorer.score([security_finding])
    testing_score = scorer.score([testing_finding])

    assert security_score < testing_score
    assert security_finding.score_impact > testing_finding.score_impact > 0


def test_risk_scorer_uses_path_tokens_for_core_detection() -> None:
    scorer = RiskScorer()
    core_module_issue = Finding(
        id="SEC-002",
        title="Critical auth bypass",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        location=Location(file_path="src/core/auth.py", line_start=8, line_end=8),
        source_engine="security",
    )
    filename_only_issue = Finding(
        id="CMP-002",
        title="Deeply nested helper",
        category="maintainability",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        location=Location(file_path="core.py", line_start=8, line_end=8),
        source_engine="complexity",
        risk_priority="monitor",
    )


    core_score = scorer.score([core_module_issue])
    filename_only_score = scorer.score([filename_only_issue])

    assert core_score < filename_only_score


def test_single_medium_finding_does_not_collapse_score() -> None:
    """Regression: previously a single medium finding could deduct ~62
    points and (with future additions) easily push the score to 0. With
    hyperbolic-decay aggregation, one medium finding must remain in the
    healthy band."""
    scorer = RiskScorer()
    score = scorer.score([_make_finding(fid="DEF-1", severity=Severity.MEDIUM)])
    assert score >= 75, f"single medium should stay 'good', got {score}"


def test_many_findings_do_not_flatline_to_zero() -> None:
    """Regression for the spr_robot_java case: 16 high + 37 medium findings
    used to produce a hard 0 because deductions were summed linearly with
    no saturation. With hyperbolic decay the score must drop into the
    'critical' band but stay strictly positive so the report remains
    informative (e.g. trend comparisons across runs)."""
    scorer = RiskScorer()
    findings = [
        _make_finding(fid=f"HIGH-{i}", severity=Severity.HIGH, blocks_release=False)
        for i in range(16)
    ] + [
        _make_finding(fid=f"MED-{i}", severity=Severity.MEDIUM)
        for i in range(37)
    ]

    score = scorer.score(findings)

    assert 0.0 < score < 40.0, (
        f"heavy issue load should be 'critical' but non-zero, got {score}"
    )


def test_score_is_monotonically_decreasing_with_more_findings() -> None:
    """Adding findings should never improve the score."""
    scorer = RiskScorer()
    one = scorer.score([_make_finding(fid="A", severity=Severity.HIGH)])
    two = scorer.score([
        _make_finding(fid="A", severity=Severity.HIGH),
        _make_finding(fid="B", severity=Severity.HIGH),
    ])
    assert two < one


