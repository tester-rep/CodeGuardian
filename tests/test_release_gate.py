"""Tests for release gate condition evaluation."""

from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric, MetricNames
from codeguardian.models.profile import ModuleProfile, ProjectProfile
from codeguardian.models.scan import ScanResult
from codeguardian.risk.release_gate import GateRule, ReleaseGate


def test_release_gate_evaluates_common_conditions() -> None:
    gate = ReleaseGate()
    gate.rules = [
        GateRule(name="minimum_score", condition="project.overall_score >= 60", action="fail", message="score low"),
        GateRule(name="no_blocking", condition="findings.blocking == 0", action="fail", message="blocking findings"),
        GateRule(name="no_critical_security", condition="security.critical == 0", action="fail", message="critical security"),
        GateRule(name="no_high_findings", condition="findings.high <= 0", action="fail", message="high findings"),
    ]

    finding = Finding(
        id="SEC-001",
        title="SQL injection",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        location=Location(file_path="sample.py", line_start=10, line_end=10),
        source_engine="security",
        rule_id="SQL-INJECTION-RISK",
        blocks_release=True,
    )
    result = ScanResult(
        project_profile=ProjectProfile(project_name="demo", overall_score=55.0),
        findings=[finding],
    )

    evaluation = gate.evaluate(result)

    assert not evaluation.passed
    assert "score low" in evaluation.reasons
    assert "blocking findings" in evaluation.reasons
    assert "critical security" in evaluation.reasons



def test_release_gate_supports_core_module_score_and_change_coverage_conditions() -> None:
    gate = ReleaseGate()
    gate.rules = [
        GateRule(
            name="core_module_score",
            condition="risk.core_module_score >= 75",
            action="fail",
            message="core module score too low ({actual})",
        ),
        GateRule(
            name="change_coverage",
            condition="test.coverage_change >= 80",
            action="warn",
            message="change coverage too low ({actual})",
        ),
    ]

    result = ScanResult(
        project_profile=ProjectProfile(project_name="demo", overall_score=82.0),
        findings=[],
        metrics=[
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.CORE_MODULE_SCORE,
                value=72.0,
                unit="score",
                source_engine="risk",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.CHANGE_LINE_COVERAGE,
                value=65.0,
                unit="%",
                source_engine="testing",
            ),
        ],
    )

    evaluation = gate.evaluate(result)

    assert not evaluation.passed
    assert "core module score too low (72.0)" in evaluation.reasons
    assert "change coverage too low (65.0)" not in evaluation.reasons
    assert "change coverage too low (65.0)" in evaluation.warnings




def test_release_gate_supports_boolean_or_conditions_for_unavailable_coverage() -> None:
    gate = ReleaseGate()
    gate.rules = [
        GateRule(
            name="coverage_optional",
            condition="test.line_coverage >= 70 or test.unavailable == true",
            action="warn",
            message="coverage unavailable rule should pass",
        )
    ]

    result = ScanResult(
        project_profile=ProjectProfile(project_name="demo", overall_score=82.0),
        findings=[],
        metrics=[],
    )

    evaluation = gate.evaluate(result)

    assert evaluation.passed
    assert evaluation.facts["test.unavailable"] is True



def test_release_gate_warn_rule_does_not_fail_gate() -> None:
    gate = ReleaseGate(threshold=0.0)
    gate.rules = [
        GateRule(
            name="coverage_warn",
            condition="test.line_coverage >= 80",
            action="warn",
            message="coverage too low ({actual})",
        )
    ]
    result = ScanResult(
        project_profile=ProjectProfile(project_name="demo", overall_score=82.0),
        metrics=[
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.LINE_COVERAGE,
                value=60.0,
                unit="%",
                source_engine="testing",
            )
        ],
    )

    evaluation = gate.evaluate(result)

    assert evaluation.passed
    assert evaluation.reasons == []
    assert evaluation.warnings == ["coverage too low (60.0)"]



def test_release_gate_ignores_test_only_findings_for_score_and_blocking() -> None:

    gate = ReleaseGate()
    gate.rules = [
        GateRule(name="minimum_score", condition="project.overall_score >= 60", action="fail", message="score low"),
        GateRule(name="no_blocking", condition="findings.blocking == 0", action="fail", message="blocking findings"),
    ]

    finding = Finding(
        id="DEF-001",
        title="Bare except catches every exception",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="tests/test_defect_engine_rules.py", line_start=10, line_end=10),
        source_engine="defect",
        rule_id="BARE-EXCEPT",
    )
    result = ScanResult(
        project_profile=ProjectProfile(project_name="demo", overall_score=0.0),
        findings=[finding],
    )

    evaluation = gate.evaluate(result)

    assert evaluation.passed
    assert evaluation.facts["project.overall_score"] == 100.0
    assert evaluation.facts["findings.blocking"] == 0.0
    assert evaluation.facts["scope.production_findings"] == 0.0
    assert evaluation.facts["scope.test_findings"] == 1.0
    assert evaluation.facts["scope.test_blocking"] == 0.0






def test_release_gate_does_not_block_on_high_maintainability_findings() -> None:
    gate = ReleaseGate(threshold=0.0)

    gate.rules = [
        GateRule(name="no_blocking", condition="findings.blocking == 0", action="fail", message="blocking findings"),
    ]

    finding = Finding(
        id="CMP-001",
        title="Long and complex function",
        category="maintainability",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="src/service.py", line_start=10, line_end=140),
        source_engine="complexity",
        rule_id="HIGH-CC-FUNCTION",
        risk_priority="must-fix",
    )
    result = ScanResult(
        project_profile=ProjectProfile(project_name="demo", overall_score=82.0),
        findings=[finding],
    )

    evaluation = gate.evaluate(result)

    assert evaluation.passed
    assert finding.is_blocking is False
    assert evaluation.facts["findings.blocking"] == 0.0
    assert evaluation.facts["findings.high"] == 1.0
    assert evaluation.facts["findings.must_fix"] == 1.0



def test_release_gate_keeps_explicit_and_security_blockers() -> None:
    explicit = Finding(
        id="SEC-001",
        title="Potential SQL injection",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="src/service.py", line_start=10, line_end=10),
        source_engine="security",
        rule_id="SQL-INJECTION-RISK",
        blocks_release=True,
    )
    high_security = Finding(
        id="SEC-002",
        title="Dynamic code execution",
        category="security",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="src/service.py", line_start=20, line_end=20),
        source_engine="security",
        rule_id="EVAL-USAGE",
    )
    high_defect = Finding(
        id="DEF-001",
        title="Bare except catches every exception",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="src/service.py", line_start=30, line_end=30),
        source_engine="defect",
        rule_id="BARE-EXCEPT",
    )

    assert explicit.is_blocking is True
    assert high_security.is_blocking is True
    assert high_defect.is_blocking is False



def test_release_gate_supports_advanced_fact_aliases_and_percent_thresholds() -> None:

    gate = ReleaseGate()
    gate.rules = [
        GateRule(
            name="duplication_limit",
            condition="duplication.overall_ratio <= 5%",
            action="warn",
            message="duplication too high ({actual})",
        ),
        GateRule(
            name="new_high_cc",
            condition="complexity.new_high_cc <= 1",
            action="warn",
            message="too many high complexity functions ({actual})",
        ),
        GateRule(
            name="high_risk_modules",
            condition="risk.high_risk_modules <= 0",
            action="fail",
            message="high risk modules present ({actual})",
        ),
        GateRule(
            name="blocking_alias",
            condition="blocking_issues == 0",
            action="fail",
            message="blocking alias triggered ({actual})",
        ),
    ]

    result = ScanResult(
        project_profile=ProjectProfile(
            project_name="demo",
            overall_score=82.0,
            modules=[
                ModuleProfile(
                    name="api",
                    path="core/api",
                    risk_score=58.0,
                    risk_level="high",
                )
            ],
        ),
        findings=[],
        metrics=[
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.DUPLICATION_RATE,
                value=7.5,
                unit="%",
                source_engine="metrics",
            ),
            Metric(
                target_id="fn:a",
                target_type="function",
                metric_name=MetricNames.CYCLOMATIC_COMPLEXITY,
                value=18.0,
                unit="score",
                source_engine="complexity",
            ),
            Metric(
                target_id="fn:b",
                target_type="function",
                metric_name=MetricNames.CYCLOMATIC_COMPLEXITY,
                value=22.0,
                unit="score",
                source_engine="complexity",
            ),
        ],
    )

    evaluation = gate.evaluate(result)

    assert not evaluation.passed
    assert evaluation.facts["duplication.overall_ratio"] == 7.5
    assert evaluation.facts["complexity.new_high_cc"] == 2.0
    assert evaluation.facts["risk.high_risk_modules"] == 1.0
    assert "duplication too high (7.5)" not in evaluation.reasons
    assert "too many high complexity functions (2.0)" not in evaluation.reasons
    assert "duplication too high (7.5)" in evaluation.warnings
    assert "too many high complexity functions (2.0)" in evaluation.warnings
    assert "high risk modules present (1.0)" in evaluation.reasons




