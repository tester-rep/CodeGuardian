"""ReleaseGate — evaluates quality gate rules and produces pass/fail verdict.

Supports both programmatic rule evaluation and YAML-based gate configuration.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

from codeguardian.config.loader import load_gate_yaml
from codeguardian.models.enums import Severity
from codeguardian.models.metric import MetricNames
from codeguardian.models.scan import ScanResult
from codeguardian.risk.scorer import RiskScorer


_OR_SPLIT_RE = re.compile(r"\s+or\s+", re.IGNORECASE)
_AND_SPLIT_RE = re.compile(r"\s+and\s+", re.IGNORECASE)


@dataclass
class GateEvaluation:
    """Result of quality gate evaluation."""

    passed: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: dict[str, float | bool] = field(default_factory=dict)



class GateRule(BaseModel):
    """A single gate rule definition."""

    name: str
    condition: str  # Expression like "project.overall_score >= 60"
    action: str  # fail / warn / info
    message: str = ""


class ReleaseGate:
    """Evaluates whether a project passes release quality gates."""

    def __init__(self, threshold: float = 60.0):
        self.threshold = threshold
        self.rules: list[GateRule] = []

    def load_rules(self, config_path: str | Path) -> None:
        """Load gate rules from a YAML file."""
        raw = load_gate_yaml(str(config_path))
        rules_data = raw.get("quality_gate", {}).get("rules", [])
        self.rules = [GateRule(**rule) for rule in rules_data]

    def evaluate(self, result: ScanResult) -> GateEvaluation:
        """Evaluate all gate rules against scan result."""
        reasons: list[str] = []

        production_findings, test_findings = self._partition_findings(result.findings)
        production_modules, test_modules = self._partition_modules(result.project_profile.modules)
        production_score = RiskScorer().score(production_findings)

        blocking_count = sum(1 for finding in production_findings if finding.is_blocking)
        high_count = sum(1 for finding in production_findings if finding.severity == Severity.HIGH)
        critical_security = sum(
            1
            for finding in production_findings
            if finding.category == "security" and finding.severity == Severity.CRITICAL
        )

        if production_score < self.threshold:
            reasons.append(
                f"Production overall score ({production_score:.0f}) "
                f"is below threshold ({self.threshold})"
            )
        if blocking_count > 0:
            reasons.append(f"There are {blocking_count} production blocking findings")
        if critical_security > 0:
            reasons.append(f"There are {critical_security} production critical security findings")

        facts = self._condition_facts(
            result,
            production_findings=production_findings,
            test_findings=test_findings,
            production_modules=production_modules,
            test_modules=test_modules,
            production_score=production_score,
            blocking_count=blocking_count,
            high_count=high_count,
            critical_security=critical_security,
        )
        warnings: list[str] = []
        for rule in self.rules:
            passed = self._evaluate_condition(rule.condition, facts)
            action = rule.action.strip().lower()
            if not passed and action in {"fail", "warn"}:
                actual = self._resolve_actual_value(rule.condition, facts)
                format_values = self._message_values(actual, facts, blocking_count, critical_security, high_count)
                try:
                    message = rule.message.format(**format_values)
                except (KeyError, ValueError):
                    message = rule.message
                if action == "fail":
                    if message and message not in reasons:
                        reasons.append(message)
                elif message and message not in warnings:
                    warnings.append(message)

        return GateEvaluation(passed=len(reasons) == 0, reasons=reasons, warnings=warnings, facts=facts)



    @staticmethod
    def _condition_facts(
        result: ScanResult,
        production_findings: list,
        test_findings: list,
        production_modules: list,
        test_modules: list,
        production_score: float,
        blocking_count: int,
        high_count: int,
        critical_security: int,
    ) -> dict[str, float | bool]:
        project_metrics = {
            metric.metric_name: metric.value
            for metric in result.metrics
            if metric.target_id == "project"
        }
        priority_counts = Counter(finding.risk_priority for finding in production_findings)
        critical_count = sum(1 for finding in production_findings if finding.severity == Severity.CRITICAL)
        line_coverage_available = MetricNames.LINE_COVERAGE in project_metrics
        line_coverage = float(project_metrics.get(MetricNames.LINE_COVERAGE, 0.0))
        branch_coverage = float(project_metrics.get(MetricNames.BRANCH_COVERAGE, 0.0))
        function_coverage = float(project_metrics.get(MetricNames.FUNCTION_COVERAGE, 0.0))
        change_coverage = float(project_metrics.get(MetricNames.CHANGE_LINE_COVERAGE, 0.0))
        core_module_score = float(project_metrics.get(MetricNames.CORE_MODULE_SCORE, production_score))
        duplication_rate = float(project_metrics.get(MetricNames.DUPLICATION_RATE, 0.0))
        avg_cyclomatic = float(project_metrics.get(MetricNames.CYCLOMATIC_COMPLEXITY, 0.0))
        avg_cognitive = float(project_metrics.get(MetricNames.COGNITIVE_COMPLEXITY, 0.0))
        maintainability_index = float(project_metrics.get(MetricNames.MAINTAINABILITY_INDEX, 0.0))
        churn_score = float(project_metrics.get(MetricNames.CHURN_SCORE, 0.0))

        worst_module_score = min((module.risk_score for module in production_modules), default=production_score)
        high_risk_modules = sum(1 for module in production_modules if module.risk_level in {"high", "critical"})
        critical_modules = sum(1 for module in production_modules if module.risk_level == "critical")
        blocking_modules = sum(1 for module in production_modules if any(finding.is_blocking for finding in module.findings))
        high_cc_functions = sum(
            1
            for metric in result.metrics
            if metric.target_type == "function"
            and metric.metric_name == MetricNames.CYCLOMATIC_COMPLEXITY
            and metric.value >= 15
        )
        test_blocking = sum(1 for finding in test_findings if finding.is_blocking)

        return {
            "project.overall_score": production_score,
            "project.total_files": float(result.project_profile.total_files),
            "project.total_loc": float(result.project_profile.total_loc),
            "findings.total": float(len(production_findings)),
            "findings.blocking": float(blocking_count),
            "findings.critical": float(critical_count),
            "findings.high": float(high_count),
            "findings.must_fix": float(priority_counts.get("must-fix", 0)),
            "findings.should_fix": float(priority_counts.get("should-fix", 0)),
            "security.critical": float(critical_security),
            "blocking_issues": float(blocking_count),
            "scope.production_findings": float(len(production_findings)),
            "scope.test_findings": float(len(test_findings)),
            "scope.production_blocking": float(blocking_count),
            "scope.test_blocking": float(test_blocking),
            "scope.production_modules": float(len(production_modules)),
            "scope.test_modules": float(len(test_modules)),
            "test.coverage_line": line_coverage,
            "test.line_coverage": line_coverage,
            "test.coverage_branch": branch_coverage,
            "test.branch_coverage": branch_coverage,
            "test.coverage_function": function_coverage,
            "test.function_coverage": function_coverage,
            "test.coverage_change": change_coverage,
            "test.unavailable": not line_coverage_available,
            "duplication.overall_ratio": duplication_rate,
            "duplication.new_ratio": duplication_rate,
            "complexity.avg_cyclomatic": avg_cyclomatic,
            "complexity.avg_cc": avg_cyclomatic,
            "complexity.avg_cognitive": avg_cognitive,
            "complexity.new_high_cc": float(high_cc_functions),
            "complexity.high_cc_functions": float(high_cc_functions),
            "maintainability.index": maintainability_index,
            "evolution.churn_score": churn_score,
            "risk.core_module_score": core_module_score,
            "risk.top_module_score": worst_module_score,
            "risk.worst_module_score": worst_module_score,
            "risk.high_risk_modules": float(high_risk_modules),
            "risk.critical_modules": float(critical_modules),
            "risk.blocking_modules": float(blocking_modules),
        }

    @staticmethod
    def _partition_findings(findings: list) -> tuple[list, list]:
        production_findings = []
        test_findings = []
        for finding in findings:
            if ReleaseGate._is_test_path(getattr(finding.location, "file_path", "")):
                test_findings.append(finding)
            else:
                production_findings.append(finding)
        return production_findings, test_findings

    @staticmethod
    def _partition_modules(modules: list) -> tuple[list, list]:
        production_modules = []
        test_modules = []
        for module in modules:
            if ReleaseGate._is_test_path(getattr(module, "path", "")):
                test_modules.append(module)
            else:
                production_modules.append(module)
        return production_modules, test_modules

    @staticmethod
    def _is_test_path(path: str | None) -> bool:
        normalized = (path or "").replace("\\", "/").lower()
        name = Path(normalized).name
        return (
            "/tests/" in f"/{normalized}"
            or "/__tests__/" in f"/{normalized}"
            or normalized in {"tests", "test"}
            or name.startswith("test_")
            or name.endswith("_test.py")
            or ".spec." in name
            or ".test." in name
        )

    def _evaluate_condition(self, condition: str, facts: dict[str, float | bool]) -> bool:

        """Evaluate a simple gate condition expression."""
        return any(self._evaluate_and_group(group, facts) for group in _OR_SPLIT_RE.split(condition.strip()) if group.strip())

    def _evaluate_and_group(self, condition: str, facts: dict[str, float | bool]) -> bool:
        return all(self._evaluate_atom(atom, facts) for atom in _AND_SPLIT_RE.split(condition.strip()) if atom.strip())

    def _evaluate_atom(self, condition: str, facts: dict[str, float | bool]) -> bool:
        expr = condition.replace(" ", "")
        for key in sorted(facts, key=len, reverse=True):
            op_val = self._extract_op_value(expr, key)
            if op_val is None:
                continue
            op, expected = op_val
            return _compare(facts[key], op, expected)
        return True

    @staticmethod
    def _resolve_actual_value(condition: str, facts: dict[str, float | bool]) -> float | bool | None:
        expr = condition.replace(" ", "")
        for key in sorted(facts, key=len, reverse=True):
            if expr.startswith(key):
                return facts[key]
        return None

    @classmethod
    def _message_values(
        cls,
        actual: float | bool | None,
        facts: dict[str, float | bool],
        blocking_count: int,
        critical_security: int,
        high_count: int,
    ) -> dict[str, str]:
        values = {
            "actual": cls._format_fact_value(actual),
            "blocking": str(blocking_count),
            "critical": str(critical_security),
            "high": str(high_count),
            "total": str(int(facts.get("findings.total", 0) or 0)),
        }
        for key, value in facts.items():
            values[key.replace(".", "_")] = cls._format_fact_value(value)
        return values

    @staticmethod
    def _format_fact_value(value: float | bool | None) -> str:
        if value is None:
            return "unknown"
        if isinstance(value, bool):
            return str(value).lower()
        return f"{float(value):.1f}"

    @staticmethod
    def _extract_op_value(expr: str, key: str) -> tuple[str, float | bool] | None:
        """Extract operator and value from an expression like 'key>=val'."""
        if not expr.startswith(key):
            return None

        remainder = expr[len(key):]
        for operator in (">=", "<=", "==", "!=", ">", "<"):
            if not remainder.startswith(operator):
                continue
            try:
                return (operator, _parse_condition_value(remainder[len(operator):]))
            except ValueError:
                return None
        return None


def _parse_condition_value(raw: str) -> float | bool:
    value = raw.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.endswith("%"):
        value = value[:-1]
    return float(value)


def _compare(actual: float | bool, op: str, expected: float | bool) -> bool:
    if isinstance(expected, bool):
        actual_bool = actual if isinstance(actual, bool) else bool(actual)
        bool_ops = {
            "==": actual_bool == expected,
            "!=": actual_bool != expected,
        }
        return bool_ops.get(op, False)

    actual_num = float(actual)
    expected_num = float(expected)
    ops = {
        ">=": actual_num >= expected_num,
        ">": actual_num > expected_num,
        "<=": actual_num <= expected_num,
        "<": actual_num < expected_num,
        "==": abs(actual_num - expected_num) < 0.001,
        "!=": abs(actual_num - expected_num) >= 0.001,
    }
    return ops.get(op, False)
