"""TestingEngine — ingests coverage reports and detects test quality issues.

Capabilities:
- Parse `coverage.py` JSON/XML reports
- Emit project/file coverage metrics
- Emit low-coverage findings for testing dimension
- Detect test functions without assertions (empty tests / mock-only tests)
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from codeguardian.core.context import ScanContext
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric, MetricNames
from codeguardian.models.scan import EngineResult
from codeguardian.utils.ignore import should_ignore

_DEFAULT_COVERAGE_FILES = ("coverage.json", "coverage.xml")
_BRANCH_COVERAGE_RE = re.compile(r"\((\d+)/(\d+)\)")
_LOW_PROJECT_COVERAGE = 80.0
_LOW_FILE_COVERAGE = 60.0


@dataclass(slots=True)
class CoverageSummary:
    file_path: str
    covered_lines: int = 0
    total_lines: int = 0
    covered_branches: int = 0
    total_branches: int = 0
    covered_functions: int = 0
    total_functions: int = 0
    executed_lines_set: set[int] | None = None
    missing_lines_set: set[int] | None = None


    @property
    def line_coverage(self) -> float:
        return _safe_percent(self.covered_lines, self.total_lines)

    @property
    def branch_coverage(self) -> float:
        return _safe_percent(self.covered_branches, self.total_branches)

    @property
    def function_coverage(self) -> float:
        return _safe_percent(self.covered_functions, self.total_functions)


class TestingEngine:
    """Analyze test coverage reports and convert them into testing metrics."""

    name = "testing"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root)
        coverage_paths, warnings = self._resolve_coverage_paths(root, ctx.config.test.coverage_files)

        coverage_by_file: dict[str, CoverageSummary] = {}
        if coverage_paths:
            for coverage_path in coverage_paths:
                try:
                    parsed = self._parse_report(coverage_path, root)
                except (ET.ParseError, ValueError, json.JSONDecodeError) as exc:
                    warnings.append(f"Failed to parse coverage report {coverage_path.name}: {exc}")
                    continue
                for summary in parsed:
                    coverage_by_file[summary.file_path] = summary

        metrics: list[Metric] = []
        findings: list[Finding] = []

        if coverage_by_file:
            metrics = self._build_metrics(coverage_by_file, ctx)
            findings = self._build_findings(coverage_by_file, ctx)
        elif not coverage_paths:
            warnings.append(
                "No coverage report found — configure test.coverage_files or place coverage.json/coverage.xml at project root"
            )

        # Detect tests without assertions (independent of coverage)
        assertion_findings = self._detect_tests_without_assertions(root, ctx)
        findings.extend(assertion_findings)

        return EngineResult(engine_name=self.name, metrics=metrics, findings=findings, warnings=warnings)


    def _resolve_coverage_paths(self, root: Path, configured_paths: list[str]) -> tuple[list[Path], list[str]]:
        warnings: list[str] = []
        candidates = configured_paths or list(_DEFAULT_COVERAGE_FILES)
        resolved_paths: list[Path] = []

        for candidate in candidates:
            path = Path(candidate)
            if not path.is_absolute():
                path = root / path
            path = path.resolve()

            if not path.exists():
                if configured_paths:
                    warnings.append(f"Coverage report not found: {path}")
                continue
            if path.suffix.lower() not in {".json", ".xml"}:
                warnings.append(f"Unsupported coverage report format: {path.name}")
                continue
            resolved_paths.append(path)

        unique_paths = list(dict.fromkeys(resolved_paths))
        return unique_paths, warnings

    def _parse_report(self, coverage_path: Path, root: Path) -> list[CoverageSummary]:
        if coverage_path.suffix.lower() == ".json":
            return self._parse_json_report(coverage_path, root)
        if coverage_path.suffix.lower() == ".xml":
            return self._parse_xml_report(coverage_path, root)
        raise ValueError(f"Unsupported coverage report format: {coverage_path.suffix}")

    def _parse_json_report(self, coverage_path: Path, root: Path) -> list[CoverageSummary]:
        payload = json.loads(coverage_path.read_text(encoding="utf-8"))
        files = payload.get("files")
        if not isinstance(files, dict):
            raise ValueError("missing 'files' map")

        summaries: list[CoverageSummary] = []
        for source_path, file_payload in files.items():
            if not isinstance(file_payload, dict):
                continue
            summary = file_payload.get("summary") or {}
            missing_lines = file_payload.get("missing_lines") or summary.get("missing_lines") or []
            executed_lines = file_payload.get("executed_lines") or []
            executed_line_set = {line for line in executed_lines if isinstance(line, int)}
            missing_line_set = {line for line in missing_lines if isinstance(line, int)}

            total_lines = _coerce_int(summary.get("num_statements"))
            covered_lines = _coerce_int(summary.get("covered_lines"))
            if total_lines == 0 and (executed_line_set or missing_line_set):
                total_lines = len(executed_line_set) + len(missing_line_set)
            if covered_lines == 0 and total_lines and missing_line_set:
                covered_lines = max(total_lines - len(missing_line_set), 0)


            total_branches = _coerce_int(summary.get("num_branches"))
            covered_branches = _coerce_int(summary.get("covered_branches"))
            total_functions = _coerce_int(summary.get("num_functions"))
            covered_functions = _coerce_int(summary.get("covered_functions"))

            if total_lines == total_branches == total_functions == 0:
                continue

            summaries.append(
                CoverageSummary(
                    file_path=_normalize_source_path(source_path, root),
                    covered_lines=covered_lines,
                    total_lines=total_lines,
                    covered_branches=covered_branches,
                    total_branches=total_branches,
                    covered_functions=covered_functions,
                    total_functions=total_functions,
                    executed_lines_set=executed_line_set,
                    missing_lines_set=missing_line_set,
                )

            )

        return summaries

    def _parse_xml_report(self, coverage_path: Path, root: Path) -> list[CoverageSummary]:
        document = ET.parse(coverage_path)
        summaries: list[CoverageSummary] = []

        for class_node in document.findall(".//class"):
            file_name = class_node.get("filename")
            if not file_name:
                continue

            line_nodes = class_node.findall("./lines/line") or class_node.findall(".//line")
            total_lines = len(line_nodes)
            covered_lines = sum(1 for line in line_nodes if _coerce_int(line.get("hits")) > 0)

            total_branches = 0
            covered_branches = 0
            for line in line_nodes:
                if line.get("branch") != "true":
                    continue
                match = _BRANCH_COVERAGE_RE.search(line.get("condition-coverage", ""))
                if not match:
                    continue
                covered_branches += int(match.group(1))
                total_branches += int(match.group(2))

            methods = class_node.findall("./methods/method")
            total_functions = len(methods)
            covered_functions = sum(1 for method in methods if float(method.get("line-rate", "0") or 0) > 0)

            if total_lines == total_branches == total_functions == 0:
                continue

            summaries.append(
                CoverageSummary(
                    file_path=_normalize_source_path(file_name, root),
                    covered_lines=covered_lines,
                    total_lines=total_lines,
                    covered_branches=covered_branches,
                    total_branches=total_branches,
                    covered_functions=covered_functions,
                    total_functions=total_functions,
                    executed_lines_set={_coerce_int(line.get("number")) for line in line_nodes if _coerce_int(line.get("hits")) > 0},
                    missing_lines_set={_coerce_int(line.get("number")) for line in line_nodes if _coerce_int(line.get("hits")) <= 0},
                )
            )


        return summaries

    def _build_metrics(self, coverage_by_file: dict[str, CoverageSummary], ctx: ScanContext) -> list[Metric]:
        metrics: list[Metric] = []
        project = CoverageSummary(file_path="project")

        for file_path, summary in sorted(coverage_by_file.items()):
            project.covered_lines += summary.covered_lines
            project.total_lines += summary.total_lines
            project.covered_branches += summary.covered_branches
            project.total_branches += summary.total_branches
            project.covered_functions += summary.covered_functions
            project.total_functions += summary.total_functions

            metrics.append(self._metric(file_path, "file", MetricNames.LINE_COVERAGE, summary.line_coverage))
            if summary.total_branches > 0:
                metrics.append(self._metric(file_path, "file", MetricNames.BRANCH_COVERAGE, summary.branch_coverage))
            if summary.total_functions > 0:
                metrics.append(self._metric(file_path, "file", MetricNames.FUNCTION_COVERAGE, summary.function_coverage))

        metrics.append(self._metric("project", "project", MetricNames.LINE_COVERAGE, project.line_coverage))
        if project.total_branches > 0:
            metrics.append(self._metric("project", "project", MetricNames.BRANCH_COVERAGE, project.branch_coverage))
        if project.total_functions > 0:
            metrics.append(self._metric("project", "project", MetricNames.FUNCTION_COVERAGE, project.function_coverage))

        change_coverage = self._build_change_coverage_metric(coverage_by_file, ctx)
        if change_coverage is not None:
            metrics.append(change_coverage)

        return metrics


    def _build_findings(self, coverage_by_file: dict[str, CoverageSummary], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        counter = 1

        project = CoverageSummary(file_path="project")
        for summary in coverage_by_file.values():
            project.covered_lines += summary.covered_lines
            project.total_lines += summary.total_lines

        if project.total_lines > 0 and project.line_coverage < _LOW_PROJECT_COVERAGE:
            findings.append(
                self._finding(
                    finding_id=f"TEST-{counter:03d}",
                    title="项目行覆盖率低于目标 (Project line coverage below target)",
                    rule_id="LOW-PROJECT-COVERAGE",
                    severity=Severity.HIGH if project.line_coverage < 60 else Severity.MEDIUM,
                    file_path="project",
                    detail=f"当前项目行覆盖率为 {project.line_coverage:.1f}%，低于目标值 {_LOW_PROJECT_COVERAGE:.0f}%。",
                    fix_suggestion="优先为核心路径、高变更文件和异常处理分支补充缺失测试。",
                    test_suggestion="添加测试后重新生成覆盖率，并确认行覆盖率达到预期阈值。",
                )
            )
            counter += 1

        weakest_files = sorted(
            (
                summary
                for summary in coverage_by_file.values()
                if summary.total_lines > 0 and summary.line_coverage < _LOW_FILE_COVERAGE and not _looks_like_test_file(summary.file_path)
            ),
            key=lambda summary: (summary.line_coverage, -summary.total_lines, summary.file_path),
        )[:10]

        for summary in weakest_files:
            findings.append(
                self._finding(
                    finding_id=f"TEST-{counter:03d}",
                    title=f"文件 {summary.file_path} 行覆盖率偏低 (Low line coverage)",
                    rule_id="LOW-FILE-COVERAGE",
                    severity=Severity.HIGH if summary.line_coverage < 20 else Severity.MEDIUM,
                    file_path=summary.file_path,
                    detail=f"{summary.file_path} 行覆盖率为 {summary.line_coverage:.1f}% ({summary.covered_lines}/{summary.total_lines})。",
                    fix_suggestion="为该文件的主要分支和失败路径补充有针对性的单元测试。",
                    test_suggestion="发布前覆盖正常路径、边界输入和异常流程。",
                )
            )
            counter += 1

        change_coverage = self._calculate_change_coverage(coverage_by_file, ctx.changed_lines)
        if change_coverage is not None and change_coverage < _LOW_PROJECT_COVERAGE:
            findings.append(
                self._finding(
                    finding_id=f"TEST-{counter:03d}",
                    title="变更代码行覆盖率低于目标 (Changed line coverage below target)",
                    rule_id="LOW-CHANGE-COVERAGE",
                    severity=Severity.HIGH if change_coverage < 60 else Severity.MEDIUM,
                    file_path="project",
                    detail=f"变更代码行覆盖率为 {change_coverage:.1f}%，低于目标值 {_LOW_PROJECT_COVERAGE:.0f}%。",
                    fix_suggestion="优先为本次改动涉及的分支、异常路径和回归风险点补测试。",
                    test_suggestion="重新生成覆盖率并确认变更代码覆盖率达到发布阈值。",
                )
            )

        return findings

    def _build_change_coverage_metric(self, coverage_by_file: dict[str, CoverageSummary], ctx: ScanContext) -> Metric | None:
        change_coverage = self._calculate_change_coverage(coverage_by_file, ctx.changed_lines)
        if change_coverage is None:
            return None
        return self._metric("project", "project", MetricNames.CHANGE_LINE_COVERAGE, change_coverage)

    @staticmethod
    def _calculate_change_coverage(
        coverage_by_file: dict[str, CoverageSummary],
        changed_lines: dict[str, list[int]],
    ) -> float | None:
        if not changed_lines:
            return None

        total_changed = 0
        covered_changed = 0
        for file_path, line_numbers in changed_lines.items():
            summary = coverage_by_file.get(file_path)
            if summary is None:
                continue
            executed = summary.executed_lines_set or set()
            missing = summary.missing_lines_set or set()
            if not executed and not missing:
                continue

            normalized_lines = {line_no for line_no in line_numbers if line_no > 0}
            total_changed += len(normalized_lines)
            covered_changed += len(normalized_lines & executed)

        if total_changed <= 0:
            return None
        return _safe_percent(covered_changed, total_changed)

    def _metric(self, target_id: str, target_type: str, metric_name: str, value: float) -> Metric:

        return Metric(
            target_id=target_id,
            target_type=target_type,
            metric_name=metric_name,
            value=round(value, 1),
            unit="%",
            source_engine=self.name,
            dimension="testing",
        )

    def _finding(
        self,
        finding_id: str,
        title: str,
        rule_id: str,
        severity: Severity,
        file_path: str,
        detail: str,
        fix_suggestion: str,
        test_suggestion: str,
    ) -> Finding:
        return Finding(
            id=finding_id,
            title=title,
            category="testing",
            severity=severity,
            confidence=Confidence.HIGH,
            location=Location(file_path=file_path, line_start=1, line_end=1),
            source_engine=self.name,
            rule_id=rule_id,
            impact="覆盖率不足会增加回归风险，并削弱发布前对关键路径的保护。",
            fix_suggestion=fix_suggestion,
            test_suggestion=test_suggestion,
            root_cause=detail,
            risk_priority="must-fix" if severity == Severity.HIGH else "should-fix",
        )

    # ── Tests without assertions detection ────────────────────────────

    # Assertion patterns by language
    _ASSERTION_PATTERNS = re.compile(
        r"\b(?:assert|assertEqual|assertRaises|assertIn|assertIs|assertTrue|assertFalse"
        r"|assertIsNone|assertIsNotNone|assertAlmostEqual|assertGreater|assertLess"
        r"|expect\(|should\.|Assert\.|Assertions?\.|verify\(|check\("
        r"|pytest\.raises|pytest\.warns|pytest\.approx"
        r"|\.to_equal|\.to_be|\.toBe|\.toEqual|\.toThrow|\.toHaveBeenCalled"
        r"|\.Should\(\)|\.ShouldBe|\.ShouldNotBe|\.ShouldThrow"
        r"|require\.|assert\.)\b",
        re.IGNORECASE,
    )

    # Test function name patterns
    _TEST_FUNC_RE = re.compile(
        r"^\s*(?:async\s+)?(?:def|function|func|public\s+(?:async\s+)?(?:void|Task))\s+"
        r"(test\w*|it\s*\(|describe\s*\(|\[(?:Fact|Theory|Test|TestMethod)\])",
        re.IGNORECASE,
    )

    _PYTHON_TEST_FUNC_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test\w+)\s*\(")

    def _detect_tests_without_assertions(self, root: Path, ctx: ScanContext) -> list[Finding]:
        """Scan test files for test functions that contain no assertion."""
        findings: list[Finding] = []
        counter = 100  # Start from TEST-100 to avoid collision with coverage findings

        # Find test files
        test_patterns = ["**/test_*.py", "**/tests/**/*.py", "**/*_test.py",
                        "**/*.spec.ts", "**/*.test.ts", "**/*.spec.js", "**/*.test.js",
                        "**/*Test.java", "**/*Tests.cs"]

        test_files: list[Path] = []
        for pattern in test_patterns:
            test_files.extend(root.glob(pattern))

        # Limit to avoid scanning too many files
        test_files = sorted(set(test_files))[:50]

        for test_file in test_files:
            if should_ignore(test_file):
                continue
            if not test_file.is_file():
                continue

            try:
                content = test_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = str(test_file.relative_to(root)).replace("\\", "/")
            empty_tests = self._find_empty_test_functions(content, rel_path)

            for func_name, line_start in empty_tests:
                counter += 1
                findings.append(Finding(
                    id=f"TEST-{counter:03d}",
                    title=f"测试函数无断言：{func_name} (Test without assertion)",
                    category="testing",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    location=Location(file_path=rel_path, line_start=line_start, line_end=line_start),
                    source_engine=self.name,
                    rule_id="TEST-NO-ASSERTION",
                    rule_description="测试函数体内没有任何断言语句(assert/expect/should)，测试可能无法验证预期行为。",
                    root_cause=f"函数 `{func_name}` 没有包含断言调用，可能是占位测试或仅测试了'不抛异常'。",
                    fix_suggestion="添加具体的断言验证预期行为，避免空测试给出虚假的信心。",
                    risk_priority="should-fix",
                ))

        return findings

    def _find_empty_test_functions(self, content: str, rel_path: str) -> list[tuple[str, int]]:
        """Find test functions without assertion statements."""
        results: list[tuple[str, int]] = []
        lines = content.splitlines()

        # Python test function detection
        if rel_path.endswith(".py"):
            results.extend(self._find_python_empty_tests(lines))
        # Could extend for Java/C#/JS but Python is highest value

        return results

    def _find_python_empty_tests(self, lines: list[str]) -> list[tuple[str, int]]:
        """Find Python test_* functions without assert/pytest.raises."""
        results: list[tuple[str, int]] = []
        i = 0
        while i < len(lines):
            match = self._PYTHON_TEST_FUNC_RE.match(lines[i])
            if not match:
                i += 1
                continue

            func_name = match.group(1)
            func_start = i + 1  # 1-indexed
            indent_level = len(lines[i]) - len(lines[i].lstrip())

            # Collect function body
            body_lines: list[str] = []
            j = i + 1
            while j < len(lines):
                line = lines[j]
                stripped = line.strip()
                if stripped == "":
                    j += 1
                    continue
                # Check if still inside function (deeper indent or decorator of next func)
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= indent_level and stripped and not stripped.startswith("#"):
                    break
                body_lines.append(line)
                j += 1

            body_text = "\n".join(body_lines)

            # Skip trivial bodies (just pass/... or single-line docstring)
            meaningful_lines = [l for l in body_lines if l.strip() and not l.strip().startswith("#")
                              and l.strip() not in ("pass", "...", '"""', "'''")]
            if len(meaningful_lines) < 2:
                i = j
                continue  # Too trivial to report

            # Check for assertions
            if not self._ASSERTION_PATTERNS.search(body_text):
                # Also check for pytest.raises context manager
                if "raises" not in body_text and "warns" not in body_text:
                    results.append((func_name, func_start))

            i = j

        return results


def _coerce_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _normalize_source_path(source_path: str, root: Path) -> str:
    path = Path(source_path)
    if path.is_absolute():
        try:
            return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
        except ValueError:
            return str(path).replace("\\", "/")
    return str(path).replace("\\", "/")


def _safe_percent(covered: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((covered / total) * 100.0, 1)


def _looks_like_test_file(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    name = Path(normalized).name
    return (
        "/tests/" in f"/{normalized}"
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".spec." in name
        or ".test." in name
    )
