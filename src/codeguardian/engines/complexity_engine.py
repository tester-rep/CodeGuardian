"""ComplexityEngine — analyzes function-level complexity metrics.

Dimension 2: Complexity Analyzer
Uses Python AST for precise metrics and reuses parser-backed function extraction
for Java/JavaScript/TypeScript before applying scoped heuristics.
"""

from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass
from pathlib import Path

from codeguardian.core.context import ScanContext
from codeguardian.languages import (
    EXTENSION_LANGUAGE_MAP,
    is_language_enabled,
    sort_paths_by_language_priority,
)
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric, MetricNames
from codeguardian.models.scan import EngineResult
from codeguardian.parsers import get_parser
from codeguardian.utils.ignore import should_ignore

CC_WARNING_THRESHOLD = 15
CC_HIGH_THRESHOLD = 25
NESTING_WARNING_THRESHOLD = 5
NESTING_HIGH_THRESHOLD = 8
PARAM_WARNING_THRESHOLD = 6
PARAM_HIGH_THRESHOLD = 10
LONG_FUNCTION_WARNING_THRESHOLD = 60
LONG_FUNCTION_HIGH_THRESHOLD = 120

# Finding control: max total complexity findings emitted per scan
MAX_COMPLEXITY_FINDINGS = 200
SUPPORTED_COMPLEXITY_LANGUAGES = {
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "cpp",
    "csharp",
    "lua",
    "rust",
}
LANGUAGE_BY_EXTENSION = {
    extension: language
    for extension, language in EXTENSION_LANGUAGE_MAP.items()
    if language in SUPPORTED_COMPLEXITY_LANGUAGES
}
SUPPORTED_EXTENSIONS = set(LANGUAGE_BY_EXTENSION)
_BRANCH_PATTERN = re.compile(r"\b(if|else\s+if|elif|elseif|for|while|case|catch|switch|match|repeat|until|select)\b")
_LUA_BLOCK_OPEN_RE = re.compile(
    r"^\s*(?:local\s+function\b|function\b|if\b.*\bthen\b|for\b.*\bdo\b|while\b.*\bdo\b|repeat\b)"
)
_LUA_BLOCK_CONTINUE_RE = re.compile(r"^\s*(?:elseif\b.*\bthen\b|else\b)")
_LUA_BLOCK_CLOSE_RE = re.compile(r"^\s*(?:end\b|until\b)")
_HEURISTIC_FUNCTION_RE = re.compile(
    r"^\s*(?:def |async def |function |local\s+function |func |(?:pub(?:\([^)]*\))?\s+)?fn |(?:public|private|protected|internal|static|virtual|override|async|sealed|partial|unsafe|extern)\s+[\w:<>,*&\[\]?\.]+\s+\w+\s*\(|(?:template\s*<[^>]+>\s*)?(?:[\w:<>~*&\[\]\s]+)\s+\w+\s*\()",
    re.MULTILINE,
)



@dataclass(slots=True)
class FunctionComplexity:
    """Function-level complexity analysis result."""

    qualified_name: str
    file_path: str
    line_start: int | None
    line_end: int | None
    cyclomatic_complexity: int
    cognitive_complexity: int
    nesting_depth: int
    param_count: int
    loc: int


@dataclass(slots=True)
class HeuristicComplexitySummary:
    """Fallback summary for files where function-level parsing is unavailable."""

    total_cc: int = 0
    function_count: int = 0
    max_nesting: int = 0


class ComplexityEngine:
    """Analyzes code complexity using AST-based and parser-backed methods."""

    name = "complexity"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root)
        function_analyses: list[FunctionComplexity] = []
        heuristic_summary = HeuristicComplexitySummary()

        candidate_files = [
            src_file
            for src_file in ctx.collect_candidate_files(root, suffixes=SUPPORTED_EXTENSIONS)
            if not should_ignore(src_file) and src_file.is_file() and src_file.suffix.lower() in SUPPORTED_EXTENSIONS
        ]


        for src_file in sort_paths_by_language_priority(candidate_files):
            suffix = src_file.suffix.lower()
            language = LANGUAGE_BY_EXTENSION[suffix]
            if not is_language_enabled(language, ctx.languages):
                continue
            if language == "python":
                analyses = self._analyze_python_file(src_file, root)
            else:
                analyses = self._analyze_parser_backed_file(src_file, root, language)


            if analyses:
                function_analyses.extend(analyses)
                continue

            summary = self._analyze_file_heuristic(src_file)
            heuristic_summary.total_cc += summary.total_cc
            heuristic_summary.function_count += summary.function_count
            heuristic_summary.max_nesting = max(
                heuristic_summary.max_nesting,
                summary.max_nesting,
            )

        findings = self._build_findings(function_analyses)
        metrics = self._build_metrics(function_analyses, heuristic_summary)

        return EngineResult(engine_name=self.name, findings=findings, metrics=metrics)

    def _build_metrics(
        self,
        function_analyses: list[FunctionComplexity],
        heuristic_summary: HeuristicComplexitySummary,
    ) -> list[Metric]:
        total_function_count = len(function_analyses) + heuristic_summary.function_count
        total_cc = sum(item.cyclomatic_complexity for item in function_analyses) + heuristic_summary.total_cc
        avg_cc = round(total_cc / total_function_count, 2) if total_function_count else 0.0

        avg_cognitive = round(
            sum(item.cognitive_complexity for item in function_analyses) / len(function_analyses),
            2,
        ) if function_analyses else 0.0
        max_nesting = max(
            [heuristic_summary.max_nesting, *(item.nesting_depth for item in function_analyses)],
            default=0,
        )
        max_params = max((item.param_count for item in function_analyses), default=0)

        metrics: list[Metric] = [
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.CYCLOMATIC_COMPLEXITY,
                value=avg_cc,
                unit="average",
                source_engine=self.name,
                dimension="complexity",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.COGNITIVE_COMPLEXITY,
                value=avg_cognitive,
                unit="average",
                source_engine=self.name,
                dimension="complexity",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.NESTING_DEPTH,
                value=float(max_nesting),
                unit="max",
                source_engine=self.name,
                dimension="complexity",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.PARAM_COUNT,
                value=float(max_params),
                unit="max",
                source_engine=self.name,
                dimension="complexity",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.DUPLICATION_RATE,
                value=0.0,
                unit="%",
                source_engine=self.name,
                dimension="complexity",
            ),
        ]

        # Compute project-level average MI
        if function_analyses:
            mi_values = []
            for item in function_analyses:
                loc = max(item.loc, 1)
                cc = item.cyclomatic_complexity
                hv = loc * 8.0
                mi_raw = 171.0 - 5.2 * math.log(max(hv, 1)) - 0.23 * cc - 16.2 * math.log(max(loc, 1))
                mi_values.append(max(0.0, min(100.0, mi_raw)))
            avg_mi = sum(mi_values) / len(mi_values)
            metrics.append(Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.MAINTAINABILITY_INDEX,
                value=round(avg_mi, 1),
                unit="average",
                source_engine=self.name,
                dimension="maintainability",
            ))

        for item in function_analyses:
            target_id = f"{item.file_path}:{item.qualified_name}"
            # Compute Maintainability Index:
            # MI = 171 - 5.2×ln(HV) - 0.23×CC - 16.2×ln(LOC)
            # Halstead Volume approximated as LOC × log2(unique_operators + unique_operands)
            # Simplified: HV ≈ LOC × 8 (empirical average for typical code)
            loc = max(item.loc, 1)
            cc = item.cyclomatic_complexity
            hv = loc * 8.0  # Simplified Halstead Volume estimate
            mi_raw = 171.0 - 5.2 * math.log(max(hv, 1)) - 0.23 * cc - 16.2 * math.log(max(loc, 1))
            mi = max(0.0, min(100.0, mi_raw))  # Clamp to 0-100

            metrics.extend([
                Metric(
                    target_id=target_id,
                    target_type="function",
                    metric_name=MetricNames.CYCLOMATIC_COMPLEXITY,
                    value=float(item.cyclomatic_complexity),
                    unit="score",
                    source_engine=self.name,
                    dimension="complexity",
                ),
                Metric(
                    target_id=target_id,
                    target_type="function",
                    metric_name=MetricNames.COGNITIVE_COMPLEXITY,
                    value=float(item.cognitive_complexity),
                    unit="score",
                    source_engine=self.name,
                    dimension="complexity",
                ),
                Metric(
                    target_id=target_id,
                    target_type="function",
                    metric_name=MetricNames.NESTING_DEPTH,
                    value=float(item.nesting_depth),
                    unit="levels",
                    source_engine=self.name,
                    dimension="complexity",
                ),
                Metric(
                    target_id=target_id,
                    target_type="function",
                    metric_name=MetricNames.PARAM_COUNT,
                    value=float(item.param_count),
                    unit="parameters",
                    source_engine=self.name,
                    dimension="complexity",
                ),
                Metric(
                    target_id=target_id,
                    target_type="function",
                    metric_name=MetricNames.MAINTAINABILITY_INDEX,
                    value=round(mi, 1),
                    unit="score",
                    source_engine=self.name,
                    dimension="maintainability",
                ),
            ])

        return metrics

    def _build_findings(self, function_analyses: list[FunctionComplexity]) -> list[Finding]:
        """Build findings with per-function aggregation and a global cap.

        Instead of emitting up to 4 separate findings per function (CC, nesting,
        params, LOC), each function produces at most ONE aggregated finding that
        summarises all exceeded thresholds.  The overall list is capped at
        MAX_COMPLEXITY_FINDINGS to avoid report flooding.
        """
        findings: list[Finding] = []
        counter = 0

        def _worst(a: Severity, b: Severity) -> Severity:
            return a if a.weight >= b.weight else b

        for item in sorted(function_analyses, key=lambda x: (x.file_path, x.line_start or 0, x.qualified_name)):
            issues: list[str] = []
            tags: list[str] = ["complexity"]
            worst_severity = Severity.LOW
            is_must_fix = False

            if item.cyclomatic_complexity >= CC_WARNING_THRESHOLD:
                high = item.cyclomatic_complexity >= CC_HIGH_THRESHOLD
                issues.append(f"CC={item.cyclomatic_complexity}")
                tags.append("cyclomatic")
                if high:
                    worst_severity = _worst(worst_severity, Severity.MEDIUM)
                else:
                    worst_severity = _worst(worst_severity, Severity.LOW)

            if item.nesting_depth >= NESTING_WARNING_THRESHOLD:
                high = item.nesting_depth >= NESTING_HIGH_THRESHOLD
                issues.append(f"nesting={item.nesting_depth}")
                tags.append("nesting")
                if high:
                    worst_severity = _worst(worst_severity, Severity.MEDIUM)
                else:
                    worst_severity = _worst(worst_severity, Severity.LOW)

            if item.param_count >= PARAM_WARNING_THRESHOLD:
                high = item.param_count >= PARAM_HIGH_THRESHOLD
                issues.append(f"params={item.param_count}")
                tags.append("api-design")
                if high:
                    worst_severity = _worst(worst_severity, Severity.LOW)
                else:
                    worst_severity = _worst(worst_severity, Severity.LOW)

            if item.loc >= LONG_FUNCTION_WARNING_THRESHOLD:
                high = item.loc >= LONG_FUNCTION_HIGH_THRESHOLD
                issues.append(f"LOC={item.loc}")
                tags.append("function-size")
                if high:
                    worst_severity = _worst(worst_severity, Severity.MEDIUM)
                else:
                    worst_severity = _worst(worst_severity, Severity.LOW)

            if not issues:
                continue

            counter += 1
            location = Location(
                file_path=item.file_path,
                line_start=item.line_start,
                line_end=item.line_end,
            )
            issue_summary = ", ".join(issues)
            # Pick dominant rule_id for the most impactful issue
            if item.cyclomatic_complexity >= CC_WARNING_THRESHOLD:
                rule_id = "HIGH-CC-FUNCTION"
            elif item.loc >= LONG_FUNCTION_WARNING_THRESHOLD:
                rule_id = "LONG-FUNCTION"
            elif item.nesting_depth >= NESTING_WARNING_THRESHOLD:
                rule_id = "DEEP-NESTING"
            else:
                rule_id = "TOO-MANY-PARAMS"

            # ── Build Chinese root_cause with explanation ─────────
            cause_parts: list[str] = []
            if item.cyclomatic_complexity >= CC_WARNING_THRESHOLD:
                cause_parts.append(
                    f"圈复杂度 (Cyclomatic Complexity) 为 {item.cyclomatic_complexity}，"
                    f"超过建议阈值 {CC_WARNING_THRESHOLD}。圈复杂度衡量函数中独立执行路径的数量，"
                    "数值越高意味着分支越多、测试和维护越困难。"
                )
            if item.loc >= LONG_FUNCTION_WARNING_THRESHOLD:
                cause_parts.append(
                    f"函数体共 {item.loc} 行，超过建议阈值 {LONG_FUNCTION_WARNING_THRESHOLD} 行。"
                    "过长的函数难以阅读和理解，也更容易隐藏 bug。"
                )
            if item.nesting_depth >= NESTING_WARNING_THRESHOLD:
                cause_parts.append(
                    f"最大嵌套深度为 {item.nesting_depth} 层，超过建议阈值 {NESTING_WARNING_THRESHOLD} 层。"
                    "深层嵌套会显著降低可读性，建议通过提前返回 (early return) 或提取子函数来简化。"
                )
            if item.param_count >= PARAM_WARNING_THRESHOLD:
                cause_parts.append(
                    f"参数数量为 {item.param_count} 个，超过建议阈值 {PARAM_WARNING_THRESHOLD} 个。"
                    "过多参数通常意味着函数职责过重，建议封装为参数对象或拆分功能。"
                )
            root_cause = "\n".join(cause_parts)

            findings.append(
                Finding(
                    id=f"CMP-{counter:03d}",
                    title=f"函数 '{item.qualified_name}' 存在复杂度问题 ({issue_summary})",
                    category="maintainability",
                    severity=worst_severity,
                    confidence=Confidence.HIGH,
                    location=location,
                    risk_priority="must-fix" if is_must_fix else "can-fix",
                    source_engine=self.name,
                    rule_id=rule_id,
                    root_cause=root_cause,
                    fix_suggestion="建议将函数拆分为更小的子函数，减少分支嵌套，简化参数列表。可通过提取方法 (Extract Method)、引入参数对象 (Parameter Object) 等重构手法改善。",
                    tags=list(dict.fromkeys(tags)),  # deduplicate while preserving order
                )
            )

            if counter >= MAX_COMPLEXITY_FINDINGS:
                break

        return findings

    def _analyze_python_file(self, src_file: Path, root: Path) -> list[FunctionComplexity]:
        rel_path = str(src_file.relative_to(root)).replace("\\", "/")

        try:
            source = src_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(src_file))
        except (OSError, SyntaxError):
            return []

        collector = _PythonComplexityCollector(rel_path)
        collector.visit(tree)
        return collector.results

    def _analyze_parser_backed_file(
        self,
        src_file: Path,
        root: Path,
        language: str,
    ) -> list[FunctionComplexity]:
        parser = get_parser(language)
        if parser is None:
            return []

        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        parsed = parser.parse_file(src_file, root)
        if not parsed.functions:
            return []

        lines = content.splitlines()
        analyses: list[FunctionComplexity] = []
        for item in parsed.functions:
            if item.start_line is None or item.end_line is None:
                continue
            snippet = "\n".join(lines[item.start_line - 1:item.end_line])
            metrics = self._analyze_function_snippet(snippet)
            analyses.append(
                FunctionComplexity(
                    qualified_name=(
                        f"{item.class_or_module}.{item.name}"
                        if item.is_method and item.class_or_module
                        else item.name
                    ),
                    file_path=item.file_path,
                    line_start=item.start_line,
                    line_end=item.end_line,
                    cyclomatic_complexity=metrics["cyclomatic_complexity"],
                    cognitive_complexity=metrics["cognitive_complexity"],
                    nesting_depth=metrics["nesting_depth"],
                    param_count=item.param_count,
                    loc=item.loc or max(0, item.end_line - item.start_line + 1),
                )
            )
        return analyses

    @staticmethod
    def _analyze_function_snippet(snippet: str) -> dict[str, int]:
        cyclomatic = 1
        cognitive = 0
        current_nesting = 0
        max_nesting = 0

        for raw_line in snippet.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue

            leading_closers = len(stripped) - len(stripped.lstrip("}"))
            if leading_closers:
                current_nesting = max(0, current_nesting - leading_closers)

            branch_hits = len(_BRANCH_PATTERN.findall(stripped))
            branch_hits += stripped.count("&&") + stripped.count("||")
            branch_hits += stripped.count("?") if "?:" not in stripped else 0
            if branch_hits:
                cyclomatic += branch_hits
                cognitive += branch_hits * (1 + current_nesting)
                max_nesting = max(max_nesting, current_nesting + 1)

            open_braces = stripped.count("{")
            close_braces = stripped.count("}")
            current_nesting = max(0, current_nesting + open_braces - max(0, close_braces - leading_closers))

        return {
            "cyclomatic_complexity": cyclomatic,
            "cognitive_complexity": max(cyclomatic, cognitive),
            "nesting_depth": max_nesting,
        }

    @staticmethod
    def _analyze_file_heuristic(src_file: Path) -> HeuristicComplexitySummary:
        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return HeuristicComplexitySummary()

        total_cc = 0
        max_nesting = 0
        lines = content.splitlines()
        for line in lines:
            total_cc += len(
                re.findall(r"\b(if|elif|elseif|else|for|while|case|catch|and|or|except|try|match|repeat|until|select)\b", line)
            )
            indent = len(line) - len(line.lstrip())
            max_nesting = max(max_nesting, indent // 4)


        function_count = len(
            re.findall(
                r"^\s*(?:def |async def |function |local\s+function |func |fn |(?:public|private|protected|internal|static|virtual)\s+[\w:<>,*&\[\]]+\s+\w+\s*\()",
                content,
                re.MULTILINE,
            )
        )


        return HeuristicComplexitySummary(
            total_cc=total_cc,
            function_count=function_count,
            max_nesting=max_nesting,
        )


class _PythonComplexityCollector(ast.NodeVisitor):
    """Collect per-function complexity from a Python AST."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.results: list[FunctionComplexity] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record_function(node)
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record_function(node)
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def _record_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        owner_parts = [*self.class_stack, *self.function_stack]
        qualified_name = ".".join([*owner_parts, node.name]) if owner_parts else node.name
        metrics = _FunctionComplexityVisitor(node).analyze()
        line_start = getattr(node, "lineno", None)
        line_end = getattr(node, "end_lineno", None)
        loc = (line_end - line_start + 1) if line_start and line_end else 0

        self.results.append(
            FunctionComplexity(
                qualified_name=qualified_name,
                file_path=self.file_path,
                line_start=line_start,
                line_end=line_end,
                cyclomatic_complexity=metrics["cyclomatic_complexity"],
                cognitive_complexity=metrics["cognitive_complexity"],
                nesting_depth=metrics["nesting_depth"],
                param_count=_count_parameters(node),
                loc=loc,
            )
        )


class _FunctionComplexityVisitor(ast.NodeVisitor):
    """Compute complexity metrics for a single function body."""

    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.root = root
        self.cyclomatic_complexity = 1
        self.cognitive_complexity = 0
        self.current_nesting = 0
        self.max_nesting = 0

    def analyze(self) -> dict[str, int]:
        for stmt in self.root.body:
            self.visit(stmt)
        return {
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "cognitive_complexity": self.cognitive_complexity,
            "nesting_depth": self.max_nesting,
        }

    def visit_If(self, node: ast.If) -> None:
        self._record_branch(1)
        self._visit_nested_blocks(node.body, node.orelse)
        self.visit(node.test)

    def visit_For(self, node: ast.For) -> None:
        self._record_branch(1)
        self.visit(node.iter)
        self._visit_nested_blocks(node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def visit_While(self, node: ast.While) -> None:
        self._record_branch(1)
        self.visit(node.test)
        self._visit_nested_blocks(node.body, node.orelse)

    def visit_Try(self, node: ast.Try) -> None:
        self._record_branch(max(1, len(node.handlers)))
        self._visit_nested_blocks(node.body)
        for handler in node.handlers:
            self._visit_nested_blocks(handler.body)
        self._visit_nested_blocks(node.orelse, node.finalbody)

    def visit_Match(self, node: ast.Match) -> None:
        self._record_branch(max(1, len(node.cases)))
        for case in node.cases:
            self._visit_nested_blocks(case.body)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        increment = max(0, len(node.values) - 1)
        if increment:
            self.cyclomatic_complexity += increment
            self.cognitive_complexity += increment * (1 + self.current_nesting)
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._record_branch(1)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._record_comprehension(node.generators)
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._record_comprehension(node.generators)
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._record_comprehension(node.generators)
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._record_comprehension(node.generators)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is not self.root:
            return
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is not self.root:
            return
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def _record_branch(self, increment: int) -> None:
        self.cyclomatic_complexity += increment
        self.cognitive_complexity += increment * (1 + self.current_nesting)

    def _visit_nested_blocks(self, *blocks: list[ast.stmt]) -> None:
        self.current_nesting += 1
        self.max_nesting = max(self.max_nesting, self.current_nesting)
        try:
            for block in blocks:
                for stmt in block:
                    self.visit(stmt)
        finally:
            self.current_nesting -= 1

    def _record_comprehension(self, generators: list[ast.comprehension]) -> None:
        increment = len(generators) + sum(len(gen.ifs) for gen in generators)
        if increment:
            self.cyclomatic_complexity += increment
            self.cognitive_complexity += increment * (1 + self.current_nesting)


def _count_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    args = node.args
    return (
        len(args.posonlyargs)
        + len(args.args)
        + len(args.kwonlyargs)
        + (1 if args.vararg else 0)
        + (1 if args.kwarg else 0)
    )

