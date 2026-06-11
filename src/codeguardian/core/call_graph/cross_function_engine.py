"""Cross-Function Detection Engine — finds bugs that span function/file boundaries.

Detects:
- Null propagation across call chains (NULL-PROP-UNCHECKED)
- Resource lifecycle violations (RESOURCE-NEVER-CLOSED)
- Cross-function taint flow (TAINT-CROSS-FUNCTION)
- Exception safety issues (EXCEPTION-LOSES-RESOURCE)
- Concurrency: lock-not-released-on-error
- API contract violations (RETURN-VALUE-IGNORED)

Requires PCI (Project Call Graph Index) on ScanContext to function.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from codeguardian.core.call_graph.function_summary import FunctionSummary, ResourceKind
from codeguardian.core.call_graph.graph import CallEdge, CallGraph, CallPath
from codeguardian.core.call_graph.symbol_table import Symbol, SymbolKind, SymbolTable
from codeguardian.engines.rule_helpers import RuleSpec, RuleHit, build_finding as _build_finding
from codeguardian.engines.rule_registry import register_rules
from codeguardian.models.enums import Confidence, Severity

if TYPE_CHECKING:
    from codeguardian.core.call_graph.pci_builder import PCIResult
    from codeguardian.core.context import ScanContext
    from codeguardian.models.finding import Finding
    from codeguardian.models.scan import EngineResult

logger = logging.getLogger(__name__)

ENGINE_NAME = "cross_function"

# ═══════════════════════════════════════════════════════════════════════
# Rule Definitions
# ═══════════════════════════════════════════════════════════════════════

_RULES = register_rules(ENGINE_NAME, [
    # Category A: Null Propagation
    RuleSpec(
        rule_id="NULL-PROP-UNCHECKED",
        title="跨函数空值传播 — 返回值可能为null但调用方未检查",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="defect",
        tags=("cross-function", "null-safety", "architecture"),
        description_zh="被调函数可能返回null/None/nil，但调用方直接使用返回值而未进行空值检查，可能导致NullPointerException/AttributeError。",
        applicable_languages=("python", "java", "go", "javascript", "typescript"),
    ),

    # Category B: Resource Lifecycle
    RuleSpec(
        rule_id="RESOURCE-NEVER-CLOSED-XFUNC",
        title="跨函数资源泄漏 — 资源在函数中获取但无调用路径释放",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="defect",
        tags=("cross-function", "resource-leak", "architecture"),
        description_zh="函数获取了资源（文件/连接/锁），但在整个调用链中找不到释放路径。",
        applicable_languages=("python", "java", "go", "cpp"),
    ),
    RuleSpec(
        rule_id="RESOURCE-LEAK-ON-EXCEPTION",
        title="异常路径资源泄漏 — 被调函数抛异常时资源未释放",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="defect",
        tags=("cross-function", "resource-leak", "exception-safety"),
        description_zh="资源获取后调用了可能抛异常的函数，但没有finally/defer/with保护释放。",
        applicable_languages=("python", "java", "go", "cpp"),
    ),

    # Category C: Taint/Injection
    RuleSpec(
        rule_id="TAINT-CROSS-FUNCTION",
        title="跨函数注入风险 — 用户输入经调用链到达危险接收端",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        category="security",
        blocks_release=True,
        risk_priority="must-fix",
        tags=("cross-function", "injection", "taint", "architecture"),
        description_zh="用户输入数据从入口函数通过调用链传播到SQL/命令/文件等危险操作，中间无有效净化。",
        applicable_languages=("python", "java", "go"),
        cwe_ids=("CWE-89", "CWE-78"),
        owasp=("A03:2021",),
    ),

    # Category D: Exception Safety
    RuleSpec(
        rule_id="UNCAUGHT-EXCEPTION-PROPAGATION",
        title="未捕获异常传播 — 被调函数异常沿调用链逃逸到入口点",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="defect",
        tags=("cross-function", "exception-safety"),
        description_zh="被调函数可能抛出特定异常，但整个调用链上无任何函数捕获处理，将导致进程崩溃或异常泄漏。",
        applicable_languages=("python", "java", "javascript", "typescript"),
    ),

    # Category E: Concurrency
    RuleSpec(
        rule_id="LOCK-LEAKED-ON-CALLEE-THROW",
        title="调用方持锁但被调方可抛异常 — 锁泄漏风险",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="defect",
        tags=("cross-function", "concurrency", "lock"),
        description_zh="函数获取锁后调用了可能抛异常的函数，但锁释放不在finally/defer中，异常时锁将泄漏。",
        applicable_languages=("python", "java", "go"),
    ),

    # Category F: API Contract
    RuleSpec(
        rule_id="ERROR-RETURN-IGNORED",
        title="错误返回值被忽略 — 调用方未检查被调函数的错误/状态返回",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="defect",
        tags=("cross-function", "api-contract", "error-handling"),
        description_zh="被调函数返回错误类型（Go error、Optional等），但调用方未检查返回值，可能遗漏错误。",
        applicable_languages=("python", "java", "go"),
    ),
])

# Build rule lookup by ID
_RULE_MAP: dict[str, RuleSpec] = {r.rule_id: r for r in _RULES}


# ═══════════════════════════════════════════════════════════════════════
# Engine Implementation
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class CallChainStep:
    """One step in a call chain (for human-readable evidence)."""

    file: str
    function: str
    line: int
    action: str  # e.g., "returns null here", "passes result to param 0"


def _make_finding(
    rule_id: str,
    file_path: str,
    line: int,
    message: str,
    lines: list[str] | None = None,
    metadata: dict | None = None,
) -> Finding | None:
    """Create a Finding from a cross-function rule hit."""
    rule = _RULE_MAP.get(rule_id)
    if rule is None:
        return None

    hit = RuleHit(
        rule=rule,
        file_path=file_path,
        line_start=line,
        line_end=line,
        message=message,
        metadata=metadata or {},
    )
    finding_id = f"CF-{uuid4().hex[:8]}"
    return _build_finding(hit, lines or [], finding_id, ENGINE_NAME)


class CrossFunctionEngine:
    """Detects bugs that require cross-function/file analysis.

    Implements AnalyzerEngine protocol. Requires PCI on ScanContext.
    """

    @property
    def name(self) -> str:
        return "cross_function"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        """Run all cross-function detection rules."""
        from codeguardian.models.scan import EngineResult as ER

        # Check if PCI is available
        pci: PCIResult | None = getattr(ctx, "_pci_result", None)
        if pci is None or pci.is_empty:
            logger.info("CrossFunctionEngine: No PCI available, skipping")
            return ER(engine_name=self.name)

        self._project_root = str(ctx.project_root)
        findings: list[Finding] = []

        # Run each detection category
        findings.extend(self._detect_null_propagation(pci, ctx))
        findings.extend(self._detect_resource_lifecycle(pci, ctx))
        findings.extend(self._detect_taint_flow(pci, ctx))
        findings.extend(self._detect_exception_safety(pci, ctx))
        findings.extend(self._detect_lock_leak(pci, ctx))
        findings.extend(self._detect_error_return_ignored(pci, ctx))

        # Business Process-level detection (L7)
        findings.extend(self._detect_business_process_issues(pci, ctx))

        logger.info(
            "CrossFunctionEngine: %d findings from PCI (%d symbols, %d edges)",
            len(findings), pci.symbol_table.size, pci.call_graph.edge_count,
        )

        return ER(engine_name=self.name, findings=findings)

    # ──────────────────────────────────────────────────────────────────
    # Category A: Null Propagation
    # ──────────────────────────────────────────────────────────────────

    def _detect_null_propagation(self, pci: PCIResult, ctx: ScanContext) -> list[Finding]:
        """Detect unchecked null return values propagating across functions."""
        findings: list[Finding] = []
        summaries = pci.function_summaries
        call_graph = pci.call_graph
        symbol_table = pci.symbol_table

        for qname, summary in summaries.items():
            if not summary.may_return_null:
                continue

            # Find callers of this function
            caller_edges = call_graph.callers_of(qname, depth=1, min_confidence=0.7)

            for edge in caller_edges:
                caller_summary = summaries.get(edge.caller)
                if caller_summary is None:
                    continue

                # Check if caller performs null check near the call site
                if self._caller_checks_null(edge, caller_summary, pci):
                    continue

                # Build evidence: call chain showing null propagation
                callee_sym = symbol_table.lookup(qname)
                caller_sym = symbol_table.lookup(edge.caller)
                if not callee_sym or not caller_sym:
                    continue

                chain = [
                    CallChainStep(
                        file=callee_sym.file_path,
                        function=callee_sym.name,
                        line=summary.null_return_lines[0] if summary.null_return_lines else callee_sym.start_line,
                        action="可能返回null/None",
                    ),
                    CallChainStep(
                        file=caller_sym.file_path,
                        function=caller_sym.name,
                        line=edge.call_site_line,
                        action="调用后未检查null直接使用返回值",
                    ),
                ]

                description = self._format_chain_description(
                    f"`{callee_sym.name}()` 可能返回null，但 `{caller_sym.name}()` "
                    f"在第{edge.call_site_line}行调用后未进行空值检查。",
                    chain,
                )

                finding = _make_finding(
                    rule_id="NULL-PROP-UNCHECKED",
                    file_path=caller_sym.file_path,
                    line=edge.call_site_line,
                    message=description,
                    metadata={
                        "callee": qname,
                        "caller": edge.caller,
                    },
                )
                if finding:
                    findings.append(finding)

        return findings[:50]  # Limit to avoid flooding

    def _caller_checks_null(
        self,
        edge: CallEdge,
        caller_summary: FunctionSummary,
        pci: PCIResult,
    ) -> bool:
        """Heuristic: check if the caller performs a null check near the call site."""
        # Use PCI file_lines cache instead of reading from disk
        lines = pci.file_lines.get(caller_summary.file_path, [])
        if not lines:
            return False

        # Get lines after the call site for null checks
        start = max(0, edge.call_site_line - 1)
        end = min(len(lines), edge.call_site_line + 5)
        context_lines = lines[start:end]

        null_check_patterns = [
            "if ", "is None", "is not None", "!= None", "== None",
            "!= null", "== null", "!= nil", "== nil",
            "Optional", ".orElse", ".isPresent", "if err",
            "?.", "??",  # Optional chaining, nullish coalescing
        ]

        for line in context_lines:
            if any(pattern in line for pattern in null_check_patterns):
                return True

        return False

    # ──────────────────────────────────────────────────────────────────
    # Category B: Resource Lifecycle
    # ──────────────────────────────────────────────────────────────────

    def _detect_resource_lifecycle(self, pci: PCIResult, ctx: ScanContext) -> list[Finding]:
        """Detect resource lifecycle violations across functions."""
        findings: list[Finding] = []
        summaries = pci.function_summaries
        call_graph = pci.call_graph
        symbol_table = pci.symbol_table

        for qname, summary in summaries.items():
            # Rule: RESOURCE-NEVER-CLOSED-XFUNC
            # Function acquires resource but uses_context_manager=False
            if summary.acquires and not summary.releases and not summary.uses_context_manager:
                # Check if ANY caller/callee in the reachable set releases it
                reachable = call_graph.reachable_from(qname, max_depth=3, direction="reverse")
                any_release = False
                for reachable_sym in reachable:
                    r_summary = summaries.get(reachable_sym)
                    if r_summary and r_summary.releases:
                        any_release = True
                        break

                if not any_release:
                    sym = symbol_table.lookup(qname)
                    if not sym:
                        continue

                    resource_info = summary.acquires[0]
                    finding = _make_finding(
                        rule_id="RESOURCE-NEVER-CLOSED-XFUNC",
                        file_path=sym.file_path,
                        line=resource_info.line,
                        message=(
                            f"`{sym.name}()` 在第{resource_info.line}行获取了"
                            f"{resource_info.kind.value}资源，"
                            f"但在整个可达调用链（深度3）中未找到释放路径。"
                        ),
                        metadata={
                            "resource_kind": resource_info.kind.value,
                            "acquirer": qname,
                        },
                    )
                    if finding:
                        findings.append(finding)

            # Rule: RESOURCE-LEAK-ON-EXCEPTION
            # Acquires resource, then calls function that may_throw, without finally
            if summary.acquires and not summary.has_finally and not summary.uses_context_manager:
                # Check callees: any may_throw?
                callee_edges = call_graph.callees_of(qname, depth=1, min_confidence=0.7)
                for edge in callee_edges:
                    callee_summary = summaries.get(edge.callee)
                    if callee_summary is None or not callee_summary.may_throw:
                        continue

                    # Is the call AFTER the resource acquisition?
                    resource_line = summary.acquires[0].line
                    if edge.call_site_line <= resource_line:
                        continue

                    sym = symbol_table.lookup(qname)
                    callee_sym = symbol_table.lookup(edge.callee)
                    if not sym or not callee_sym:
                        continue

                    chain = [
                        CallChainStep(
                            file=sym.file_path,
                            function=sym.name,
                            line=resource_line,
                            action=f"获取{summary.acquires[0].kind.value}资源",
                        ),
                        CallChainStep(
                            file=sym.file_path,
                            function=sym.name,
                            line=edge.call_site_line,
                            action=f"调用 `{callee_sym.name}()` — 可能抛出 {', '.join(callee_summary.may_throw)}",
                        ),
                    ]

                    description = self._format_chain_description(
                        f"`{sym.name}()` 在第{resource_line}行获取资源后，"
                        f"第{edge.call_site_line}行调用可能抛异常的 `{callee_sym.name}()`，"
                        f"但无finally/defer/with保护资源释放。",
                        chain,
                    )

                    finding = _make_finding(
                        rule_id="RESOURCE-LEAK-ON-EXCEPTION",
                        file_path=sym.file_path,
                        line=edge.call_site_line,
                        message=description,
                    )
                    if finding:
                        findings.append(finding)
                    break  # One finding per function is enough

        return findings[:30]

    # ──────────────────────────────────────────────────────────────────
    # Category C: Taint Flow
    # ──────────────────────────────────────────────────────────────────

    def _detect_taint_flow(self, pci: PCIResult, ctx: ScanContext) -> list[Finding]:
        """Detect cross-function taint propagation from sources to sinks."""
        findings: list[Finding] = []
        summaries = pci.function_summaries
        call_graph = pci.call_graph
        symbol_table = pci.symbol_table

        # Find all source functions
        sources = [qname for qname, s in summaries.items() if s.is_source]
        # Find all sink functions
        sinks = [qname for qname, s in summaries.items() if s.is_sink]

        if not sources or not sinks:
            return findings

        # For each source, check if there's a path to any sink
        for source_qname in sources:
            for sink_qname in sinks:
                if source_qname == sink_qname:
                    continue

                paths = call_graph.paths_between(
                    source_qname, sink_qname, max_depth=4, min_confidence=0.6,
                )

                for path in paths[:2]:  # Limit per source-sink pair
                    # Check if any function on the path is a sanitizer
                    sanitized = False
                    for sym_name in path.symbols():
                        s = summaries.get(sym_name)
                        if s and s.is_sanitizer:
                            sanitized = True
                            break

                    if sanitized:
                        continue

                    # Build finding with full call chain
                    source_sym = symbol_table.lookup(source_qname)
                    sink_sym = symbol_table.lookup(sink_qname)
                    if not source_sym or not sink_sym:
                        continue

                    chain: list[CallChainStep] = []
                    chain.append(CallChainStep(
                        file=source_sym.file_path,
                        function=source_sym.name,
                        line=source_sym.start_line,
                        action="用户输入/外部数据进入",
                    ))

                    for edge in path.edges:
                        intermediate_sym = symbol_table.lookup(edge.callee)
                        if intermediate_sym and intermediate_sym.qualified_name != sink_qname:
                            chain.append(CallChainStep(
                                file=intermediate_sym.file_path,
                                function=intermediate_sym.name,
                                line=edge.call_site_line,
                                action="数据传递（未净化）",
                            ))

                    chain.append(CallChainStep(
                        file=sink_sym.file_path,
                        function=sink_sym.name,
                        line=sink_sym.start_line,
                        action="到达危险操作（SQL/命令/文件）",
                    ))

                    description = self._format_chain_description(
                        f"用户输入从 `{source_sym.name}()` 经 {path.depth} 步调用链"
                        f"到达危险操作 `{sink_sym.name}()`，路径上无净化函数。",
                        chain,
                    )

                    finding = _make_finding(
                        rule_id="TAINT-CROSS-FUNCTION",
                        file_path=sink_sym.file_path,
                        line=sink_sym.start_line,
                        message=description,
                        metadata={
                            "source": source_qname,
                            "sink": sink_qname,
                            "path_depth": str(path.depth),
                        },
                    )
                    if finding:
                        findings.append(finding)

        return findings[:20]

    # ──────────────────────────────────────────────────────────────────
    # Category D: Exception Safety
    # ──────────────────────────────────────────────────────────────────

    def _detect_exception_safety(self, pci: PCIResult, ctx: ScanContext) -> list[Finding]:
        """Detect uncaught exceptions propagating to entry points."""
        findings: list[Finding] = []
        summaries = pci.function_summaries
        call_graph = pci.call_graph
        symbol_table = pci.symbol_table

        # Find functions that may_throw and check if exceptions escape
        for qname, summary in summaries.items():
            if not summary.may_throw:
                continue

            # Walk up callers to see if exception is ever caught
            for exc_type in summary.may_throw:
                callers = call_graph.callers_of(qname, depth=3, min_confidence=0.7)
                caught = False

                for edge in callers:
                    caller_summary = summaries.get(edge.caller)
                    if caller_summary is None:
                        continue
                    # Check if any caller catches this or a parent exception
                    if exc_type in caller_summary.catches or "Exception" in caller_summary.catches:
                        caught = True
                        break

                if caught:
                    continue

                # Check if any caller is an entry point
                entry_callers = [
                    e for e in callers
                    if e.caller in call_graph.entry_points()
                ]

                if entry_callers:
                    sym = symbol_table.lookup(qname)
                    if not sym:
                        continue

                    entry_sym = symbol_table.lookup(entry_callers[0].caller)
                    entry_name = entry_sym.name if entry_sym else "entry"

                    finding = _make_finding(
                        rule_id="UNCAUGHT-EXCEPTION-PROPAGATION",
                        file_path=sym.file_path,
                        line=sym.start_line,
                        message=(
                            f"`{sym.name}()` 抛出 `{exc_type}`，沿调用链传播到入口函数"
                            f" `{entry_name}()` 而无任何捕获处理。"
                        ),
                        metadata={
                            "exception_type": exc_type,
                            "thrower": qname,
                            "entry_point": entry_callers[0].caller,
                        },
                    )
                    if finding:
                        findings.append(finding)

        return findings[:20]

    # ──────────────────────────────────────────────────────────────────
    # Category E: Lock Leak
    # ──────────────────────────────────────────────────────────────────

    def _detect_lock_leak(self, pci: PCIResult, ctx: ScanContext) -> list[Finding]:
        """Detect lock-not-released-on-error patterns."""
        findings: list[Finding] = []
        summaries = pci.function_summaries
        call_graph = pci.call_graph
        symbol_table = pci.symbol_table

        for qname, summary in summaries.items():
            if not summary.acquires_lock:
                continue
            if summary.has_finally or summary.uses_context_manager:
                continue

            # Check if any callee may throw
            callee_edges = call_graph.callees_of(qname, depth=1, min_confidence=0.7)
            throwing_callees = []

            for edge in callee_edges:
                callee_summary = summaries.get(edge.callee)
                if callee_summary and callee_summary.may_throw:
                    throwing_callees.append((edge, callee_summary))

            if not throwing_callees:
                continue

            sym = symbol_table.lookup(qname)
            if not sym:
                continue

            edge, callee_summary = throwing_callees[0]
            callee_sym = symbol_table.lookup(edge.callee)
            callee_name = callee_sym.name if callee_sym else edge.callee

            finding = _make_finding(
                rule_id="LOCK-LEAKED-ON-CALLEE-THROW",
                file_path=sym.file_path,
                line=edge.call_site_line,
                message=(
                    f"`{sym.name}()` 持有锁 `{summary.acquires_lock}`，"
                    f"但调用的 `{callee_name}()` 可能抛出"
                    f" {', '.join(callee_summary.may_throw)}。"
                    f"锁释放不在finally/defer中，异常时将死锁。"
                ),
                metadata={
                    "lock_holder": qname,
                    "lock_name": summary.acquires_lock,
                    "throwing_callee": edge.callee,
                },
            )
            if finding:
                findings.append(finding)

        return findings[:15]

    # ──────────────────────────────────────────────────────────────────
    # Category F: Error Return Ignored
    # ──────────────────────────────────────────────────────────────────

    def _detect_error_return_ignored(self, pci: PCIResult, ctx: ScanContext) -> list[Finding]:
        """Detect callers that ignore error return values."""
        findings: list[Finding] = []
        summaries = pci.function_summaries
        call_graph = pci.call_graph
        symbol_table = pci.symbol_table

        # Find functions that return errors
        error_returners = [
            qname for qname, s in summaries.items()
            if s.return_value_is_error or s.return_value_is_optional
        ]

        for qname in error_returners:
            callers = call_graph.callers_of(qname, depth=1, min_confidence=0.7)

            for edge in callers:
                # Heuristic: if the call is on a line by itself (not assigned to variable)
                # then the return value is likely ignored
                # This requires access to source lines
                caller_summary = summaries.get(edge.caller)
                if not caller_summary:
                    continue

                if self._call_return_is_ignored(edge, pci):
                    sym = symbol_table.lookup(qname)
                    caller_sym = symbol_table.lookup(edge.caller)
                    if not sym or not caller_sym:
                        continue

                    finding = _make_finding(
                        rule_id="ERROR-RETURN-IGNORED",
                        file_path=caller_sym.file_path,
                        line=edge.call_site_line,
                        message=(
                            f"`{caller_sym.name}()` 调用 `{sym.name}()` "
                            f"但未检查其返回的错误/可选值，可能遗漏错误处理。"
                        ),
                        metadata={
                            "callee": qname,
                            "caller": edge.caller,
                        },
                    )
                    if finding:
                        findings.append(finding)

        return findings[:20]

    # ──────────────────────────────────────────────────────────────────
    # Helper Methods
    # ──────────────────────────────────────────────────────────────────

    def _call_return_is_ignored(self, edge: CallEdge, pci: PCIResult) -> bool:
        """Heuristic: check if a function call's return value is used."""
        # This is a simplified check — in reality we'd need AST analysis
        # For now, use a conservative approach: only flag Go-style error handling
        callee_summary = pci.function_summaries.get(edge.callee)
        if not callee_summary:
            return False

        # For Go, check if the language is Go and function returns error
        sym = pci.symbol_table.lookup(edge.callee)
        if sym and sym.language == "go" and callee_summary.return_value_is_error:
            # In Go, ignoring error is a common anti-pattern
            # Check if the call site line looks like a bare call (no assignment)
            # This requires source lines — for now, always flag Go error returns
            # that are called from entry points or public functions
            caller_sym = pci.symbol_table.lookup(edge.caller)
            if caller_sym and caller_sym.visibility.value == "public":
                return True

        return False

    def _get_lines_around(
        self,
        file_path: str,
        line: int,
        after: int = 5,
        pci: PCIResult | None = None,
    ) -> list[str]:
        """Get source lines around a given line number."""
        # Prefer PCI file_lines cache
        if pci is not None:
            lines = pci.file_lines.get(file_path, [])
            if lines:
                start = max(0, line - 1)
                end = min(len(lines), line + after)
                return lines[start:end]

        # Fallback: read from disk using project_root
        try:
            project_root = getattr(self, "_project_root", None)
            if project_root:
                full_path = Path(project_root) / file_path
            else:
                full_path = Path(file_path)

            if not full_path.exists():
                return []

            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, line - 1)
            end = min(len(lines), line + after)
            return lines[start:end]
        except Exception:
            return []

    @staticmethod
    def _format_chain_description(header: str, chain: list[CallChainStep]) -> str:
        """Format a finding description with call chain evidence."""
        parts = [header, "", "调用链路:"]
        for i, step in enumerate(chain):
            prefix = "→" if i > 0 else "●"
            parts.append(f"  {prefix} {step.file}:{step.line}  {step.function}() — {step.action}")
        return "\n".join(parts)

    # ──────────────────────────────────────────────────────────────────
    # Business Process Level (L7)
    # ──────────────────────────────────────────────────────────────────

    def _detect_business_process_issues(self, pci: PCIResult, ctx: ScanContext) -> list[Finding]:
        """Run business process-level detection (L7 analysis)."""
        try:
            from codeguardian.core.call_graph.process_detector import ProcessDetector
            from codeguardian.core.call_graph.process_analyzer import ProcessAnalyzer

            detector = ProcessDetector(max_depth=8, max_processes=100)
            processes = detector.detect(pci)

            if not processes:
                return []

            analyzer = ProcessAnalyzer()
            return analyzer.analyze(processes, pci)
        except Exception as e:
            logger.debug("Business process detection failed: %s", e)
            return []
