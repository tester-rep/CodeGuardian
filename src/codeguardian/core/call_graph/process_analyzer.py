"""Business Process Analyzer — detects flow-level bugs that no single-function check can find.

Rules detect issues that only emerge when viewing the complete business operation:
- Transaction consistency (multiple writes without boundary)
- Partial failure risk (writes before throwing calls)
- Cascading timeout risk (many external calls in sequence)
- Auth/audit gaps on sensitive operations
- Idempotency missing on mutating endpoints
- Error swallowing mid-flow
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import uuid4

from codeguardian.engines.rule_helpers import RuleSpec, RuleHit, build_finding as _build_finding
from codeguardian.engines.rule_registry import register_rules
from codeguardian.models.enums import Confidence, Severity

if TYPE_CHECKING:
    from codeguardian.core.call_graph.pci_builder import PCIResult
    from codeguardian.core.call_graph.process_detector import BusinessProcess, EntryType
    from codeguardian.models.finding import Finding

logger = logging.getLogger(__name__)

ENGINE_NAME = "business_process"

# ═══════════════════════════════════════════════════════════════════════
# Rule Definitions
# ═══════════════════════════════════════════════════════════════════════

_RULES = register_rules(ENGINE_NAME, [
    # Tier 1: Transaction Consistency
    RuleSpec(
        rule_id="BIZ-NO-TRANSACTION-BOUNDARY",
        title="业务流程多写操作无事务保护 — 部分失败将导致数据不一致",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="defect",
        risk_priority="must-fix",
        tags=("business-process", "transaction", "consistency", "architecture"),
        description_zh=(
            "业务流程中存在多个写操作（数据库/文件/消息），但整个流程无事务边界包裹。"
            "若中间步骤失败，已执行的写操作无法回滚，导致数据不一致。"
        ),
        applicable_languages=("python", "java", "go"),
    ),
    RuleSpec(
        rule_id="BIZ-PARTIAL-FAILURE-RISK",
        title="业务流程写操作间存在可抛异常调用 — 部分提交风险",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="defect",
        risk_priority="must-fix",
        tags=("business-process", "transaction", "partial-failure"),
        description_zh=(
            "业务流程中两个写操作之间存在可能抛出异常的调用。"
            "第一个写操作成功后若后续调用失败，已写入的数据无法撤回。"
        ),
        applicable_languages=("python", "java", "go"),
    ),

    # Tier 2: Timeout/Resilience
    RuleSpec(
        rule_id="BIZ-CASCADING-TIMEOUT",
        title="业务流程串行多个外部调用 — 级联超时风险",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="performance",
        tags=("business-process", "timeout", "resilience", "architecture"),
        description_zh=(
            "业务流程中串行调用了多个外部服务（HTTP/RPC/数据库），"
            "总延迟为各调用延迟之和，可能超过入口层超时阈值导致整个请求失败。"
        ),
        applicable_languages=("python", "java", "go"),
    ),

    # Tier 3: Security/Auth
    RuleSpec(
        rule_id="BIZ-SENSITIVE-NO-AUDIT",
        title="敏感业务操作无审计日志 — 操作不可追溯",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="security",
        tags=("business-process", "audit", "compliance"),
        description_zh=(
            "涉及资金/权限/用户数据变更的业务流程中，"
            "整个调用链上未发现审计日志记录，敏感操作不可追溯。"
        ),
        applicable_languages=("python", "java", "go"),
        cwe_ids=("CWE-778",),
    ),
    RuleSpec(
        rule_id="BIZ-MULTI-ENTRY-NO-AUTH",
        title="敏感业务流程入口无权限校验 — 越权风险",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="security",
        tags=("business-process", "auth", "access-control"),
        description_zh=(
            "包含敏感操作（数据变更/资金操作）的业务流程入口处"
            "未发现权限校验逻辑，存在未授权访问风险。"
        ),
        applicable_languages=("python", "java", "go"),
        cwe_ids=("CWE-862",),
        owasp=("A01:2021",),
    ),

    # Tier 4: Idempotency
    RuleSpec(
        rule_id="BIZ-NOT-IDEMPOTENT",
        title="有副作用的业务流程无幂等保护 — 重试将重复执行",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="defect",
        tags=("business-process", "idempotency", "retry-safety"),
        description_zh=(
            "业务流程包含不可逆副作用（支付/发送/创建），但入口处无幂等键检查。"
            "网络重试或用户重复提交将导致操作被多次执行。"
        ),
        applicable_languages=("python", "java", "go"),
    ),

    # Tier 5: Error Handling
    RuleSpec(
        rule_id="BIZ-ERROR-SWALLOWED-MIDFLOW",
        title="业务流程中间环节吞没异常 — 后续步骤基于错误状态执行",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="defect",
        tags=("business-process", "error-handling", "silent-failure"),
        description_zh=(
            "业务流程中某个中间函数捕获了所有异常但未重新抛出，"
            "导致上游无法感知失败，后续步骤可能基于无效状态继续执行。"
        ),
        applicable_languages=("python", "java", "go"),
    ),
    RuleSpec(
        rule_id="BIZ-READ-WRITE-NO-LOCK",
        title="业务流程先读后写同一状态无并发保护 — TOCTOU风险",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="defect",
        tags=("business-process", "concurrency", "toctou", "race-condition"),
        description_zh=(
            "业务流程中一个函数读取状态（余额/库存/权限），另一个函数基于该状态执行写操作，"
            "但两者之间无锁/乐观锁/CAS保护。并发时可能产生竞态条件。"
        ),
        applicable_languages=("python", "java", "go"),
        cwe_ids=("CWE-367",),
    ),

    # Tier 6: N+1 I/O Pattern
    RuleSpec(
        rule_id="BIZ-IO-IN-LOOP",
        title="循环内执行I/O操作 — N+1查询/调用模式",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="performance",
        risk_priority="should-fix",
        tags=("business-process", "performance", "n-plus-one", "io"),
        description_zh=(
            "业务流程中某个函数在循环（for/while）内执行数据库查询或外部HTTP调用。"
            "当循环迭代N次时，产生N次网络往返，总延迟为N×单次延迟。"
            "应改为批量查询（IN/batch API）或预加载。"
        ),
        applicable_languages=("python", "java", "go"),
    ),

    # Tier 7: Sensitive Data Leak
    RuleSpec(
        rule_id="BIZ-SENSITIVE-DATA-LEAK",
        title="敏感数据经调用链泄漏到日志/响应 — 信息泄露风险",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="security",
        risk_priority="must-fix",
        tags=("business-process", "security", "data-leak", "sensitive"),
        description_zh=(
            "业务流程中函数读取敏感字段（password/token/secret/key），"
            "经过调用链传播后到达日志输出或HTTP响应序列化，"
            "可能导致敏感信息泄露到日志文件或客户端。"
        ),
        applicable_languages=("python", "java", "go"),
        cwe_ids=("CWE-532", "CWE-200"),
        owasp=("A01:2021",),
    ),
])

_RULE_MAP: dict[str, RuleSpec] = {r.rule_id: r for r in _RULES}


# ═══════════════════════════════════════════════════════════════════════
# Finding Builder
# ═══════════════════════════════════════════════════════════════════════

def _make_finding(
    rule_id: str,
    file_path: str,
    line: int,
    message: str,
    metadata: dict | None = None,
) -> Finding | None:
    """Create a Finding from a business process rule hit."""
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
    finding_id = f"BIZ-{uuid4().hex[:8]}"
    return _build_finding(hit, [], finding_id, ENGINE_NAME)


# ═══════════════════════════════════════════════════════════════════════
# Process Analyzer
# ═══════════════════════════════════════════════════════════════════════

class ProcessAnalyzer:
    """Analyzes BusinessProcess objects for flow-level bugs."""

    def analyze(self, processes: list[BusinessProcess], pci: PCIResult) -> list[Finding]:
        """Run all flow-level detection rules on discovered processes."""
        findings: list[Finding] = []

        for process in processes:
            findings.extend(self._check_transaction_consistency(process, pci))
            findings.extend(self._check_cascading_timeout(process, pci))
            findings.extend(self._check_sensitive_no_audit(process, pci))
            findings.extend(self._check_auth_gap(process, pci))
            findings.extend(self._check_idempotency(process, pci))
            findings.extend(self._check_error_swallowing(process, pci))
            findings.extend(self._check_read_write_race(process, pci))
            findings.extend(self._check_io_in_loop(process, pci))
            findings.extend(self._check_sensitive_data_leak(process, pci))

        logger.info(
            "ProcessAnalyzer: %d processes → %d findings",
            len(processes), len(findings),
        )
        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 1: Transaction Consistency
    # ──────────────────────────────────────────────────────────────────

    def _check_transaction_consistency(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect multiple writes without transaction boundary."""
        findings: list[Finding] = []

        if not process.has_multiple_writes:
            return findings

        if process.has_transaction:
            return findings

        # Check if writes happen in functions that may_throw between them
        summaries = pci.function_summaries
        write_funcs = process.write_operations

        # Find throwing functions between writes
        throwing_between = False
        for qname in process.all_functions:
            s = summaries.get(qname)
            if s and s.may_throw and qname not in write_funcs:
                throwing_between = True
                break

        if throwing_between:
            # More severe: partial failure risk
            entry_sym = pci.symbol_table.lookup(process.entry_point)
            if entry_sym:
                msg = (
                    f"业务流程 `{entry_sym.name}()` 包含 {len(write_funcs)} 个写操作，"
                    f"写操作之间存在可能抛异常的调用，但整个流程无事务包裹。\n"
                    f"部分失败时已写入数据无法回滚。\n\n"
                    f"写操作: {', '.join(w.split('.')[-1] + '()' for w in write_funcs[:5])}\n"
                    f"流程深度: {process.max_depth} 层，涉及 {len(process.all_functions)} 个函数"
                )
                finding = _make_finding(
                    "BIZ-PARTIAL-FAILURE-RISK",
                    entry_sym.file_path,
                    entry_sym.start_line,
                    msg,
                    metadata={"entry": process.entry_point, "write_count": str(len(write_funcs))},
                )
                if finding:
                    findings.append(finding)
        else:
            # Still worth flagging: multiple writes without transaction
            entry_sym = pci.symbol_table.lookup(process.entry_point)
            if entry_sym:
                msg = (
                    f"业务流程 `{entry_sym.name}()` 包含 {len(write_funcs)} 个写操作"
                    f"但无事务边界保护。\n\n"
                    f"写操作: {', '.join(w.split('.')[-1] + '()' for w in write_funcs[:5])}"
                )
                finding = _make_finding(
                    "BIZ-NO-TRANSACTION-BOUNDARY",
                    entry_sym.file_path,
                    entry_sym.start_line,
                    msg,
                    metadata={"entry": process.entry_point, "write_count": str(len(write_funcs))},
                )
                if finding:
                    findings.append(finding)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 2: Cascading Timeout
    # ──────────────────────────────────────────────────────────────────

    def _check_cascading_timeout(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect flows with many sequential external calls (timeout risk)."""
        findings: list[Finding] = []

        # Threshold: ≥3 external calls in one flow is risky
        if process.external_call_count < 3:
            return findings

        # Only flag HTTP handlers (they have client-side timeouts)
        from codeguardian.core.call_graph.process_detector import EntryType
        if process.entry_type not in (EntryType.HTTP_HANDLER, EntryType.PUBLIC_API):
            return findings

        entry_sym = pci.symbol_table.lookup(process.entry_point)
        if not entry_sym:
            return findings

        external_names = [
            q.split(".")[-1] + "()"
            for q in process.external_calls[:6]
        ]

        msg = (
            f"业务流程 `{entry_sym.name}()` 串行调用了 {process.external_call_count} "
            f"个外部/IO操作，总延迟为各调用延迟之和。\n"
            f"若某个外部服务响应慢，整个请求将超时失败。\n\n"
            f"外部调用: {', '.join(external_names)}\n"
            f"建议: 并行化独立调用、添加超时控制、或引入熔断机制。"
        )
        finding = _make_finding(
            "BIZ-CASCADING-TIMEOUT",
            entry_sym.file_path,
            entry_sym.start_line,
            msg,
            metadata={"external_count": str(process.external_call_count)},
        )
        if finding:
            findings.append(finding)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 3: Sensitive Operation Audit
    # ──────────────────────────────────────────────────────────────────

    def _check_sensitive_no_audit(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect sensitive operations without audit logging."""
        findings: list[Finding] = []

        if not process.is_sensitive:
            return findings

        if process.has_audit_log:
            return findings

        entry_sym = pci.symbol_table.lookup(process.entry_point)
        if not entry_sym:
            return findings

        sensitive_names = [q.split(".")[-1] for q in process.sensitive_operations[:5]]
        msg = (
            f"业务流程 `{entry_sym.name}()` 包含敏感操作 "
            f"({', '.join(sensitive_names)})，"
            f"但整个调用链中未发现审计日志记录。\n"
            f"敏感操作不可追溯，不符合安全审计要求。"
        )
        finding = _make_finding(
            "BIZ-SENSITIVE-NO-AUDIT",
            entry_sym.file_path,
            entry_sym.start_line,
            msg,
            metadata={"sensitive_ops": ", ".join(sensitive_names)},
        )
        if finding:
            findings.append(finding)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 3: Auth Gap
    # ──────────────────────────────────────────────────────────────────

    def _check_auth_gap(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect sensitive flows without auth check at entry."""
        findings: list[Finding] = []

        # Only check if flow has writes or sensitive ops
        if not process.has_multiple_writes and not process.is_sensitive:
            return findings

        if process.has_auth_check:
            return findings

        # Only flag HTTP handlers (internal calls may have auth elsewhere)
        from codeguardian.core.call_graph.process_detector import EntryType
        if process.entry_type != EntryType.HTTP_HANDLER:
            return findings

        entry_sym = pci.symbol_table.lookup(process.entry_point)
        if not entry_sym:
            return findings

        msg = (
            f"HTTP处理函数 `{entry_sym.name}()` 包含数据变更操作，"
            f"但入口处及调用链中未发现权限校验逻辑。\n"
            f"存在未授权访问风险。\n\n"
            f"写操作数: {len(process.write_operations)}, "
            f"敏感操作: {len(process.sensitive_operations)}"
        )
        finding = _make_finding(
            "BIZ-MULTI-ENTRY-NO-AUTH",
            entry_sym.file_path,
            entry_sym.start_line,
            msg,
        )
        if finding:
            findings.append(finding)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 4: Idempotency
    # ──────────────────────────────────────────────────────────────────

    def _check_idempotency(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect mutating endpoints without idempotency protection."""
        findings: list[Finding] = []

        # Only POST/PUT handlers with sensitive or write operations
        from codeguardian.core.call_graph.process_detector import EntryType
        if process.entry_type != EntryType.HTTP_HANDLER:
            return findings

        if not process.is_sensitive and not process.has_multiple_writes:
            return findings

        if process.has_idempotency_check:
            return findings

        entry_sym = pci.symbol_table.lookup(process.entry_point)
        if not entry_sym:
            return findings

        # Heuristic: only flag if it looks like a POST/create/transfer handler
        name_lower = entry_sym.name.lower()
        mutating_indicators = {"create", "post", "transfer", "pay", "send", "submit", "order"}
        if not any(ind in name_lower for ind in mutating_indicators):
            return findings

        msg = (
            f"业务流程 `{entry_sym.name}()` 包含不可逆副作用（写操作/敏感操作），"
            f"但未检测到幂等键/去重机制。\n"
            f"网络重试或用户重复点击将导致操作被多次执行。"
        )
        finding = _make_finding(
            "BIZ-NOT-IDEMPOTENT",
            entry_sym.file_path,
            entry_sym.start_line,
            msg,
        )
        if finding:
            findings.append(finding)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 5: Error Swallowing
    # ──────────────────────────────────────────────────────────────────

    def _check_error_swallowing(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect mid-flow error swallowing that hides failures."""
        findings: list[Finding] = []

        if not process.error_swallowers:
            return findings

        # Only flag if there are operations AFTER the swallower
        # (If swallower is at the end, it's less critical)
        for swallower in process.error_swallowers[:3]:
            # Check if swallower is a middle node (not the entry or a leaf)
            swallower_node = next(
                (n for n in process.nodes if n.qualified_name == swallower), None,
            )
            if swallower_node is None:
                continue
            if swallower_node.depth == 0:
                continue  # Entry point catching is different
            if swallower_node.depth >= process.max_depth - 1:
                continue  # Leaf — less impactful

            sym = pci.symbol_table.lookup(swallower)
            if not sym:
                continue

            entry_sym = pci.symbol_table.lookup(process.entry_point)
            entry_name = entry_sym.name if entry_sym else process.entry_point

            msg = (
                f"业务流程 `{entry_name}()` 的中间环节 `{sym.name}()` "
                f"捕获了所有异常但未重新抛出。\n"
                f"上游（调用方）无法感知此处失败，"
                f"后续步骤将基于无效/不完整状态继续执行。\n\n"
                f"位于流程第 {swallower_node.depth} 层（共 {process.max_depth} 层）"
            )
            finding = _make_finding(
                "BIZ-ERROR-SWALLOWED-MIDFLOW",
                sym.file_path,
                sym.start_line,
                msg,
                metadata={"swallower": swallower, "entry": process.entry_point},
            )
            if finding:
                findings.append(finding)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 5: Read-Write Race (TOCTOU)
    # ──────────────────────────────────────────────────────────────────

    def _check_read_write_race(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect read-then-write on same state without locking."""
        findings: list[Finding] = []

        if not process.read_then_write_fields:
            return findings

        # Check if the process has any locking
        summaries = pci.function_summaries
        has_lock = any(
            summaries.get(q) and (summaries[q].acquires_lock or summaries[q].holds_lock_throughout)
            for q in process.all_functions
        )
        if has_lock:
            return findings

        # Only flag HTTP handlers (concurrent requests likely)
        from codeguardian.core.call_graph.process_detector import EntryType
        if process.entry_type not in (EntryType.HTTP_HANDLER, EntryType.MQ_CONSUMER):
            return findings

        entry_sym = pci.symbol_table.lookup(process.entry_point)
        if not entry_sym:
            return findings

        # Take first few read-write pairs
        pairs = process.read_then_write_fields[:3]
        pair_descriptions = [f"字段`{field}`: {flow}" for field, flow in pairs]

        msg = (
            f"业务流程 `{entry_sym.name}()` 中不同函数先读后写同一状态，"
            f"但流程中无锁/乐观锁保护。\n"
            f"并发请求时可能产生竞态条件（TOCTOU）。\n\n"
            f"读写链路:\n" + "\n".join(f"  • {d}" for d in pair_descriptions)
        )
        finding = _make_finding(
            "BIZ-READ-WRITE-NO-LOCK",
            entry_sym.file_path,
            entry_sym.start_line,
            msg,
            metadata={"field_count": str(len(process.read_then_write_fields))},
        )
        if finding:
            findings.append(finding)

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Tier 6: N+1 I/O in Loop
    # ──────────────────────────────────────────────────────────────────

    def _check_io_in_loop(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect I/O calls inside loops (N+1 query/call pattern)."""
        import re

        findings: list[Finding] = []
        summaries = pci.function_summaries
        symbol_table = pci.symbol_table

        # Only check processes with I/O operations
        if not process.external_calls:
            return findings

        # Loop patterns per language
        loop_re = re.compile(r"\b(?:for|while)\b")
        # I/O call patterns that indicate DB/HTTP operations inside loops
        io_call_patterns = re.compile(
            r"(?:\.execute|\.query|\.find|\.get|\.fetch|\.select|"
            r"requests\.|http\.|\.send\(|\.post\(|\.put\(|"
            r"db\.|cursor\.|session\.|\.Query|\.Exec|\.Find|"
            r"\.findOne|\.findAll|\.save\(|\.delete\()",
            re.IGNORECASE,
        )

        for qname in process.all_functions:
            summary = summaries.get(qname)
            if summary is None or not summary.has_io:
                continue

            sym = symbol_table.lookup(qname)
            if sym is None:
                continue

            # Get function source
            file_lines = pci.file_lines.get(sym.file_path)
            if not file_lines:
                continue

            body_start = max(0, sym.start_line - 1)
            body_end = min(len(file_lines), sym.end_line)
            body_lines = file_lines[body_start:body_end]

            # Track indentation-based nesting: find loops, then check if IO inside
            in_loop = False
            loop_indent = 0
            io_in_loop_line = 0

            for i, line in enumerate(body_lines):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                    continue

                indent = len(line) - len(line.lstrip())

                if loop_re.search(stripped):
                    in_loop = True
                    loop_indent = indent
                elif in_loop and indent <= loop_indent and stripped and not stripped.startswith(("}", ")")):
                    in_loop = False

                if in_loop and indent > loop_indent and io_call_patterns.search(stripped):
                    io_in_loop_line = sym.start_line + i
                    break

            if io_in_loop_line > 0:
                entry_sym = symbol_table.lookup(process.entry_point)
                entry_name = entry_sym.name if entry_sym else process.entry_point.split(".")[-1]

                msg = (
                    f"函数 `{sym.name}()` 在循环内执行I/O操作（第{io_in_loop_line}行），"
                    f"属于业务流程 `{entry_name}()`。\n"
                    f"当循环迭代N次时产生N次网络/DB往返，总延迟 = N × 单次延迟。\n\n"
                    f"建议: 使用批量查询（WHERE IN / batch API）或在循环外预加载数据。"
                )
                finding = _make_finding(
                    "BIZ-IO-IN-LOOP",
                    sym.file_path,
                    io_in_loop_line,
                    msg,
                    metadata={
                        "io_function": qname,
                        "entry_point": process.entry_point,
                    },
                )
                if finding:
                    findings.append(finding)

        return findings[:10]  # Cap to avoid noise

    # ──────────────────────────────────────────────────────────────────
    # Tier 7: Sensitive Data Leak
    # ──────────────────────────────────────────────────────────────────

    def _check_sensitive_data_leak(
        self, process: BusinessProcess, pci: PCIResult,
    ) -> list[Finding]:
        """Detect sensitive fields reaching log/response sinks via call chain."""
        findings: list[Finding] = []
        summaries = pci.function_summaries
        call_graph = pci.call_graph
        symbol_table = pci.symbol_table

        # Sensitive field keywords
        sensitive_keywords = {
            "password", "passwd", "pwd", "token", "secret", "key",
            "private", "ssn", "credit_card", "card_number", "cvv",
            "api_key", "apikey", "auth_token", "access_token",
            "refresh_token", "session_id",
        }

        # Find functions that read sensitive fields
        sensitive_readers: dict[str, list[str]] = {}  # qname -> [field_names]
        for qname in process.all_functions:
            s = summaries.get(qname)
            if s is None:
                continue
            for field in s.reads_fields:
                field_lower = field.lower()
                if any(kw in field_lower for kw in sensitive_keywords):
                    if qname not in sensitive_readers:
                        sensitive_readers[qname] = []
                    sensitive_readers[qname].append(field)

        if not sensitive_readers:
            return findings

        # Find sink functions (log, print, serialize, response)
        sink_keywords = {"log", "print", "debug", "info", "warn", "error",
                         "serialize", "json", "response", "render", "write",
                         "send", "output", "dump", "format"}

        sinks: list[str] = []
        for qname in process.all_functions:
            name_lower = qname.split(".")[-1].lower()
            if any(kw in name_lower for kw in sink_keywords):
                sinks.append(qname)
            # Also check if function has_io and looks like logging
            s = summaries.get(qname)
            if s and s.has_io and any(kw in name_lower for kw in ("log", "print", "write")):
                if qname not in sinks:
                    sinks.append(qname)

        if not sinks:
            return findings

        # Check paths from sensitive readers to sinks
        for reader_qname, fields in sensitive_readers.items():
            for sink_qname in sinks:
                if reader_qname == sink_qname:
                    # Same function reads sensitive data and logs — direct leak
                    sym = symbol_table.lookup(reader_qname)
                    if sym:
                        msg = (
                            f"函数 `{sym.name}()` 读取敏感字段 "
                            f"({', '.join(f'`{f}`' for f in fields[:3])}) "
                            f"并在同一函数中输出到日志/响应，可能泄露敏感信息。"
                        )
                        finding = _make_finding(
                            "BIZ-SENSITIVE-DATA-LEAK",
                            sym.file_path,
                            sym.start_line,
                            msg,
                            metadata={"sensitive_fields": ",".join(fields[:3]), "sink": sink_qname},
                        )
                        if finding:
                            findings.append(finding)
                    continue

                # Cross-function: check if there's a call path
                paths = call_graph.paths_between(
                    reader_qname, sink_qname, max_depth=3, min_confidence=0.5,
                )
                if not paths:
                    continue

                # Check if any function on the path is a sanitizer/masker
                path = paths[0]
                sanitized = False
                for sym_name in path.symbols():
                    s = summaries.get(sym_name)
                    if s and s.is_sanitizer:
                        sanitized = True
                        break
                    # Also check name for masking patterns
                    name_lower = sym_name.split(".")[-1].lower()
                    if any(m in name_lower for m in ("mask", "redact", "sanitize", "censor", "hide")):
                        sanitized = True
                        break

                if sanitized:
                    continue

                reader_sym = symbol_table.lookup(reader_qname)
                sink_sym = symbol_table.lookup(sink_qname)
                if not reader_sym or not sink_sym:
                    continue

                chain_funcs = " → ".join(s.split(".")[-1] + "()" for s in path.symbols()[:5])
                msg = (
                    f"敏感字段 ({', '.join(f'`{f}`' for f in fields[:3])}) "
                    f"从 `{reader_sym.name}()` 经调用链传播到 `{sink_sym.name}()`。\n"
                    f"路径: {chain_funcs}\n"
                    f"路径上无脱敏/掩码处理，可能导致敏感信息泄露到日志或客户端响应。"
                )
                finding = _make_finding(
                    "BIZ-SENSITIVE-DATA-LEAK",
                    sink_sym.file_path,
                    sink_sym.start_line,
                    msg,
                    metadata={
                        "sensitive_fields": ",".join(fields[:3]),
                        "reader": reader_qname,
                        "sink": sink_qname,
                        "path_depth": str(path.depth),
                    },
                )
                if finding:
                    findings.append(finding)
                break  # One finding per reader is enough

        return findings[:10]
