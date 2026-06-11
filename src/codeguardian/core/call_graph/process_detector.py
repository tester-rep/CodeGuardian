"""Business Process Detection — identifies complete user-facing operation flows.

A BusinessProcess = entry point → full DFS call tree = one complete user operation.
ProcessDetector discovers entry points (HTTP handlers, CLI commands, MQ consumers,
scheduled tasks) and builds the call tree for each.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codeguardian.core.call_graph.function_summary import FunctionSummary
    from codeguardian.core.call_graph.graph import CallEdge, CallGraph
    from codeguardian.core.call_graph.pci_builder import PCIResult
    from codeguardian.core.call_graph.symbol_table import Symbol, SymbolTable

logger = logging.getLogger(__name__)


class EntryType(Enum):
    """Classification of business process entry points."""

    HTTP_HANDLER = "http_handler"
    CLI_COMMAND = "cli_command"
    MQ_CONSUMER = "mq_consumer"
    SCHEDULED = "scheduled"
    EVENT_HANDLER = "event_handler"
    MAIN = "main"
    PUBLIC_API = "public_api"  # Exported/public functions at module boundary


@dataclass(slots=True)
class ProcessNode:
    """A node in the business process call tree."""

    qualified_name: str
    file_path: str
    line: int
    depth: int  # Distance from entry point
    call_form: str = ""  # How it was called


@dataclass
class BusinessProcess:
    """A complete user-facing operation traced from entry point through call tree."""

    entry_point: str  # Qualified name of entry function
    entry_type: EntryType
    entry_file: str
    entry_line: int

    # Call tree (BFS order)
    nodes: list[ProcessNode] = field(default_factory=list)
    all_functions: set[str] = field(default_factory=set)

    # Aggregated behavioral properties (computed from FunctionSummaries)
    write_operations: list[str] = field(default_factory=list)
    read_then_write_fields: list[tuple[str, str]] = field(default_factory=list)  # (field, function)
    external_calls: list[str] = field(default_factory=list)  # Functions with has_io
    has_transaction: bool = False
    has_auth_check: bool = False
    has_audit_log: bool = False
    has_rate_limit: bool = False
    has_idempotency_check: bool = False
    sensitive_operations: list[str] = field(default_factory=list)
    total_may_throw: set[str] = field(default_factory=set)
    error_swallowers: list[str] = field(default_factory=list)  # Functions that catch-all without rethrow
    max_depth: int = 0
    external_call_count: int = 0

    @property
    def is_trivial(self) -> bool:
        """Process with ≤2 functions is too simple for flow-level analysis."""
        return len(self.all_functions) <= 2

    @property
    def has_multiple_writes(self) -> bool:
        return len(self.write_operations) >= 2

    @property
    def is_sensitive(self) -> bool:
        return bool(self.sensitive_operations)


# ═══════════════════════════════════════════════════════════════════════
# Entry Point Detection Patterns
# ═══════════════════════════════════════════════════════════════════════

# Python frameworks
_PYTHON_HTTP_PATTERNS = [
    re.compile(r"@app\.(?:route|get|post|put|delete|patch)\b"),
    re.compile(r"@router\.(?:get|post|put|delete|patch|api_route)\b"),
    re.compile(r"@(?:blueprint|bp)\.(?:route|get|post|put|delete)\b"),
    re.compile(r"class\s+\w+(?:View|ViewSet|APIView)\b"),
]
_PYTHON_MQ_PATTERNS = [
    re.compile(r"@(?:celery|app)\.task\b"),
    re.compile(r"@(?:consumer|subscriber|handler)\.(?:listen|subscribe|handle)\b"),
    re.compile(r"def\s+(?:on_message|handle_event|process_message)\b"),
]
_PYTHON_SCHEDULED_PATTERNS = [
    re.compile(r"@(?:scheduler|schedule|cron|periodic_task)\b"),
    re.compile(r"@celery\.task.*bind.*schedule"),
]
_PYTHON_CLI_PATTERNS = [
    re.compile(r"@(?:click\.command|app\.command|typer\.command)\b"),
    re.compile(r"def\s+(?:main|cli|run)\b"),
]

# Java frameworks
_JAVA_HTTP_PATTERNS = [
    re.compile(r"@(?:Request|Get|Post|Put|Delete|Patch)Mapping\b"),
    re.compile(r"@(?:Path|GET|POST|PUT|DELETE)\b"),  # JAX-RS
    re.compile(r"@RestController\b"),
]
_JAVA_MQ_PATTERNS = [
    re.compile(r"@(?:RabbitListener|KafkaListener|JmsListener|StreamListener)\b"),
    re.compile(r"@(?:EventHandler|EventListener)\b"),
]
_JAVA_SCHEDULED_PATTERNS = [
    re.compile(r"@Scheduled\b"),
    re.compile(r"@(?:Async)\b.*(?:scheduled|cron)"),
]

# Go frameworks
_GO_HTTP_PATTERNS = [
    re.compile(r"(?:router|r|mux|e|g|app)\.(?:GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\b"),
    re.compile(r"http\.Handle(?:Func)?\b"),
    re.compile(r"gin\.(?:Context|HandlerFunc)\b"),
]
_GO_MQ_PATTERNS = [
    re.compile(r"(?:Subscribe|Consume|Handle)\b.*(?:message|event|msg)\b", re.IGNORECASE),
]

# Tokens indicating sensitive operations
_SENSITIVE_TOKENS = {
    "payment", "pay", "charge", "refund", "transfer", "withdraw", "deposit",
    "delete_user", "remove_user", "deactivate",
    "password", "reset_password", "change_password",
    "permission", "role", "grant", "revoke",
    "admin", "sudo", "escalate",
}

# Tokens indicating audit/logging
_AUDIT_TOKENS = {
    "audit", "audit_log", "log_action", "record_event",
    "activity_log", "track", "history",
}

# Tokens indicating auth checks
_AUTH_TOKENS = {
    "authenticate", "authorize", "check_permission", "require_auth",
    "login_required", "permission_required", "is_authenticated",
    "@login_required", "@permission_classes", "@requires_auth",
    "jwt", "token", "session",
}

# Tokens indicating rate limiting
_RATE_LIMIT_TOKENS = {
    "rate_limit", "throttle", "ratelimit", "limiter",
    "@rate_limit", "@throttle",
}

# Tokens indicating idempotency
_IDEMPOTENCY_TOKENS = {
    "idempotency", "idempotent", "idempotency_key", "request_id",
    "dedup", "deduplicate", "nonce",
}

# Tokens indicating transaction boundaries
_TRANSACTION_TOKENS = {
    "transaction", "begin_transaction", "commit", "rollback",
    "@transactional", "@atomic", "with_transaction",
    "BEGIN", "COMMIT", "ROLLBACK",
    "db.transaction", "session.begin",
    # Go
    "tx.Commit", "tx.Rollback", ".Begin(",
    # Python
    "atomic", "transaction.atomic",
}

# Tokens indicating write operations
_WRITE_TOKENS = {
    "save", "update", "delete", "insert", "create", "remove", "put",
    "write", "store", "persist", "commit",
    "execute", "executemany",  # SQL writes
    "send", "publish", "emit",  # Message sends
}


class ProcessDetector:
    """Discovers entry points and builds BusinessProcess objects from PCI."""

    def __init__(self, max_depth: int = 8, max_processes: int = 200) -> None:
        self.max_depth = max_depth
        self.max_processes = max_processes

    def detect(self, pci: PCIResult) -> list[BusinessProcess]:
        """Detect all business processes in the project."""
        symbol_table = pci.symbol_table
        call_graph = pci.call_graph
        summaries = pci.function_summaries

        # Step 1: Find entry points
        entries = self._find_entry_points(pci)

        if not entries:
            logger.debug("ProcessDetector: No entry points found")
            return []

        # Step 2: Build call tree for each entry point
        processes: list[BusinessProcess] = []
        for entry_qname, entry_type in entries[:self.max_processes]:
            sym = symbol_table.lookup(entry_qname)
            if sym is None:
                continue

            process = self._build_process(
                entry_qname, entry_type, sym, call_graph, summaries,
            )
            if not process.is_trivial:
                self._compute_aggregated_properties(process, summaries, pci)
                processes.append(process)

        logger.info(
            "ProcessDetector: %d entry points → %d non-trivial processes",
            len(entries), len(processes),
        )
        return processes

    def _find_entry_points(self, pci: PCIResult) -> list[tuple[str, EntryType]]:
        """Find all entry points by checking source lines for framework patterns."""
        entries: list[tuple[str, EntryType]] = []
        symbol_table = pci.symbol_table
        call_graph = pci.call_graph

        for sym in symbol_table.all_functions():
            entry_type = self._classify_entry_point(sym, pci)
            if entry_type is not None:
                entries.append((sym.qualified_name, entry_type))

        # Also consider graph-structural entry points (no callers)
        # But only if they're public functions, not private helpers
        for ep in call_graph.entry_points():
            if any(ep == e[0] for e in entries):
                continue  # Already found
            sym = symbol_table.lookup(ep)
            if sym is None:
                continue
            # Only consider public functions with meaningful names
            if sym.visibility.value == "public" and not sym.name.startswith("_"):
                # Must have at least 2 callees to be interesting
                callees = call_graph.callees_of(ep, depth=1)
                if len(callees) >= 2:
                    entries.append((ep, EntryType.PUBLIC_API))

        return entries

    def _classify_entry_point(self, sym: Symbol, pci: PCIResult) -> EntryType | None:
        """Classify a symbol as an entry point type based on source context."""
        # Read a few lines before the function definition for decorators
        file_lines = self._get_file_lines(sym.file_path, pci)
        if not file_lines:
            return None

        # Get decorator/annotation context (up to 5 lines before function start)
        context_start = max(0, sym.start_line - 6)
        context_end = min(len(file_lines), sym.start_line + 2)
        context = "\n".join(file_lines[context_start:context_end])

        lang = sym.language

        if lang == "python":
            return self._classify_python_entry(context, sym.name)
        elif lang == "java":
            return self._classify_java_entry(context, sym.name)
        elif lang == "go":
            return self._classify_go_entry(context, sym.name)

        return None

    def _classify_python_entry(self, context: str, func_name: str) -> EntryType | None:
        for pattern in _PYTHON_HTTP_PATTERNS:
            if pattern.search(context):
                return EntryType.HTTP_HANDLER
        for pattern in _PYTHON_MQ_PATTERNS:
            if pattern.search(context):
                return EntryType.MQ_CONSUMER
        for pattern in _PYTHON_SCHEDULED_PATTERNS:
            if pattern.search(context):
                return EntryType.SCHEDULED
        for pattern in _PYTHON_CLI_PATTERNS:
            if pattern.search(context):
                return EntryType.CLI_COMMAND
        if func_name == "main" or func_name == "__main__":
            return EntryType.MAIN
        return None

    def _classify_java_entry(self, context: str, func_name: str) -> EntryType | None:
        for pattern in _JAVA_HTTP_PATTERNS:
            if pattern.search(context):
                return EntryType.HTTP_HANDLER
        for pattern in _JAVA_MQ_PATTERNS:
            if pattern.search(context):
                return EntryType.MQ_CONSUMER
        for pattern in _JAVA_SCHEDULED_PATTERNS:
            if pattern.search(context):
                return EntryType.SCHEDULED
        if func_name == "main":
            return EntryType.MAIN
        return None

    def _classify_go_entry(self, context: str, func_name: str) -> EntryType | None:
        # Go handlers are typically registered, not decorated
        # Check if the function signature matches handler pattern
        if "http.ResponseWriter" in context or "gin.Context" in context or "echo.Context" in context:
            return EntryType.HTTP_HANDLER
        for pattern in _GO_HTTP_PATTERNS:
            if pattern.search(context):
                return EntryType.HTTP_HANDLER
        for pattern in _GO_MQ_PATTERNS:
            if pattern.search(context):
                return EntryType.MQ_CONSUMER
        if func_name == "main":
            return EntryType.MAIN
        return None

    def _build_process(
        self,
        entry_qname: str,
        entry_type: EntryType,
        entry_sym: Symbol,
        call_graph: CallGraph,
        summaries: dict[str, FunctionSummary],
    ) -> BusinessProcess:
        """BFS from entry point to build complete call tree."""
        process = BusinessProcess(
            entry_point=entry_qname,
            entry_type=entry_type,
            entry_file=entry_sym.file_path,
            entry_line=entry_sym.start_line,
        )

        visited: set[str] = {entry_qname}
        process.all_functions.add(entry_qname)
        process.nodes.append(ProcessNode(
            qualified_name=entry_qname,
            file_path=entry_sym.file_path,
            line=entry_sym.start_line,
            depth=0,
        ))

        queue: deque[tuple[str, int]] = deque([(entry_qname, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= self.max_depth:
                continue

            edges = call_graph.callees_of(current, depth=1, min_confidence=0.6)
            for edge in edges:
                if edge.callee in visited:
                    continue
                visited.add(edge.callee)
                process.all_functions.add(edge.callee)
                process.nodes.append(ProcessNode(
                    qualified_name=edge.callee,
                    file_path=edge.call_site_file,
                    line=edge.call_site_line,
                    depth=depth + 1,
                    call_form=edge.call_form.value,
                ))
                queue.append((edge.callee, depth + 1))

        process.max_depth = max((n.depth for n in process.nodes), default=0)
        return process

    def _compute_aggregated_properties(
        self,
        process: BusinessProcess,
        summaries: dict[str, FunctionSummary],
        pci: PCIResult,
    ) -> None:
        """Compute flow-level properties by aggregating function summaries."""
        all_read_fields: dict[str, list[str]] = {}  # field -> [functions that read it]
        all_write_fields: dict[str, list[str]] = {}  # field -> [functions that write it]

        for qname in process.all_functions:
            summary = summaries.get(qname)
            if summary is None:
                continue

            # Write operations
            if summary.writes_fields or summary.is_sink:
                process.write_operations.append(qname)

            # External calls
            if summary.has_io:
                process.external_calls.append(qname)
                process.external_call_count += 1

            # Exception accumulation
            process.total_may_throw.update(summary.may_throw)

            # Error swallowers
            if summary.catches and not summary.may_throw and not summary.has_finally:
                # Catches exceptions but doesn't rethrow — potential swallower
                broad_catches = {"Exception", "BaseException", "Throwable", "error"}
                if summary.catches & broad_catches:
                    process.error_swallowers.append(qname)

            # Sensitive operation detection
            name_lower = qname.lower().split(".")[-1]
            if any(token in name_lower for token in _SENSITIVE_TOKENS):
                process.sensitive_operations.append(qname)

            # Field tracking for read-then-write detection
            for f in summary.reads_fields:
                all_read_fields.setdefault(f, []).append(qname)
            for f in summary.writes_fields:
                all_write_fields.setdefault(f, []).append(qname)

        # Detect read-then-write on same field (potential race/TOCTOU)
        for field_name in all_read_fields:
            if field_name in all_write_fields:
                readers = all_read_fields[field_name]
                writers = all_write_fields[field_name]
                # If different functions read and write same field, flag it
                for reader in readers:
                    for writer in writers:
                        if reader != writer:
                            process.read_then_write_fields.append((field_name, f"{reader}→{writer}"))

        # Check for flow-level properties by scanning source context
        self._detect_flow_properties_from_source(process, summaries, pci)

    def _detect_flow_properties_from_source(
        self,
        process: BusinessProcess,
        summaries: dict[str, FunctionSummary],
        pci: PCIResult,
    ) -> None:
        """Scan source lines of process functions for transaction/auth/audit tokens."""
        for qname in process.all_functions:
            summary = summaries.get(qname)
            if summary is None:
                continue

            file_lines = self._get_file_lines(summary.file_path, pci)
            if not file_lines:
                continue

            # Get function body
            start = max(0, summary.start_line - 1)
            end = min(len(file_lines), summary.end_line)
            body = "\n".join(file_lines[start:end]).lower()

            # Transaction check
            if not process.has_transaction:
                if any(token.lower() in body for token in _TRANSACTION_TOKENS):
                    process.has_transaction = True

            # Auth check
            if not process.has_auth_check:
                if any(token in body for token in _AUTH_TOKENS):
                    process.has_auth_check = True

            # Audit log check
            if not process.has_audit_log:
                if any(token in body for token in _AUDIT_TOKENS):
                    process.has_audit_log = True

            # Rate limit check
            if not process.has_rate_limit:
                if any(token in body for token in _RATE_LIMIT_TOKENS):
                    process.has_rate_limit = True

            # Idempotency check
            if not process.has_idempotency_check:
                if any(token in body for token in _IDEMPOTENCY_TOKENS):
                    process.has_idempotency_check = True

            # Also check write operations by token
            if qname not in process.write_operations:
                if any(token in body for token in _WRITE_TOKENS):
                    process.write_operations.append(qname)

    def _get_file_lines(self, file_path: str, pci: PCIResult) -> list[str] | None:
        """Get cached file lines from PCI build result."""
        return pci.file_lines.get(file_path)
