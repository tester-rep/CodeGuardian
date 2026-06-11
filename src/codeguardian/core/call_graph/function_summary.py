"""FunctionSummary — per-function behavioral analysis for cross-function detection.

Summarizes: null return, exception escape, resource acquire/release,
taint propagation, field access, lock behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ResourceKind(Enum):
    """Types of resources tracked."""

    FILE = "file"
    CONNECTION = "connection"
    LOCK = "lock"
    STREAM = "stream"
    CURSOR = "cursor"
    TRANSACTION = "transaction"
    CHANNEL = "channel"
    GENERIC = "generic"


@dataclass(slots=True)
class ResourceAction:
    """A resource acquisition or release action."""

    kind: ResourceKind
    line: int
    variable: str = ""  # variable name holding the resource
    method: str = ""  # method used (open, acquire, close, release)


@dataclass(slots=True)
class TaintFlow:
    """Describes how taint flows through a function."""

    source_param: int  # parameter position that's the taint source (-1 = return from callee)
    sink_type: str  # "return" | "field_write" | "call_arg" | "sql" | "command" | "file"
    sink_detail: str = ""  # e.g., which callee and which arg position
    transforms: list[str] = field(default_factory=list)  # operations applied (no sanitization)
    sanitized: bool = False  # True if sanitizer exists on this flow path


@dataclass(slots=True)
class FunctionSummary:
    """Behavioral summary for a single function, computed from local analysis.

    Used by cross-function detection rules to reason about inter-procedural behavior
    without re-analyzing function bodies.
    """

    qualified_name: str
    file_path: str
    start_line: int = 0
    end_line: int = 0

    # ── Null behavior ──
    may_return_null: bool = False  # Can return None/null/nil
    null_return_lines: list[int] = field(default_factory=list)  # Lines with null returns
    # Parameter positions that, if null, propagate to return or deref
    nullable_params: set[int] = field(default_factory=set)

    # ── Exception behavior ──
    may_throw: set[str] = field(default_factory=set)  # Exception types that can escape
    always_throws: bool = False  # Function never returns normally (e.g., sys.exit)
    catches: set[str] = field(default_factory=set)  # Exception types caught internally
    has_finally: bool = False  # Has finally/defer block

    # ── Resource behavior ──
    acquires: list[ResourceAction] = field(default_factory=list)  # Resources opened
    releases: list[ResourceAction] = field(default_factory=list)  # Resources closed
    requires_cleanup: bool = False  # Caller must close something this returns
    uses_context_manager: bool = False  # Uses with/try-with-resources/defer

    # ── Taint behavior ──
    taint_flows: list[TaintFlow] = field(default_factory=list)  # Taint propagation paths
    is_sanitizer: bool = False  # This function sanitizes input
    is_source: bool = False  # This function produces tainted data (e.g., request param)
    is_sink: bool = False  # This function is a dangerous sink (e.g., SQL exec)

    # ── State behavior ──
    reads_fields: set[str] = field(default_factory=set)  # Instance/class fields read
    writes_fields: set[str] = field(default_factory=set)  # Instance/class fields written

    # ── Lock behavior ──
    acquires_lock: str | None = None  # Lock acquired (not released in same function)
    releases_lock: str | None = None  # Lock released
    holds_lock_throughout: bool = False  # Lock held from start to end

    # ── Side effects ──
    has_io: bool = False  # Performs I/O (file, network, etc.)
    is_pure: bool = False  # No side effects (heuristic)

    # ── Return value significance ──
    return_value_is_error: bool = False  # Returns error type (Go error, Result, etc.)
    return_value_is_optional: bool = False  # Returns Optional/Maybe/nullable type

    # ── Propagated (filled by summary propagation phase) ──
    transitive_may_throw: set[str] = field(default_factory=set)
    transitive_may_return_null: bool = False
    transitive_acquires_resource: bool = False


# ═══════════════════════════════════════════════════════════════════════
# Local summary computation from AST
# ═══════════════════════════════════════════════════════════════════════

# Known null-returning patterns per language
_NULL_LITERALS = {
    "python": {"None"},
    "java": {"null"},
    "go": {"nil"},
    "javascript": {"null", "undefined"},
    "typescript": {"null", "undefined"},
    "cpp": {"nullptr", "NULL", "0"},
    "csharp": {"null"},
}

# Known exception-raising patterns
_THROW_KEYWORDS = {
    "python": "raise",
    "java": "throw",
    "go": "panic",
    "javascript": "throw",
    "typescript": "throw",
    "cpp": "throw",
    "csharp": "throw",
}

# Known resource acquisition patterns
_RESOURCE_ACQUIRE_PATTERNS: dict[str, list[tuple[str, ResourceKind]]] = {
    "python": [
        ("open(", ResourceKind.FILE),
        (".connect(", ResourceKind.CONNECTION),
        (".cursor(", ResourceKind.CURSOR),
        ("Lock(", ResourceKind.LOCK),
        ("acquire(", ResourceKind.LOCK),
        ("socket(", ResourceKind.STREAM),
    ],
    "java": [
        ("new FileInputStream", ResourceKind.FILE),
        ("new FileOutputStream", ResourceKind.FILE),
        ("new BufferedReader", ResourceKind.STREAM),
        ("new BufferedWriter", ResourceKind.STREAM),
        (".getConnection(", ResourceKind.CONNECTION),
        ("DriverManager.getConnection", ResourceKind.CONNECTION),
        (".prepareStatement(", ResourceKind.CURSOR),
        (".createStatement(", ResourceKind.CURSOR),
        (".lock(", ResourceKind.LOCK),
        (".tryLock(", ResourceKind.LOCK),
        ("new Socket(", ResourceKind.STREAM),
        (".beginTransaction(", ResourceKind.TRANSACTION),
    ],
    "go": [
        ("os.Open(", ResourceKind.FILE),
        ("os.Create(", ResourceKind.FILE),
        (".Open(", ResourceKind.FILE),
        ("sql.Open(", ResourceKind.CONNECTION),
        (".Begin(", ResourceKind.TRANSACTION),
        (".Lock(", ResourceKind.LOCK),
        ("make(chan", ResourceKind.CHANNEL),
        ("net.Dial(", ResourceKind.STREAM),
        ("http.Get(", ResourceKind.STREAM),
    ],
}

# Known resource release patterns
_RESOURCE_RELEASE_PATTERNS: dict[str, list[tuple[str, ResourceKind]]] = {
    "python": [
        (".close(", ResourceKind.GENERIC),
        (".release(", ResourceKind.LOCK),
        (".shutdown(", ResourceKind.GENERIC),
    ],
    "java": [
        (".close(", ResourceKind.GENERIC),
        (".unlock(", ResourceKind.LOCK),
        (".release(", ResourceKind.LOCK),
        (".shutdown(", ResourceKind.GENERIC),
        (".commit(", ResourceKind.TRANSACTION),
        (".rollback(", ResourceKind.TRANSACTION),
    ],
    "go": [
        (".Close(", ResourceKind.GENERIC),
        (".Unlock(", ResourceKind.LOCK),
        ("defer ", ResourceKind.GENERIC),  # Go defer for cleanup
    ],
}

# Known taint sources (functions that produce untrusted data)
_TAINT_SOURCES = {
    "python": {
        "input", "raw_input",
        "request.args.get", "request.form.get", "request.json",
        "request.data", "request.values",
        "os.environ.get", "os.getenv",
    },
    "java": {
        "getParameter", "getHeader", "getQueryString",
        "getInputStream", "getReader",
        "readLine", "nextLine",
    },
    "go": {
        "r.URL.Query", "r.FormValue", "r.Header.Get",
        "r.Body", "os.Getenv",
        "bufio.NewReader", "bufio.NewScanner",
    },
}

# Known taint sinks (dangerous destinations)
_TAINT_SINKS = {
    "python": {
        "execute", "executemany", "raw",  # SQL
        "os.system", "subprocess.call", "subprocess.run", "subprocess.Popen",  # Command
        "eval", "exec",  # Code execution
        "open",  # File
    },
    "java": {
        "executeQuery", "executeUpdate", "execute", "prepareStatement",  # SQL
        "Runtime.exec", "ProcessBuilder",  # Command
        "new File(", "FileWriter",  # File
    },
    "go": {
        "db.Query", "db.Exec", "db.QueryRow",  # SQL
        "exec.Command",  # Command
        "os.Open", "os.Create",  # File
        "template.HTML",  # XSS
    },
}

# Known sanitizer functions
_SANITIZERS = {
    "python": {"escape", "quote", "sanitize", "clean", "strip_tags", "bleach.clean", "markupsafe.escape"},
    "java": {"escapeHtml", "escapeSql", "sanitize", "encode", "StringEscapeUtils"},
    "go": {"html.EscapeString", "url.QueryEscape", "template.HTMLEscapeString"},
}


def compute_local_summary(
    qualified_name: str,
    file_path: str,
    source_lines: list[str],
    start_line: int,
    end_line: int,
    language: str,
    return_type: str | None = None,
) -> FunctionSummary:
    """Compute a FunctionSummary from the source lines of a function body.

    This is local analysis only — no cross-function propagation.
    """
    summary = FunctionSummary(
        qualified_name=qualified_name,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
    )

    if not source_lines:
        return summary

    body = "\n".join(source_lines)
    null_literals = _NULL_LITERALS.get(language, set())

    # ── Null return detection ──
    _detect_null_returns(summary, source_lines, start_line, language, null_literals)

    # ── Return type analysis ──
    if return_type:
        _analyze_return_type(summary, return_type, language)

    # ── Exception detection ──
    _detect_exceptions(summary, source_lines, language)

    # ── Resource detection ──
    _detect_resources(summary, source_lines, start_line, language)

    # ── Taint detection ──
    _detect_taint(summary, source_lines, language)

    # ── Field access detection ──
    _detect_field_access(summary, source_lines, language)

    # ── Lock detection ──
    _detect_locks(summary, source_lines, language)

    # ── Context manager / defer detection ──
    _detect_context_managers(summary, body, language)

    # ── Purity heuristic ──
    summary.is_pure = (
        not summary.has_io
        and not summary.writes_fields
        and not summary.acquires
        and not summary.releases
        and not summary.acquires_lock
    )

    return summary


def _detect_null_returns(
    summary: FunctionSummary,
    lines: list[str],
    start_line: int,
    language: str,
    null_literals: set[str],
) -> None:
    """Detect return statements that return null/None/nil."""
    for i, line in enumerate(lines):
        stripped = line.strip()

        if language == "python":
            # return None, or bare return (implicit None)
            if stripped == "return" or stripped == "return None":
                summary.may_return_null = True
                summary.null_return_lines.append(start_line + i)
            elif stripped.startswith("return ") and "None" in stripped:
                # Could be return value_or_None — heuristic
                # Only flag direct None returns or conditional None
                if stripped == "return None" or stripped.endswith("or None"):
                    summary.may_return_null = True
                    summary.null_return_lines.append(start_line + i)

        elif language in ("java", "javascript", "typescript", "csharp"):
            if "return null" in stripped or "return undefined" in stripped:
                summary.may_return_null = True
                summary.null_return_lines.append(start_line + i)

        elif language == "go":
            # return nil, or return value, nil (error return)
            if "return nil" in stripped:
                summary.may_return_null = True
                summary.null_return_lines.append(start_line + i)


def _analyze_return_type(summary: FunctionSummary, return_type: str, language: str) -> None:
    """Analyze return type annotation for nullable/error indicators."""
    rt_lower = return_type.lower()

    # Optional types
    optional_indicators = {"optional", "none", "null", "nullable", "maybe", "?"}
    if any(ind in rt_lower for ind in optional_indicators):
        summary.return_value_is_optional = True
        summary.may_return_null = True

    # Error types (Go)
    if language == "go" and "error" in rt_lower:
        summary.return_value_is_error = True

    # Result types
    if "result" in rt_lower:
        summary.return_value_is_error = True


def _detect_exceptions(
    summary: FunctionSummary,
    lines: list[str],
    language: str,
) -> None:
    """Detect throw/raise statements and try-catch blocks."""
    throw_keyword = _THROW_KEYWORDS.get(language, "")
    in_try = False
    in_catch = False
    caught_types: set[str] = set()

    for line in lines:
        stripped = line.strip()

        # Try block detection
        if stripped.startswith("try") or stripped.startswith("try:"):
            in_try = True
        elif language == "python" and stripped.startswith(("except", "except ")):
            in_catch = True
            # Extract caught exception type
            if stripped.startswith("except "):
                exc_part = stripped[7:].split(":")[0].split(" as ")[0].strip().strip("()")
                if exc_part and exc_part != "Exception" and exc_part != "BaseException":
                    caught_types.add(exc_part)
                elif exc_part:
                    caught_types.add(exc_part)
        elif language in ("java", "javascript", "typescript", "csharp") and "catch" in stripped:
            in_catch = True
            # Extract caught type from catch(ExceptionType e)
            if "(" in stripped:
                paren_content = stripped.split("(", 1)[1].split(")", 1)[0].strip()
                tokens = paren_content.split()
                if tokens:
                    caught_types.add(tokens[0])
        elif stripped.startswith("finally") or stripped.startswith("finally:"):
            summary.has_finally = True

        # Throw/raise detection
        if throw_keyword and stripped.startswith(throw_keyword):
            if language == "python":
                # raise ExceptionType(...)
                exc_text = stripped[6:].strip()
                if exc_text:
                    exc_type = exc_text.split("(")[0].strip()
                    if not in_catch:  # Not re-raising inside handler
                        summary.may_throw.add(exc_type)
            elif language in ("java", "javascript", "typescript", "csharp"):
                # throw new ExceptionType(...)
                exc_text = stripped[6:].strip()
                if exc_text.startswith("new "):
                    exc_type = exc_text[4:].split("(")[0].strip()
                    if not in_catch:
                        summary.may_throw.add(exc_type)
                elif "(" in exc_text:
                    exc_type = exc_text.split("(")[0].strip()
                    if not in_catch:
                        summary.may_throw.add(exc_type)
            elif language == "go":
                # panic(...)
                if stripped.startswith("panic("):
                    summary.may_throw.add("panic")

    summary.catches = caught_types

    # Check if function always throws (heuristic: last statement is throw/raise without try)
    if lines:
        last_meaningful = ""
        for line in reversed(lines):
            if line.strip():
                last_meaningful = line.strip()
                break
        if throw_keyword and last_meaningful.startswith(throw_keyword):
            # Very rough heuristic — only if no return statements exist
            has_return = any("return " in l or l.strip() == "return" for l in lines)
            if not has_return:
                summary.always_throws = True


def _detect_resources(
    summary: FunctionSummary,
    lines: list[str],
    start_line: int,
    language: str,
) -> None:
    """Detect resource acquisition and release patterns."""
    acquire_patterns = _RESOURCE_ACQUIRE_PATTERNS.get(language, [])
    release_patterns = _RESOURCE_RELEASE_PATTERNS.get(language, [])

    for i, line in enumerate(lines):
        stripped = line.strip()
        for pattern, kind in acquire_patterns:
            if pattern in stripped:
                summary.acquires.append(ResourceAction(
                    kind=kind,
                    line=start_line + i,
                    method=pattern.strip("(."),
                ))
                break

        for pattern, kind in release_patterns:
            if pattern in stripped:
                summary.releases.append(ResourceAction(
                    kind=kind,
                    line=start_line + i,
                    method=pattern.strip("(."),
                ))
                break

    # If acquires resources but doesn't release them → requires cleanup
    if summary.acquires and not summary.releases and not summary.uses_context_manager:
        summary.requires_cleanup = True


def _detect_taint(
    summary: FunctionSummary,
    lines: list[str],
    language: str,
) -> None:
    """Detect taint sources, sinks, and sanitizers."""
    sources = _TAINT_SOURCES.get(language, set())
    sinks = _TAINT_SINKS.get(language, set())
    sanitizers = _SANITIZERS.get(language, set())

    body = "\n".join(lines)

    # Check if function is a source
    for source in sources:
        if source in body:
            summary.is_source = True
            break

    # Check if function is a sink
    for sink in sinks:
        if sink in body:
            summary.is_sink = True
            break

    # Check if function is a sanitizer
    for sanitizer in sanitizers:
        if sanitizer in body:
            summary.is_sanitizer = True
            break


def _detect_field_access(
    summary: FunctionSummary,
    lines: list[str],
    language: str,
) -> None:
    """Detect instance/class field reads and writes."""
    for line in lines:
        stripped = line.strip()

        if language == "python":
            # self.field = ... → write
            if "self." in stripped:
                if "self." in stripped.split("=")[0] and "==" not in stripped and "!=" not in stripped:
                    # Rough: if self.X appears before = on a line, it's a write
                    parts = stripped.split("=", 1)
                    if len(parts) == 2 and "self." in parts[0] and not parts[0].strip().startswith(("#", "if", "while", "return")):
                        field_match = parts[0].strip()
                        if field_match.startswith("self."):
                            field_name = field_match[5:].split("[")[0].split("(")[0].strip()
                            if field_name and field_name.isidentifier():
                                summary.writes_fields.add(field_name)
                    else:
                        # Read
                        import re
                        for m in re.finditer(r"self\.(\w+)", stripped):
                            summary.reads_fields.add(m.group(1))
                else:
                    import re
                    for m in re.finditer(r"self\.(\w+)", stripped):
                        summary.reads_fields.add(m.group(1))

        elif language == "java":
            # this.field = ... → write, or just field access
            if "this." in stripped:
                import re
                if "this." in stripped.split("=")[0] and "==" not in stripped:
                    for m in re.finditer(r"this\.(\w+)", stripped.split("=")[0]):
                        summary.writes_fields.add(m.group(1))
                for m in re.finditer(r"this\.(\w+)", stripped):
                    summary.reads_fields.add(m.group(1))


def _detect_locks(
    summary: FunctionSummary,
    lines: list[str],
    language: str,
) -> None:
    """Detect lock acquire/release patterns."""
    has_acquire = False
    has_release = False
    lock_name = ""

    for line in lines:
        stripped = line.strip()

        if language == "python":
            if ".acquire(" in stripped or "Lock()" in stripped:
                has_acquire = True
                lock_name = stripped.split(".acquire")[0].strip().split("=")[0].strip() if ".acquire(" in stripped else "lock"
            if ".release(" in stripped:
                has_release = True

        elif language == "java":
            if ".lock(" in stripped or ".tryLock(" in stripped:
                has_acquire = True
                lock_name = stripped.split(".lock")[0].strip().split(".tryLock")[0].strip()
            if ".unlock(" in stripped:
                has_release = True
            if "synchronized" in stripped:
                summary.holds_lock_throughout = True

        elif language == "go":
            if ".Lock(" in stripped or ".RLock(" in stripped:
                has_acquire = True
                lock_name = stripped.split(".Lock")[0].strip().split(".RLock")[0].strip()
            if ".Unlock(" in stripped or ".RUnlock(" in stripped:
                has_release = True

    if has_acquire and not has_release:
        summary.acquires_lock = lock_name or "unknown"
    if has_release and not has_acquire:
        summary.releases_lock = lock_name or "unknown"


def _detect_context_managers(summary: FunctionSummary, body: str, language: str) -> None:
    """Detect use of context managers / try-with-resources / defer."""
    if language == "python":
        if "with " in body and ("open(" in body or "connect(" in body or "Lock(" in body):
            summary.uses_context_manager = True
    elif language == "java":
        if "try (" in body or "try(" in body:  # try-with-resources
            summary.uses_context_manager = True
    elif language == "go":
        if "defer " in body:
            summary.uses_context_manager = True

    # I/O heuristic
    io_patterns = {"print(", "println(", "write(", "read(", "send(", "recv(", "fetch(", "http.", "net."}
    if any(p in body for p in io_patterns):
        summary.has_io = True
