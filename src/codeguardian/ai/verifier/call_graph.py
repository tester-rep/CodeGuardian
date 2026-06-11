"""CallGraphFinder — locate caller/callee snippets for a finding.

Why this exists
---------------
The verifier needs richer evidence than "the hit line ± 5". For high/critical
findings we want the function that *contains* the hit, plus 1-2 hops of
caller/callee code (possibly cross-file), so the AI can judge whether the
suspected pattern is actually exercised on a real path.

Design constraints
------------------
- **Zero new dependencies.** We reuse `codeguardian.parsers.get_parser`,
  which already covers Python / Java / JS/TS / Go / C++ / C# / Lua / Rust.
- **Best-effort, not exact.** Caller detection is a name-based regex search
  scoped to the project tree; this is not LSP. False positives in the call
  graph are tolerable — the AI sees the snippet and decides what's relevant.
- **Bounded.** Hard caps on files scanned, snippets returned, and total bytes
  emitted, so we never blow the AI prompt budget on a giant repo.

Output
------
``CallGraphSnippet`` is a small immutable record carrying just enough for the
prompt builder to format a code block: file/line range + raw code text.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from codeguardian.languages import language_from_path
from codeguardian.parsers.base import ParsedFunction, ParsedStructure
from codeguardian.parsers.factory import get_parser

logger = logging.getLogger(__name__)

# Bounds — safety net to keep prompt size predictable.
MAX_FILES_SCANNED = 400
MAX_SNIPPETS_PER_KIND = 6  # caller_snippets ≤ 6, callee_snippets ≤ 6
MAX_LINES_PER_SNIPPET = 80
MAX_TOTAL_BYTES = 12_000  # ~3K tokens worst case across all snippets


@dataclass(slots=True)
class CallGraphSnippet:
    """One piece of caller/callee context to feed into the prompt."""

    file_path: str  # repo-relative, posix-style
    function_name: str
    line_start: int
    line_end: int
    code: str  # the function body verbatim (already capped to MAX_LINES_PER_SNIPPET)
    relation: str  # "caller" | "callee"


@dataclass(slots=True)
class CallGraphResult:
    """Aggregate of caller/callee evidence for a single finding."""

    enclosing_function: ParsedFunction | None = None
    enclosing_file: str | None = None
    callers: list[CallGraphSnippet] = field(default_factory=list)
    callees: list[CallGraphSnippet] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(len(s.code) for s in self.callers) + sum(len(s.code) for s in self.callees)


# ────────────────────────────────────────────────────────────────────
# Public entry
# ────────────────────────────────────────────────────────────────────


def find_call_graph(
    *,
    project_root: Path,
    file_path: str,
    line_start: int,
    caller_depth: int,
    callee_depth: int,
    pci: object | None = None,
) -> CallGraphResult:
    """Return up to ``caller_depth`` / ``callee_depth`` hops around the hit.

    Depth ``0`` means "skip that side". Depth ``≥ 2`` walks one extra hop
    (caller's caller / callee's callee), bounded by the global caps above.

    If ``pci`` (PCIResult) is provided, uses the pre-built call graph for
    high-accuracy cross-file resolution. Falls back to regex scan otherwise.
    """
    result = CallGraphResult()
    abs_path = (project_root / file_path).resolve()
    if not abs_path.is_file():
        result.notes.append(f"file not readable: {file_path}")
        return result

    language = language_from_path(abs_path)
    if language is None:
        result.notes.append(f"unsupported language for {file_path}")
        return result

    # 1. Locate the function that encloses the hit line.
    enclosing = _enclosing_function(abs_path, project_root, language, line_start)
    if enclosing is None:
        result.notes.append("could not locate enclosing function via parser")
        return result
    result.enclosing_function = enclosing
    result.enclosing_file = enclosing.file_path

    # ─── PCI fast path: use pre-built call graph ───
    if pci is not None:
        _collect_via_pci(
            pci=pci,
            enclosing=enclosing,
            project_root=project_root,
            caller_depth=caller_depth,
            callee_depth=callee_depth,
            result=result,
        )
        return result

    # ─── Fallback: regex-based scan ───
    # 2. Caller chain (cross-file): who calls `enclosing.name`?
    if caller_depth > 0:
        seen_caller_keys: set[str] = set()
        _collect_callers(
            project_root=project_root,
            target_name=enclosing.name,
            target_qualname_file=enclosing.file_path,
            language=language,
            depth_remaining=caller_depth,
            out=result.callers,
            seen=seen_caller_keys,
        )

    # 3. Callee chain (same-file first; cross-file via project index would need
    #    a heavier symbol map — out of scope for this MVP). What does the
    #    enclosing function call?
    if callee_depth > 0:
        seen_callee_keys: set[str] = set()
        _collect_callees(
            project_root=project_root,
            from_function=enclosing,
            language=language,
            depth_remaining=callee_depth,
            out=result.callees,
            seen=seen_callee_keys,
        )

    return result


# ────────────────────────────────────────────────────────────────────
# PCI-based fast path
# ────────────────────────────────────────────────────────────────────


def _collect_via_pci(
    *,
    pci: object,
    enclosing: ParsedFunction,
    project_root: Path,
    caller_depth: int,
    callee_depth: int,
    result: CallGraphResult,
) -> None:
    """Use PCI call graph for high-accuracy caller/callee resolution.

    Much faster and more accurate than regex: O(1) graph lookup vs O(n) file scan.
    """
    from codeguardian.core.call_graph.pci_builder import PCIResult

    if not isinstance(pci, PCIResult) or pci.is_empty:
        result.notes.append("PCI empty or invalid, skipping PCI path")
        return

    symbol_table = pci.symbol_table
    call_graph = pci.call_graph
    file_lines = pci.file_lines

    # Resolve enclosing function to a PCI symbol (by file + name + line overlap)
    enclosing_sym = _resolve_to_pci_symbol(enclosing, symbol_table)
    if enclosing_sym is None:
        result.notes.append(f"could not resolve {enclosing.name} in PCI symbol table")
        return

    total_bytes = 0

    # Collect callers via call graph
    if caller_depth > 0:
        caller_edges = call_graph.callers_of(
            enclosing_sym.qualified_name, depth=caller_depth, min_confidence=0.5,
        )
        for edge in caller_edges[:MAX_SNIPPETS_PER_KIND]:
            if total_bytes >= MAX_TOTAL_BYTES:
                break
            caller_sym = symbol_table.lookup(edge.caller)
            if caller_sym is None:
                continue
            body = _pci_function_body(caller_sym, file_lines, project_root)
            if not body:
                continue
            snippet = CallGraphSnippet(
                file_path=caller_sym.file_path,
                function_name=caller_sym.name,
                line_start=caller_sym.start_line,
                line_end=caller_sym.end_line,
                code=body,
                relation="caller",
            )
            if total_bytes + len(body) > MAX_TOTAL_BYTES:
                break
            total_bytes += len(body)
            result.callers.append(snippet)

    # Collect callees via call graph
    if callee_depth > 0:
        callee_edges = call_graph.callees_of(
            enclosing_sym.qualified_name, depth=callee_depth, min_confidence=0.5,
        )
        for edge in callee_edges[:MAX_SNIPPETS_PER_KIND]:
            if total_bytes >= MAX_TOTAL_BYTES:
                break
            callee_sym = symbol_table.lookup(edge.callee)
            if callee_sym is None:
                continue
            body = _pci_function_body(callee_sym, file_lines, project_root)
            if not body:
                continue
            snippet = CallGraphSnippet(
                file_path=callee_sym.file_path,
                function_name=callee_sym.name,
                line_start=callee_sym.start_line,
                line_end=callee_sym.end_line,
                code=body,
                relation="callee",
            )
            if total_bytes + len(body) > MAX_TOTAL_BYTES:
                break
            total_bytes += len(body)
            result.callees.append(snippet)

    result.notes.append(
        f"PCI: {len(result.callers)} callers, {len(result.callees)} callees"
    )


def _resolve_to_pci_symbol(enclosing: ParsedFunction, symbol_table: object) -> object | None:
    """Resolve a ParsedFunction to a PCI Symbol by file path + name + line overlap."""
    from codeguardian.core.call_graph.symbol_table import SymbolKind

    # First try: exact file + name match
    candidates = symbol_table.lookup_in_file(enclosing.file_path)
    for sym in candidates:
        if sym.kind not in (SymbolKind.FUNCTION, SymbolKind.METHOD, SymbolKind.CONSTRUCTOR):
            continue
        if sym.name != enclosing.name:
            continue
        # Line overlap check for overloads
        if (enclosing.start_line is not None and enclosing.end_line is not None
                and sym.start_line <= enclosing.end_line and sym.end_line >= enclosing.start_line):
            return sym
        # If no line info, name match in same file is good enough
        if enclosing.start_line is None:
            return sym

    # Fallback: name-only match (less precise)
    by_name = symbol_table.lookup_by_name(enclosing.name, context_file=enclosing.file_path)
    for sym in by_name:
        if sym.file_path == enclosing.file_path:
            return sym

    return None


def _pci_function_body(sym: object, file_lines: dict, project_root: Path) -> str:
    """Read function body from PCI file_lines cache, formatted with line numbers."""
    lines = file_lines.get(sym.file_path)
    if not lines:
        # Fallback: read from disk
        abs_path = project_root / sym.file_path
        text = _read_text(abs_path)
        if not text:
            return ""
        lines = text.splitlines()

    n = len(lines)
    start = max(1, sym.start_line)
    end = min(n, sym.end_line)
    if end - start + 1 > MAX_LINES_PER_SNIPPET:
        end = start + MAX_LINES_PER_SNIPPET - 1
    if start > n:
        return ""

    width = len(str(end))
    return "\n".join(
        f"{str(start + i).rjust(width)}: {lines[start - 1 + i]}"
        for i in range(end - start + 1)
    )


# ────────────────────────────────────────────────────────────────────
# Internals (regex fallback)
# ────────────────────────────────────────────────────────────────────


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _parse(path: Path, project_root: Path, language: str) -> ParsedStructure | None:
    parser = get_parser(language)
    if parser is None:
        return None
    try:
        return parser.parse_file(path, project_root)
    except Exception:  # noqa: BLE001 — parser bugs must not break verification
        logger.debug("parser failed on %s", path, exc_info=True)
        return None


def _enclosing_function(
    abs_path: Path,
    project_root: Path,
    language: str,
    line: int,
) -> ParsedFunction | None:
    structure = _parse(abs_path, project_root, language)
    if structure is None:
        return None
    # Smallest function containing `line` wins (handles nested defs).
    best: ParsedFunction | None = None
    best_span = 10**9
    for func in structure.functions:
        if func.start_line is None or func.end_line is None:
            continue
        if func.start_line <= line <= func.end_line:
            span = func.end_line - func.start_line
            if span < best_span:
                best, best_span = func, span
    return best


def _function_body(
    abs_path: Path,
    func: ParsedFunction,
) -> str:
    """Read the function body, clipped to MAX_LINES_PER_SNIPPET and decorated
    with line numbers so the AI can cite positions back to us.
    """
    if func.start_line is None or func.end_line is None:
        return ""
    text = _read_text(abs_path)
    if not text:
        return ""
    lines = text.splitlines()
    n = len(lines)
    start = max(1, func.start_line)
    end = min(n, func.end_line)
    if end - start + 1 > MAX_LINES_PER_SNIPPET:
        end = start + MAX_LINES_PER_SNIPPET - 1
    width = len(str(end))
    return "\n".join(
        f"{str(start + i).rjust(width)}: {lines[start - 1 + i]}"
        for i in range(end - start + 1)
    )


def _candidate_files(project_root: Path, language: str) -> list[Path]:
    """List all files in project_root matching the language, capped."""
    from codeguardian.languages import EXTENSION_LANGUAGE_MAP

    target_exts = {ext for ext, lang in EXTENSION_LANGUAGE_MAP.items() if lang == language}
    if not target_exts:
        return []

    out: list[Path] = []
    skip_dirs = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", ".idea", "__pycache__"}
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in target_exts:
            continue
        # Skip if any path component is in skip_dirs.
        if any(part in skip_dirs for part in path.parts):
            continue
        out.append(path)
        if len(out) >= MAX_FILES_SCANNED:
            break
    return out


def _collect_callers(
    *,
    project_root: Path,
    target_name: str,
    target_qualname_file: str,
    language: str,
    depth_remaining: int,
    out: list[CallGraphSnippet],
    seen: set[str],
) -> None:
    """Walk one hop: find functions that call `target_name`.

    Cross-file via brute-force scan of all same-language files. Acceptable
    cost: caller hops happen ≤ 2 times per finding, project capped at
    MAX_FILES_SCANNED.
    """
    if depth_remaining <= 0 or len(out) >= MAX_SNIPPETS_PER_KIND:
        return

    call_pattern = re.compile(rf"\b{re.escape(target_name)}\s*\(")

    for path in _candidate_files(project_root, language):
        if len(out) >= MAX_SNIPPETS_PER_KIND:
            return
        text = _read_text(path)
        if not text or not call_pattern.search(text):
            continue
        structure = _parse(path, project_root, language)
        if structure is None:
            continue

        rel_path = _relpath(path, project_root)
        # Find the line numbers where the call occurs, then map back to the
        # enclosing function in *this* file.
        call_lines = [i + 1 for i, line in enumerate(text.splitlines()) if call_pattern.search(line)]
        for call_line in call_lines:
            if len(out) >= MAX_SNIPPETS_PER_KIND:
                break
            enclosing = _enclosing_at(structure.functions, call_line)
            if enclosing is None:
                continue
            # Skip self-recursion (the target function calling itself).
            if enclosing.file_path == target_qualname_file and enclosing.name == target_name:
                continue
            key = f"{enclosing.file_path}:{enclosing.name}:{enclosing.start_line}"
            if key in seen:
                continue
            seen.add(key)

            body = _function_body(path, enclosing)
            if not body:
                continue
            snippet = CallGraphSnippet(
                file_path=rel_path,
                function_name=enclosing.name,
                line_start=enclosing.start_line or 0,
                line_end=enclosing.end_line or 0,
                code=body,
                relation="caller",
            )
            if _exceeds_total(out, snippet):
                return
            out.append(snippet)

            # Recurse one more hop on the caller's caller.
            if depth_remaining - 1 > 0:
                _collect_callers(
                    project_root=project_root,
                    target_name=enclosing.name,
                    target_qualname_file=enclosing.file_path,
                    language=language,
                    depth_remaining=depth_remaining - 1,
                    out=out,
                    seen=seen,
                )


def _collect_callees(
    *,
    project_root: Path,
    from_function: ParsedFunction,
    language: str,
    depth_remaining: int,
    out: list[CallGraphSnippet],
    seen: set[str],
) -> None:
    """Find functions that `from_function` calls (same-file first).

    Same-file resolution is cheap and high-precision. Cross-file callee
    resolution would require a project-wide symbol map; we leave that out
    deliberately — the cost/benefit isn't worth it for a verifier that
    already has the enclosing function.
    """
    if depth_remaining <= 0 or len(out) >= MAX_SNIPPETS_PER_KIND:
        return
    if from_function.start_line is None or from_function.end_line is None:
        return

    abs_path = (project_root / from_function.file_path).resolve()
    text = _read_text(abs_path)
    if not text:
        return
    lines = text.splitlines()
    body_text = "\n".join(lines[from_function.start_line - 1 : from_function.end_line])

    # Identifiers followed by '('. Conservative: drop language keywords and
    # extremely short names to keep noise down.
    candidates = {
        m.group(1)
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z_0-9]{2,})\s*\(", body_text)
    }
    candidates -= _LANGUAGE_KEYWORDS.get(language, _LANGUAGE_KEYWORDS["_default"])
    candidates.discard(from_function.name)  # skip self

    structure = _parse(abs_path, project_root, language)
    if structure is None:
        return
    by_name: dict[str, list[ParsedFunction]] = {}
    for func in structure.functions:
        by_name.setdefault(func.name, []).append(func)

    for name in candidates:
        if len(out) >= MAX_SNIPPETS_PER_KIND:
            return
        for callee in by_name.get(name, []):
            if callee.start_line is None:
                continue
            key = f"{callee.file_path}:{callee.name}:{callee.start_line}"
            if key in seen:
                continue
            seen.add(key)
            body = _function_body(abs_path, callee)
            if not body:
                continue
            snippet = CallGraphSnippet(
                file_path=callee.file_path,
                function_name=callee.name,
                line_start=callee.start_line or 0,
                line_end=callee.end_line or 0,
                code=body,
                relation="callee",
            )
            if _exceeds_total(out, snippet):
                return
            out.append(snippet)

            if depth_remaining - 1 > 0:
                _collect_callees(
                    project_root=project_root,
                    from_function=callee,
                    language=language,
                    depth_remaining=depth_remaining - 1,
                    out=out,
                    seen=seen,
                )


def _enclosing_at(functions: list[ParsedFunction], line: int) -> ParsedFunction | None:
    best: ParsedFunction | None = None
    best_span = 10**9
    for func in functions:
        if func.start_line is None or func.end_line is None:
            continue
        if func.start_line <= line <= func.end_line:
            span = func.end_line - func.start_line
            if span < best_span:
                best, best_span = func, span
    return best


def _exceeds_total(out: list[CallGraphSnippet], new: CallGraphSnippet) -> bool:
    """True when adding `new` would push us past MAX_TOTAL_BYTES."""
    current = sum(len(s.code) for s in out)
    return current + len(new.code) > MAX_TOTAL_BYTES


def _relpath(path: Path, project_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(project_root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


# Built-in language keywords we don't want to accidentally treat as callees.
# Not exhaustive — we only need to suppress the loudest false positives.
_LANGUAGE_KEYWORDS: dict[str, set[str]] = {
    "python": {"if", "for", "while", "with", "return", "print", "len", "str", "int",
               "list", "dict", "set", "tuple", "range", "isinstance", "type",
               "super", "enumerate", "zip", "map", "filter", "sorted", "any", "all"},
    "java": {"if", "for", "while", "switch", "return", "new", "this", "super",
             "synchronized", "throw", "throws", "instanceof", "System",
             "String", "Integer", "Long", "Double", "Float", "Boolean"},
    "javascript": {"if", "for", "while", "return", "new", "this", "console",
                   "Object", "Array", "String", "Number", "Boolean", "Math",
                   "JSON", "Promise", "setTimeout", "setInterval"},
    "typescript": {"if", "for", "while", "return", "new", "this", "console",
                   "Object", "Array", "String", "Number", "Boolean", "Math",
                   "JSON", "Promise", "setTimeout", "setInterval"},
    "go": {"if", "for", "switch", "return", "make", "new", "len", "cap",
           "append", "panic", "recover", "go", "defer", "fmt"},
    "cpp": {"if", "for", "while", "switch", "return", "new", "delete",
            "sizeof", "static_cast", "dynamic_cast", "reinterpret_cast",
            "const_cast", "std", "printf", "scanf", "cout", "cin"},
    "csharp": {"if", "for", "while", "switch", "return", "new", "this", "base",
               "throw", "is", "as", "Console", "String", "Int32", "Boolean"},
    "_default": {"if", "for", "while", "return", "new", "this"},
}
