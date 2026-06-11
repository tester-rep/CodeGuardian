"""Same-file field-write lookup for verifier Pass 2 context.

Why this exists
---------------
The two-pass verifier was producing false positives on findings like
"intervalMinMillisec is read but its initializer isn't visible in the
±10-line snippet". The AI assumed worst case (uninitialized) and verdict=true.

The call-graph machinery (``call_graph.py``) finds *callers/callees of the
enclosing function* — not *where a referenced field is assigned*. Field
initializers in Java/Python typically live elsewhere in the same file
(class header, constructor, top of module), outside both the ±10-line
snippet and the enclosing-function block.

This module fills that gap with the smallest possible mechanism:

1. From the hit line ± 5 lines, extract identifiers used as ``.name`` or
   bare ``name`` references (filtered against language keywords).
2. For each candidate, grep the *same file* for ``\\bname\\s*=(?!=)``
   (assignment / declaration-with-init), capturing each match plus ±2
   surrounding lines.
3. Hard-cap output by per-field hits, total fields, and total bytes.

Cross-file lookup is deliberately out of scope — that needs a real symbol
index. Field initializers in Java/Python are overwhelmingly same-class /
same-module, so this gets us most of the value at near-zero cost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from codeguardian.languages import language_from_path

# Bounds — keep prompt size predictable.
HIT_RADIUS = 5            # lines around the hit to scan for field names
WRITE_RADIUS = 2          # lines around each write match to include
MAX_FIELDS_PER_FINDING = 5
MAX_WRITES_PER_FIELD = 5
MAX_TOTAL_BYTES = 2_000   # ~500 tokens worst case

# Reserved names we never want to chase. Kept here (not imported from
# call_graph) to avoid a cyclic import and because the filter intent here
# is slightly different — we exclude common method/builtin names too,
# since methods aren't "fields" anyway.
_KEYWORDS: dict[str, set[str]] = {
    "python": {
        "if", "for", "while", "with", "return", "print", "len", "str", "int",
        "list", "dict", "set", "tuple", "range", "isinstance", "type", "super",
        "enumerate", "zip", "map", "filter", "sorted", "any", "all", "self",
        "cls", "True", "False", "None", "and", "or", "not", "in", "is",
        "import", "from", "class", "def", "lambda", "yield", "raise", "try",
        "except", "finally", "pass", "continue", "break", "global", "nonlocal",
    },
    "java": {
        "if", "for", "while", "switch", "return", "new", "this", "super",
        "synchronized", "throw", "throws", "instanceof", "System", "String",
        "Integer", "Long", "Double", "Float", "Boolean", "true", "false",
        "null", "void", "int", "long", "double", "float", "boolean", "char",
        "byte", "short", "public", "private", "protected", "static", "final",
        "class", "interface", "enum", "extends", "implements", "package",
        "import", "try", "catch", "finally", "do", "else", "abstract",
    },
    "javascript": {
        "if", "for", "while", "return", "new", "this", "console", "Object",
        "Array", "String", "Number", "Boolean", "Math", "JSON", "Promise",
        "setTimeout", "setInterval", "true", "false", "null", "undefined",
        "var", "let", "const", "function", "class", "extends", "import",
        "export", "from", "async", "await", "try", "catch", "finally",
    },
    "typescript": {
        "if", "for", "while", "return", "new", "this", "console", "Object",
        "Array", "String", "Number", "Boolean", "Math", "JSON", "Promise",
        "setTimeout", "setInterval", "true", "false", "null", "undefined",
        "var", "let", "const", "function", "class", "extends", "import",
        "export", "from", "async", "await", "try", "catch", "finally",
        "interface", "type", "enum", "readonly", "public", "private", "protected",
    },
    "go": {
        "if", "for", "switch", "return", "make", "new", "len", "cap", "append",
        "panic", "recover", "go", "defer", "fmt", "true", "false", "nil",
        "var", "const", "func", "type", "struct", "interface", "package",
        "import", "range", "select", "case", "default", "chan", "map",
    },
    "cpp": {
        "if", "for", "while", "switch", "return", "new", "delete", "sizeof",
        "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast", "std",
        "printf", "scanf", "cout", "cin", "true", "false", "nullptr", "NULL",
        "void", "int", "long", "double", "float", "char", "bool", "auto",
        "const", "static", "class", "struct", "namespace", "template",
        "public", "private", "protected", "using", "typedef", "virtual",
    },
    "csharp": {
        "if", "for", "while", "switch", "return", "new", "this", "base", "throw",
        "is", "as", "Console", "String", "Int32", "Boolean", "true", "false",
        "null", "void", "int", "long", "double", "float", "bool", "string",
        "var", "const", "static", "readonly", "public", "private", "protected",
        "internal", "class", "struct", "interface", "namespace", "using",
    },
    "_default": {"if", "for", "while", "return", "new", "this", "true", "false", "null"},
}

# Identifier reference: bare name OR `.name` member access.
# Captures the field name (group 1).
_FIELD_REF_RE = re.compile(r"(?:\.|\b)([A-Za-z_][A-Za-z_0-9]{2,})")


@dataclass(slots=True)
class FieldWriteSnippet:
    """One assignment / declaration-with-init match for a referenced field."""

    field_name: str
    line: int          # 1-based line number where the write was matched
    code_block: str    # ±WRITE_RADIUS lines, formatted with line numbers


def find_field_writes(
    *,
    file_path: Path,
    line_start: int,
    code_lines: list[str] | None = None,
) -> list[FieldWriteSnippet]:
    """Return same-file write-site snippets for fields referenced near the hit.

    Parameters
    ----------
    file_path
        Absolute path to the source file containing the finding.
    line_start
        1-based hit line. Field-name extraction scans ±HIT_RADIUS around it.
    code_lines
        Optional pre-read file content (saves a re-read when the caller
        already has it, e.g. ``build_pass2_context``).

    Returns
    -------
    list[FieldWriteSnippet]
        Empty when the file is unreadable, the language is unsupported,
        or no candidate fields have visible writes in this file.
    """
    if line_start <= 0:
        return []

    lines = code_lines if code_lines is not None else _read_lines(file_path)
    if not lines:
        return []

    language = language_from_path(file_path)
    if language is None:
        return []

    keywords = _KEYWORDS.get(language, _KEYWORDS["_default"])

    # 1. Extract candidate field names from the hit window.
    n = len(lines)
    win_start = max(0, line_start - 1 - HIT_RADIUS)
    win_end = min(n, line_start + HIT_RADIUS)
    hit_window = "\n".join(lines[win_start:win_end])
    candidates: list[str] = []
    seen_names: set[str] = set()
    for match in _FIELD_REF_RE.finditer(hit_window):
        name = match.group(1)
        if name in keywords or name in seen_names:
            continue
        seen_names.add(name)
        candidates.append(name)
        if len(candidates) >= MAX_FIELDS_PER_FINDING * 4:
            # Over-collect; we'll trim after the write-grep stage since some
            # candidates may have zero writes and waste a slot.
            break

    if not candidates:
        return []

    # 2. For each candidate, grep `\bname\s*=(?!=)` in the whole file.
    out: list[FieldWriteSnippet] = []
    total_bytes = 0
    fields_emitted = 0
    for name in candidates:
        if fields_emitted >= MAX_FIELDS_PER_FINDING:
            break
        write_re = re.compile(rf"\b{re.escape(name)}\s*=(?!=)")
        per_field_hits = 0
        emitted_any_for_field = False
        for idx, raw_line in enumerate(lines):
            if per_field_hits >= MAX_WRITES_PER_FIELD:
                break
            if not write_re.search(raw_line):
                continue
            # Skip if this write happens *inside* the hit window itself —
            # the AI already sees those lines via the enclosing-function
            # block, no need to duplicate.
            line_no = idx + 1
            if win_start + 1 <= line_no <= win_end:
                continue
            block_start = max(1, line_no - WRITE_RADIUS)
            block_end = min(n, line_no + WRITE_RADIUS)
            block = _format_block(block_start, lines[block_start - 1 : block_end])
            new_size = len(block) + 64  # header overhead estimate
            if total_bytes + new_size > MAX_TOTAL_BYTES:
                # Budget exhausted; return what we have.
                return out
            out.append(FieldWriteSnippet(field_name=name, line=line_no, code_block=block))
            total_bytes += new_size
            per_field_hits += 1
            emitted_any_for_field = True
        if emitted_any_for_field:
            fields_emitted += 1

    return out


# ──────────────────────────────────────────────────────────────────
# Helpers (kept private to this module to avoid coupling with prompts.py)
# ──────────────────────────────────────────────────────────────────


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _format_block(start_line: int, snippet_lines: list[str]) -> str:
    if not snippet_lines:
        return ""
    width = len(str(start_line + len(snippet_lines) - 1))
    return "\n".join(
        f"{str(start_line + i).rjust(width)}: {line}"
        for i, line in enumerate(snippet_lines)
    )
