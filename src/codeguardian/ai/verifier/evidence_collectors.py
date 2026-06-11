"""Rule-targeted evidence collectors for verifier Pass 2.

Why this exists
---------------
The base verifier Pass 2 already gives the AI: enclosing function body,
file imports, caller/callee snippets, plus same-file field-write reverse
lookup (see ``field_writes.py``). For most rules that's enough.

But three rule families produce **stubborn FPs** that the base context
can't kill, because the dispositive evidence lives in places those
collectors don't look:

A. **Static mutable shared state** (``STATIC-MUTABLE-SHARED-STATE``,
   ``UNUSED-VARIABLE``). The regex matches `static Map<...>` declarations
   but cannot see *how* the field is used: ``ConcurrentHashMap`` wrapping,
   ``Collections.unmodifiableMap``, ``synchronized(field) { ... }`` blocks,
   ``field.put(...)`` only inside a ``static {}`` initializer block, etc.
   The base ``field_writes`` collector finds ``name = ...`` writes but
   misses ``name.method(...)`` *uses* — which is where thread-safety
   evidence actually lives.

B. **Exception swallowing** (``LOG-ONLY-EXCEPT``,
   ``SWALLOWED-EXCEPTION-FLOW``, ``BROAD-EXCEPT``,
   ``EXCEPTION-SWALLOWED-NO-LOG``). The hit line is the ``catch``/``except``
   header, but the question "is this swallow OK?" depends on the **whole
   catch body** plus **what the caller does on failure** (retry? fallback?
   surface error?). Pass 2's enclosing-function block usually covers the
   catch body, but caller behavior is often missed.

C. **Resource lifecycle** (``RESOURCE-LEAK``,
   ``RESOURCE-CLOSE-NOT-GUARANTEED``). The hit line is the resource
   *acquisition*, but the question "is it closed safely?" depends on the
   surrounding ``try-with-resources`` / ``finally`` / ``defer`` / ``with``
   structure that may live a few lines above or below.

Each collector is a small, self-contained function that takes
``(file_path, line_start, code_lines, finding)`` and returns a
``EvidenceBlock`` (or None when nothing useful was found). They are
stateless, do no I/O beyond the already-loaded ``code_lines``, and obey
strict per-collector byte caps so they never blow the prompt budget.

The dispatch table at the bottom maps ``rule_id`` → collector. Rules not
in the table get the existing base context, no behavioral change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from codeguardian.languages import language_from_path

# ────────────────────────────────────────────────────────────────────
# Common types
# ────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class EvidenceBlock:
    """One collected evidence section, ready to be inlined into the prompt.

    ``header`` is a short markdown heading (no leading ``##`` — the prompt
    builder adds those). ``body`` is pre-formatted text including any code
    fences.
    """

    header: str
    body: str

    def __bool__(self) -> bool:  # pragma: no cover — trivial
        return bool(self.body.strip())


# ────────────────────────────────────────────────────────────────────
# Bounds — keep prompt size predictable per evidence type
# ────────────────────────────────────────────────────────────────────

# A — static mutable shared state
A_USE_RADIUS = 2          # ±lines around each `field.method(...)` call
A_MAX_USES_PER_FIELD = 6
A_MAX_TOTAL_BYTES = 2_500
# Synchronization / immutability tokens we explicitly flag for the AI.
# These are the tokens that, when present near a "static mutable" hit,
# usually mean the finding is a false positive. We don't decide that
# here — we just surface the hits so the model can decide.
A_SAFETY_TOKENS = (
    "ConcurrentHashMap",
    "ConcurrentMap",
    "ConcurrentSkipListMap",
    "ConcurrentSkipListSet",
    "ConcurrentLinkedQueue",
    "ConcurrentLinkedDeque",
    "CopyOnWriteArrayList",
    "CopyOnWriteArraySet",
    "AtomicInteger",
    "AtomicLong",
    "AtomicReference",
    "AtomicBoolean",
    "synchronized",
    "Collections.unmodifiableMap",
    "Collections.unmodifiableList",
    "Collections.unmodifiableSet",
    "Collections.synchronizedMap",
    "Collections.synchronizedList",
    "Collections.synchronizedSet",
    "ImmutableMap",
    "ImmutableList",
    "ImmutableSet",
    "ThreadLocal",
    "volatile",
)

# B — exception handling
B_CATCH_BODY_MAX_LINES = 30
B_CALLER_TAIL_MAX_LINES = 25  # tail of caller body where retry/fallback usually lives
B_MAX_TOTAL_BYTES = 2_500

# C — resource lifecycle
C_WINDOW_BEFORE = 5    # lines before the resource acquisition
C_WINDOW_AFTER = 25    # lines after — try-with-resources / finally / close path
C_MAX_TOTAL_BYTES = 2_000

# Rule-id sets that route to each collector.
# Keep these small and explicit — adding a rule here forces Pass 2 escalation
# (see verifier.py) and increases token spend per finding, so we only opt in
# rules that are demonstrably FP-prone and benefit from the specific evidence.
A_RULE_IDS: frozenset[str] = frozenset({
    "STATIC-MUTABLE-SHARED-STATE",
    "UNUSED-VARIABLE",  # often a "field looks unused but is reflectively/serialized" FP
})
B_RULE_IDS: frozenset[str] = frozenset({
    "LOG-ONLY-EXCEPT",
    "SWALLOWED-EXCEPTION-FLOW",
    "BROAD-EXCEPT",
    "BARE-EXCEPT",
    "EXCEPTION-SWALLOWED-NO-LOG",
})
C_RULE_IDS: frozenset[str] = frozenset({
    "RESOURCE-LEAK",
    "RESOURCE-CLOSE-NOT-GUARANTEED",
})

# Union — used by the verifier to decide "force Pass 2" for these rules.
ENHANCED_RULE_IDS: frozenset[str] = A_RULE_IDS | B_RULE_IDS | C_RULE_IDS


# ────────────────────────────────────────────────────────────────────
# Helpers (private)
# ────────────────────────────────────────────────────────────────────


def _format_block(start_line: int, lines: list[str]) -> str:
    """Render a list of source lines with right-aligned line numbers."""
    if not lines:
        return ""
    width = len(str(start_line + len(lines) - 1))
    return "\n".join(
        f"{str(start_line + i).rjust(width)}: {line}"
        for i, line in enumerate(lines)
    )


def _slice(lines: list[str], start: int, end: int) -> tuple[int, list[str]]:
    """1-based [start, end] clamped to [1, len(lines)]; return (start, slice)."""
    if not lines:
        return 1, []
    n = len(lines)
    s = max(1, start)
    e = min(n, end)
    if s > e:
        return s, []
    return s, lines[s - 1 : e]


def _extract_field_name_for_a(lines: list[str], hit_line: int) -> str | None:
    """A-class: pull the field identifier from a `static <type> NAME = ...` hit.

    This regex is intentionally loose — we only need the first plausible
    UpperCamel/UPPER_SNAKE/lowerCamel identifier following a type token
    on the hit line. Returns None if nothing recognizable is on the line.
    """
    if hit_line <= 0 or hit_line > len(lines):
        return None
    line = lines[hit_line - 1]
    # Try common Java/Kotlin static field shapes:
    #   static <Type> NAME = ...
    #   private static [final] <Type> NAME = ...
    #   public static [final] <Type<...>> NAME = ...
    # Note: identifiers may be single-character (e.g. `M`, `K`), so we use
    # `[A-Za-z_]\w*` (1+) rather than requiring a 2+ length pattern.
    m = re.search(
        r"\bstatic\b[^;]*?\b([A-Za-z_]\w*)\s*[=;]",
        line,
    )
    if m:
        # Filter out language tokens that can land here when the line has
        # only modifiers but no field (e.g. `static {`).
        name = m.group(1)
        if name not in {"final", "volatile", "transient", "synchronized", "abstract"}:
            return name
    # Fall back: any `NAME = ...` token.
    m2 = re.search(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*=", line)
    return m2.group(1) if m2 else None


# ────────────────────────────────────────────────────────────────────
# A — Static mutable shared state: field-use sites + safety-token scan
# ────────────────────────────────────────────────────────────────────


def collect_a_static_mutable_evidence(
    *,
    file_path: Path,
    line_start: int,
    code_lines: list[str],
) -> EvidenceBlock | None:
    """For STATIC-MUTABLE-SHARED-STATE-style hits, surface:

    1. **Use sites** of the suspect field: every ``field.method(...)`` call
       in the same file (put/get/synchronized-block/etc.), with ±2 lines
       of context. This is what ``field_writes.py`` deliberately doesn't
       cover (it only catches ``name = ...`` writes).

    2. **Safety-token presence**: a 1-line summary of which thread-safety
       / immutability tokens appear anywhere in the file
       (``ConcurrentHashMap``, ``synchronized``, ``unmodifiableMap``, ...).
       Lets the AI quickly see "this file has zero sync primitives" vs
       "ConcurrentHashMap is used 4 times".

    Returns None when the field name can't be extracted or there are no
    use sites worth showing.
    """
    if not code_lines or line_start <= 0:
        return None
    field_name = _extract_field_name_for_a(code_lines, line_start)
    if not field_name:
        return None

    # 1. Find use-sites: `field.method(`, `synchronized(field)`, `(field)`.
    # Pattern matches both `FIELD.put(...)` and `synchronized (FIELD)`.
    name_re = re.escape(field_name)
    use_re = re.compile(
        rf"(?:\b{name_re}\.[A-Za-z_]\w*\s*\()"     # FIELD.method(
        rf"|(?:\bsynchronized\s*\(\s*{name_re}\s*\))"  # synchronized(FIELD)
    )

    use_blocks: list[str] = []
    total_bytes = 0
    for idx, raw in enumerate(code_lines):
        if len(use_blocks) >= A_MAX_USES_PER_FIELD:
            break
        if not use_re.search(raw):
            continue
        line_no = idx + 1
        # Skip the hit line itself (it's the declaration, already shown
        # in the enclosing-function block).
        if line_no == line_start:
            continue
        s, snippet = _slice(code_lines, line_no - A_USE_RADIUS, line_no + A_USE_RADIUS)
        block = _format_block(s, snippet)
        size = len(block) + 64  # header overhead
        if total_bytes + size > A_MAX_TOTAL_BYTES:
            break
        use_blocks.append(f"第 {line_no} 行附近：\n```\n{block}\n```")
        total_bytes += size

    # 2. Safety-token scan over the whole file (cheap).
    file_text = "\n".join(code_lines)
    found_tokens: list[str] = []
    for token in A_SAFETY_TOKENS:
        # Word-ish boundary — handle `Collections.unmodifiableMap(` etc.
        if token in file_text:
            count = file_text.count(token)
            found_tokens.append(f"`{token}`×{count}")

    body_parts: list[str] = []
    body_parts.append(
        f"_这是规则 STATIC-MUTABLE-SHARED-STATE 等并发类规则的增强证据。_  \n"
        f"_目标字段：`{field_name}`_"
    )

    if found_tokens:
        body_parts.append(
            "**本文件中出现的并发安全/不可变包装迹象**（仅做事实陈列，不预设结论）：\n- "
            + ", ".join(found_tokens)
        )
    else:
        body_parts.append(
            "**本文件中未发现任何并发安全包装迹象**"
            "（无 ConcurrentXxx / synchronized / unmodifiable / Atomic / volatile 等）。"
        )

    if use_blocks:
        body_parts.append(
            f"**`{field_name}` 在本文件中的使用点（含 method 调用 / synchronized 块）：**\n\n"
            + "\n\n".join(use_blocks)
        )
    else:
        body_parts.append(
            f"**未在本文件其他位置找到 `{field_name}` 的方法调用或 synchronized 块。**"
            "（可能仅在声明处使用，或被跨文件读写。）"
        )

    return EvidenceBlock(
        header="增强证据：静态字段使用面（A 类）",
        body="\n\n".join(body_parts),
    )


# ────────────────────────────────────────────────────────────────────
# B — Exception swallowing: catch/except body + caller tail
# ────────────────────────────────────────────────────────────────────

_JAVA_CATCH_RE = re.compile(r"\bcatch\s*\(")
_PY_EXCEPT_RE = re.compile(r"^\s*except\b")


def collect_b_exception_evidence(
    *,
    file_path: Path,
    line_start: int,
    code_lines: list[str],
    callers: list,  # list[CallGraphSnippet] — duck-typed to avoid import cycle
) -> EvidenceBlock | None:
    """For exception-swallow rules, surface:

    1. **Full catch/except body** starting at the hit line, until the
       block-closing brace/dedent. Default Pass 2 already shows the
       enclosing function, but for very long methods the catch body can
       be truncated; this guarantees it's complete.

    2. **Tail of each caller** — the last ~25 lines of the calling
       function, where retry / fallback / surfacing error usually lives.
       If the caller wraps the call in its own try/catch + retry loop,
       a "swallow" inside isn't really a swallow.

    Returns None when neither evidence stream produced anything.
    """
    if not code_lines or line_start <= 0:
        return None

    language = language_from_path(file_path)
    catch_block = _extract_catch_body(code_lines, line_start, language)

    # Caller tails — last C_TAIL lines of each caller body.
    caller_tails: list[str] = []
    total_bytes = len(catch_block) if catch_block else 0
    for snip in callers or []:
        if total_bytes >= B_MAX_TOTAL_BYTES:
            break
        body_lines = snip.code.splitlines() if snip.code else []
        if not body_lines:
            continue
        tail = body_lines[-B_CALLER_TAIL_MAX_LINES:]
        tail_text = "\n".join(tail)
        section = (
            f"### `{snip.function_name}` "
            f"({snip.file_path}:{snip.line_start}-{snip.line_end}) — 末尾 {len(tail)} 行\n"
            f"```\n{tail_text}\n```"
        )
        size = len(section)
        if total_bytes + size > B_MAX_TOTAL_BYTES:
            break
        caller_tails.append(section)
        total_bytes += size

    if not catch_block and not caller_tails:
        return None

    body_parts: list[str] = [
        "_这是异常吞掉/宽泛 catch 类规则的增强证据。"
        "判断要点：catch 块内是否有重抛/兜底/明确错误返回；调用方是否有 retry/fallback/上层处理。_",
    ]
    if catch_block:
        body_parts.append(
            f"**完整 catch/except 块：**\n```\n{catch_block}\n```"
        )
    if caller_tails:
        body_parts.append(
            "**调用方函数末尾（重试/兜底/异常抛出通常在这）：**\n\n"
            + "\n\n".join(caller_tails)
        )

    return EvidenceBlock(
        header="增强证据：异常处理上下文（B 类）",
        body="\n\n".join(body_parts),
    )


def _extract_catch_body(
    lines: list[str],
    hit_line: int,
    language: str | None,
) -> str:
    """Return formatted catch/except block starting at or near ``hit_line``.

    Strategy:
      - Java/JS/TS/C++/C#: scan from hit_line up to 5 lines back to find a
        line containing ``catch (``, then walk forward tracking brace depth
        until ``{...}`` closes (or until ``B_CATCH_BODY_MAX_LINES`` reached).
      - Python: find the ``except`` line, then capture the indented block
        following it.

    Returns "" when no catch-like construct is detectable.
    """
    if not lines or hit_line <= 0:
        return ""
    n = len(lines)
    idx = min(max(hit_line - 1, 0), n - 1)

    if language == "python":
        # Find the nearest preceding `except` line (within 5 lines).
        anchor = None
        for i in range(idx, max(idx - 5, -1), -1):
            if _PY_EXCEPT_RE.search(lines[i]):
                anchor = i
                break
        if anchor is None:
            return ""
        # Capture indented block.
        header_indent = len(lines[anchor]) - len(lines[anchor].lstrip())
        out: list[str] = [lines[anchor]]
        for i in range(anchor + 1, min(anchor + 1 + B_CATCH_BODY_MAX_LINES, n)):
            cur = lines[i]
            if not cur.strip():
                out.append(cur)
                continue
            cur_indent = len(cur) - len(cur.lstrip())
            if cur_indent <= header_indent:
                break
            out.append(cur)
        return _format_block(anchor + 1, out)

    # Brace-language path.
    anchor = None
    for i in range(idx, max(idx - 5, -1), -1):
        if _JAVA_CATCH_RE.search(lines[i]):
            anchor = i
            break
    if anchor is None:
        return ""
    # Walk forward tracking brace depth. Start counting from the first '{'
    # we see on or after the catch line.
    depth = 0
    saw_open = False
    out_lines: list[str] = []
    for i in range(anchor, min(anchor + B_CATCH_BODY_MAX_LINES, n)):
        cur = lines[i]
        out_lines.append(cur)
        for ch in cur:
            if ch == "{":
                depth += 1
                saw_open = True
            elif ch == "}":
                depth -= 1
                if saw_open and depth <= 0:
                    return _format_block(anchor + 1, out_lines)
    return _format_block(anchor + 1, out_lines)


# ────────────────────────────────────────────────────────────────────
# C — Resource lifecycle: surrounding try/finally/with structure
# ────────────────────────────────────────────────────────────────────

_C_LIFECYCLE_TOKENS = (
    "try-with-resources",  # textual cue (Java docs/comments)
    "try (",               # Java try-with-resources actual syntax
    "try(",
    "finally",
    "defer ",              # Go
    "with ",               # Python
    ".close(",
    "AutoCloseable",
    "Closeable",
)


def collect_c_resource_evidence(
    *,
    file_path: Path,
    line_start: int,
    code_lines: list[str],
) -> EvidenceBlock | None:
    """For RESOURCE-LEAK / RESOURCE-CLOSE-NOT-GUARANTEED, surface:

    1. **Window around the hit**: lines from ``hit - 5`` to ``hit + 25``,
       which usually contains the ``try (...) {`` opener / ``finally``
       block / ``defer`` / ``with`` statement.

    2. **Lifecycle-token scan**: which resource-management tokens appear
       in that window. Lets the AI immediately see "no `finally`, no `try (`,
       no `.close(`" vs "try-with-resources is used 2 lines above the hit".

    Bounded to ~2KB total. Returns None when window extraction fails.
    """
    if not code_lines or line_start <= 0:
        return None

    s, window = _slice(
        code_lines,
        line_start - C_WINDOW_BEFORE,
        line_start + C_WINDOW_AFTER,
    )
    if not window:
        return None
    block = _format_block(s, window)
    if len(block) > C_MAX_TOTAL_BYTES:
        # Trim from the tail — context closer to the hit is more valuable.
        block = block[:C_MAX_TOTAL_BYTES] + "\n... (已按字节预算截断)"

    window_text = "\n".join(window)
    found_tokens: list[str] = []
    for token in _C_LIFECYCLE_TOKENS:
        if token in window_text:
            found_tokens.append(f"`{token.strip()}`")

    if found_tokens:
        token_summary = "**该窗口出现的资源管理迹象**：" + ", ".join(found_tokens)
    else:
        token_summary = (
            "**该窗口未出现 try-with-resources / finally / defer / with / .close() / "
            "AutoCloseable 等资源管理迹象。**"
        )

    body = (
        "_这是资源泄漏类规则的增强证据。"
        "判断要点：命中行附近是否有 try-with-resources / finally / defer / with 等"
        "确定性释放结构。_\n\n"
        f"{token_summary}\n\n"
        f"**命中行 -{C_WINDOW_BEFORE} ~ +{C_WINDOW_AFTER} 行窗口：**\n"
        f"```\n{block}\n```"
    )
    return EvidenceBlock(
        header="增强证据：资源生命周期窗口（C 类）",
        body=body,
    )


# ────────────────────────────────────────────────────────────────────
# Public dispatch
# ────────────────────────────────────────────────────────────────────


def is_enhanced_rule(rule_id: str | None) -> bool:
    """Return True when this rule_id has a registered evidence collector.

    The verifier uses this to force Pass 2 escalation regardless of
    Pass 1's verdict — the user's hard requirement: "宁愿不要检查出问题，
    也不要检查一堆假问题"。 Forcing Pass 2 ensures these high-FP rules
    always get the richer context before any verdict is finalized.
    """
    return rule_id in ENHANCED_RULE_IDS


def collect_evidence_for_rule(
    *,
    rule_id: str | None,
    file_path: Path,
    line_start: int,
    code_lines: list[str],
    callers: list,
) -> EvidenceBlock | None:
    """Dispatch ``rule_id`` to the matching collector. Returns ``None`` for
    unmapped rules — the caller (prompts.py) just skips inlining anything.

    ``callers`` is the list of ``CallGraphSnippet`` already computed by the
    base Pass 2 pipeline. We accept it as a generic list to avoid an import
    cycle with ``call_graph.py`` — only the ``code`` / ``function_name`` /
    ``file_path`` / ``line_start`` / ``line_end`` attributes are used.
    """
    if rule_id is None:
        return None
    if rule_id in A_RULE_IDS:
        return collect_a_static_mutable_evidence(
            file_path=file_path,
            line_start=line_start,
            code_lines=code_lines,
        )
    if rule_id in B_RULE_IDS:
        return collect_b_exception_evidence(
            file_path=file_path,
            line_start=line_start,
            code_lines=code_lines,
            callers=callers,
        )
    if rule_id in C_RULE_IDS:
        return collect_c_resource_evidence(
            file_path=file_path,
            line_start=line_start,
            code_lines=code_lines,
        )
    return None
