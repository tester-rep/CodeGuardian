"""LocalValidator — zero-cost post-AI finding verification using local AST analysis.

Design doc §七: "用本地能力验证 AI findings，零 token 成本"

After AI returns findings, this module performs lightweight local checks to
filter likely false positives WITHOUT spending additional AI tokens:

  - null_safety: Check if variable has null guard before the flagged line
  - security/injection: Check if input passes through known sanitizer
  - resource: Check if resource has matching close/release in same scope
  - error_handling: Check if exception is re-raised or logged (not truly swallowed)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codeguardian.ai.deep_review.models import AIFindingRaw

logger = logging.getLogger(__name__)


class ValidationVerdict(Enum):
    """Result of local validation."""

    CONFIRMED = "confirmed"  # Local evidence supports AI finding
    LIKELY_FP = "likely_fp"  # Local evidence contradicts AI finding
    UNVERIFIED = "unverified"  # Cannot determine locally, keep AI judgment


@dataclass
class ValidationResult:
    """Result of validating a single AI finding."""

    verdict: ValidationVerdict
    reason: str = ""


# Known sanitizer/validator function names (case-insensitive patterns)
_SANITIZER_PATTERNS = re.compile(
    r"\b(?:sanitize|escape|clean|validate|filter|quote|param|bind|prepare|"
    r"html_escape|url_encode|encode_for|anti_xss|strip_tags|bleach|"
    r"markupsafe|defuse|secure|safe_|htmlspecialchars|addslashes|"
    r"mysql_real_escape|pg_escape|parameterize|placeholder)\b",
    re.IGNORECASE,
)

# Null guard patterns
_NULL_CHECK_PATTERNS = re.compile(
    r"\b(?:is not None|is None|!= None|== None|!= null|== null|"
    r"!= nil|== nil|if\s+\w+\s*[!]=\s*(?:None|null|nil)|"
    r"Optional\.isPresent|\.isPresent\(\)|Objects\.requireNonNull|"
    r"assert\s+\w+\s+is not None|guard\s+let)\b",
    re.IGNORECASE,
)

# Resource close patterns
_RESOURCE_CLOSE_PATTERNS = re.compile(
    r"\b(?:\.close\(\)|\.dispose\(\)|\.release\(\)|\.shutdown\(\)|"
    r"\.disconnect\(\)|finally:|__exit__|contextmanager|"
    r"with\s+|using\s*\(|defer\s+|try-with-resources)\b",
    re.IGNORECASE,
)

# Exception handling patterns (not truly swallowed)
_EXCEPTION_HANDLED_PATTERNS = re.compile(
    r"\b(?:logger\.|log\.|logging\.|raise|throw|rethrow|re-raise|"
    r"return\s+(?:err|error)|panic\(|os\.Exit|sys\.exit)\b",
    re.IGNORECASE,
)

# ─── Hallucinated-evidence detection ──────────────────────────────────────────
#
# Detects AI findings that quote a code string which doesn't actually exist
# in the source (e.g. AI claims "关键字 'retur' 应为 'return'" when the source
# clearly contains `return`). This is the single most common LLM hallucination
# pattern — a token-level misreading by smaller models.
#
# Strategy: only trigger when the AI uses an *assertive* phrasing about a
# specific quoted token. We extract those tokens and check the file ±5 lines
# around the flagged line. Any single missing token → LIKELY_FP.
#
# Conservative on purpose: AI may legitimately reference class/function names
# that live elsewhere in the codebase. We only enforce the check when the
# evidence text contains language that asserts the token is *literally
# present at this location*.

# Phrases that signal "AI is asserting this exact string exists in source".
# Matched against evidence + description + fix_suggestion (lower-cased).
_ASSERTIVE_PHRASES = (
    "关键字",
    "应该是",
    "应为",
    "应改为",
    "拼写",
    "拼错",
    "写错",
    "代码中存在",
    "源码中存在",
    "should be",
    "typo",
    "misspelled",
    "should read",
)

# Quoted tokens: backticks, single, or double quotes.
# Length capped to avoid matching long phrases — we want short identifiers/keywords.
_QUOTED_TOKEN_RE = re.compile(r"[`'\"]([A-Za-z_][A-Za-z0-9_]{0,29})[`'\"]")

# ─── Long-lived resource patterns (process-scoped, not per-call) ─────────────
# These are typical "client/pool/executor" objects that intentionally live
# for the lifetime of the process. AI frequently reports them as "resource
# leak" because there is no explicit close, but closing them per-method is
# wrong by design.
_LONG_LIVED_RESOURCE_TYPES = re.compile(
    r"\b(?:OkHttpClient|HttpClient|RestTemplate|WebClient|ApacheHttpClient|"
    r"ThreadPoolExecutor|ScheduledThreadPoolExecutor|ForkJoinPool|"
    r"Executors\.new\w+|"
    r"HikariDataSource|DruidDataSource|BasicDataSource|DataSource|"
    r"RedisTemplate|JedisPool|LettuceConnectionFactory|"
    r"KafkaProducer|KafkaConsumer|"
    r"OkHttpClient\.Builder|MongoClient|"
    r"requests\.Session|aiohttp\.ClientSession|httpx\.Client|httpx\.AsyncClient)\b"
)

# Annotations / declarations that signal "container manages lifecycle"
_CONTAINER_MANAGED_HINTS = re.compile(
    r"@(?:Component|Service|Repository|Bean|Configuration|RestController|Controller)\b|"
    r"\bstatic\s+final\s+\w+|\bprivate\s+final\s+\w+|"
    r"@Singleton\b|@Inject\b|@Autowired\b"
)

# Singleton fail-fast pattern: class has both an init() and getInstance() and
# getInstance throws when uninitialised. This is intentional design (e.g.
# Java DriverManager-style), not a bug.
# Match: getInstance() ... throw new XxxException, allowing nested braces
# (e.g. an inner `if (x == null) { throw ... }`). We cap to ~30 lines of body
# by limiting characters to ~600 to avoid runaway matches across the file.
_FAIL_FAST_SINGLETON_RE = re.compile(
    r"\bgetInstance\s*\([^)]*\)[^{]*\{.{0,600}?throw\s+new\s+\w+Exception",
    re.DOTALL,
)
_HAS_INIT_METHOD_RE = re.compile(
    r"\bpublic\s+static\s+\w+\s+init\s*\(",
)

# Infinite loops with intentional sleep/yield (worker / scheduler / main loop)
_INTENTIONAL_LOOP_BODY_RE = re.compile(
    r"\b(?:Thread\.sleep|TimeUnit\.\w+\.sleep|sleep\(|"
    r"time\.sleep|asyncio\.sleep|await\s+asyncio\.sleep|"
    r"select\(|poll\(|wait\()\b",
)

# Parameter / variable name extraction from finding evidence.
# Catches phrases like:
#   "变量 paramMap 可能为 null"  /  "变量 `result` may be None"
#   "L70: paramMap.get() 可能返回 null"
#   "result.value may NPE"
_VAR_NAME_FROM_EVIDENCE_RE = re.compile(
    r"(?:变量\s*[`'\"]?([A-Za-z_][A-Za-z0-9_]{0,40})[`'\"]?|"
    r"\b([A-Za-z_][A-Za-z0-9_]{1,40})\.(?:get|put|set|add|remove|"
    r"value|field|method|call|invoke|run)\s*\(|"
    r"\b([A-Za-z_][A-Za-z0-9_]{1,40})\s+(?:may|might|could|可能)\s+(?:be|return|为)\s*(?:null|None|nil))",
)


class LocalValidator:
    """Validates AI findings using local static analysis (zero token cost).

    Operates on source code directly — no AI calls needed.
    Typically filters 10-30% additional false positives beyond the critic.
    """

    def __init__(self, project_root: Path) -> None:
        self._project_root = project_root
        self._file_cache: dict[str, str] = {}

    def validate_findings(
        self, findings: list[AIFindingRaw], file_path: str,
    ) -> list[tuple[AIFindingRaw, ValidationResult]]:
        """Validate a list of AI findings for a given file.

        Returns list of (finding, validation_result) tuples.
        """
        results: list[tuple[AIFindingRaw, ValidationResult]] = []
        source = self._read_file(file_path)

        for finding in findings:
            result = self._validate_single(finding, file_path, source)
            results.append((finding, result))

        return results

    def filter_false_positives(
        self, findings: list[AIFindingRaw], file_path: str,
    ) -> tuple[list[AIFindingRaw], list[AIFindingRaw]]:
        """Split findings into kept and filtered-out lists.

        Returns (kept_findings, filtered_findings).
        """
        validated = self.validate_findings(findings, file_path)
        kept: list[AIFindingRaw] = []
        filtered: list[AIFindingRaw] = []

        for finding, result in validated:
            if result.verdict == ValidationVerdict.LIKELY_FP:
                filtered.append(finding)
                logger.debug(
                    "LocalValidator filtered FP: %s @ L%d — %s",
                    finding.title, finding.line_start, result.reason,
                )
            else:
                kept.append(finding)

        if filtered:
            logger.info(
                "LocalValidator: %d/%d findings filtered as likely FP in %s",
                len(filtered), len(validated), file_path,
            )

        return kept, filtered

    def _validate_single(
        self, finding: AIFindingRaw, file_path: str, source: str,
    ) -> ValidationResult:
        """Apply category-specific validation logic."""
        # Universal check first: does the AI's evidence actually quote
        # a code string that exists in the source? If the AI asserts a
        # specific token is present and we can't find it, that's a
        # hallucination — drop regardless of category.
        evidence_check = self._check_evidence_substring(finding, source)
        if evidence_check.verdict == ValidationVerdict.LIKELY_FP:
            return evidence_check

        # Universal check: intentional fail-fast singleton design.
        # Catches cases like "getInstance() throws when not initialised"
        # which AI flags as critical "uninitialised singleton" bug.
        ff = self._check_intentional_fail_fast(finding, source)
        if ff.verdict == ValidationVerdict.LIKELY_FP:
            return ff

        # Universal check: intentional infinite loop (worker thread, main
        # event loop with sleep/wait/poll).
        loop = self._check_intentional_infinite_loop(finding, source)
        if loop.verdict == ValidationVerdict.LIKELY_FP:
            return loop

        category = finding.category.lower()

        if category == "null_safety":
            return self._check_null_guard(finding, source)
        elif category == "security":
            return self._check_sanitizer(finding, source)
        elif category == "resource":
            # First: long-lived process-scoped clients/pools should not be
            # closed per-method — these are by-design and not leaks.
            llr = self._check_long_lived_resource(finding, source)
            if llr.verdict == ValidationVerdict.LIKELY_FP:
                return llr
            return self._check_resource_close(finding, source)
        elif category == "error_handling":
            return self._check_exception_handling(finding, source)

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _check_evidence_substring(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Reject findings whose evidence quotes a token absent from the source.

        Only triggers when the AI uses *assertive* language about a specific
        quoted token (see ``_ASSERTIVE_PHRASES``). Without such a trigger,
        quoted strings may legitimately reference symbols defined elsewhere —
        we stay neutral (UNVERIFIED) in that case.

        Returns LIKELY_FP if any asserted token cannot be found within ±5 lines
        of ``finding.line_start``. Otherwise UNVERIFIED.
        """
        # Combine all AI-authored text fields for analysis.
        combined = " ".join(filter(None, [
            finding.evidence or "",
            finding.description or "",
            finding.fix_suggestion or "",
            finding.title or "",
        ]))
        if not combined:
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        combined_lower = combined.lower()
        # Cheap gate: only run the expensive check if the AI is asserting
        # something about a literal code string at this location.
        if not any(phrase in combined_lower for phrase in _ASSERTIVE_PHRASES):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Extract quoted short tokens (identifiers/keywords).
        quoted_tokens = _QUOTED_TOKEN_RE.findall(combined)
        if not quoted_tokens:
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        lines = source.splitlines()
        if not lines or finding.line_start <= 0:
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Search window: ±5 lines around the flagged line, clamped to file.
        start = max(0, finding.line_start - 6)
        end = min(len(lines), finding.line_start + 5)
        window = "\n".join(lines[start:end])

        # Word-boundary check: a quoted token must appear as a *complete*
        # identifier in the window. Substring matching would falsely confirm
        # 'retur' inside 'return' — exactly the bug we're trying to catch.
        missing: list[str] = []
        for tok in set(quoted_tokens):
            pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(tok) + r"(?![A-Za-z0-9_])")
            if not pattern.search(window):
                missing.append(tok)

        if missing:
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason=(
                    f"AI asserted token(s) {missing!r} exist near "
                    f"L{finding.line_start} but they are absent from the source "
                    "(likely hallucination)"
                ),
            )

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _check_null_guard(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Check if there's a null guard for the *specific variable* the
        finding accuses, in the preceding code path.

        Two-stage strategy:
        1. Try to extract the accused variable name from evidence/description
           using known patterns (e.g. "变量 X 可能为 null" / "X.method() may NPE").
           If found, look for an explicit guard on *that* variable (`if X != null`,
           `X != null`, `Objects.requireNonNull(X)`, `X is not None`, etc.).
        2. Fallback: any null-check token in the preceding 10 lines (legacy
           heuristic). This is intentionally weak — only triggers when the
           variable name cannot be extracted.
        """
        lines = source.splitlines()
        target_line = finding.line_start

        if target_line <= 0 or target_line > len(lines):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Window: 12 lines before the flagged line + the flagged line itself.
        # Tightened from 10 → 12 to catch guards in early function bodies.
        start_check = max(0, target_line - 13)
        preceding_code = "\n".join(lines[start_check:target_line])

        # Stage 1: try to extract the accused variable name.
        var_name = self._extract_accused_variable(finding)
        if var_name:
            # Build a pattern that matches an explicit guard on *this* variable.
            # Examples it must catch:
            #   if (X != null) {            (Java/C/C++/Go-ish)
            #   if (X == null) return ...;  (early-return guard)
            #   if X is not None:           (Python)
            #   if X is None: raise ...     (early-raise guard)
            #   X != nil                     (Go)
            #   Objects.requireNonNull(X)
            #   assert X is not None
            #   if (X.isPresent())
            #   if (X.get(...) != null)     ← guard on a method call result of X
            v = re.escape(var_name)
            guard_re = re.compile(
                rf"\b{v}\s*(?:!=|==)\s*(?:null|None|nil)|"
                rf"\b{v}\s+is\s+(?:not\s+)?None|"
                rf"\b{v}\.\w+\s*\([^)]*\)\s*(?:!=|==)\s*(?:null|None|nil)|"
                rf"Objects\.requireNonNull\s*\(\s*{v}\b|"
                rf"\b{v}\.isPresent\s*\(\)|"
                rf"\bassert\s+{v}\s+is\s+not\s+None|"
                rf"\bif\s*\(?\s*!?\s*{v}\s*[\)\s]",
                re.IGNORECASE,
            )
            if guard_re.search(preceding_code):
                return ValidationResult(
                    verdict=ValidationVerdict.LIKELY_FP,
                    reason=(
                        f"Explicit null guard for variable '{var_name}' "
                        f"found in preceding code (within 12 lines)"
                    ),
                )
            # If we have a variable name AND the surrounding scope contains
            # a `throw`/`raise` statement keyed on that variable being null,
            # AI's "missing null handling" finding is likely a FP — fail-fast
            # IS handling. Look at function-scope (50 lines back).
            func_scope_start = max(0, target_line - 51)
            func_scope = "\n".join(lines[func_scope_start:target_line])
            fail_fast_re = re.compile(
                rf"if\s*\(?\s*{v}\s*==\s*(?:null|None|nil)[^{{]*?(?:throw|raise|return)",
                re.IGNORECASE | re.DOTALL,
            )
            if fail_fast_re.search(func_scope):
                return ValidationResult(
                    verdict=ValidationVerdict.LIKELY_FP,
                    reason=(
                        f"Variable '{var_name}' is fail-fast guarded "
                        f"(throw/raise/return on null) in function scope"
                    ),
                )
            # Variable was identified but no specific guard found — this is
            # genuinely suspicious; do NOT degrade to the weak generic check,
            # report UNVERIFIED so AI judgment stands.
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Stage 2 fallback: legacy weak heuristic.
        if _NULL_CHECK_PATTERNS.search(preceding_code):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason="Generic null guard found in preceding code path",
            )

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _extract_accused_variable(self, finding: AIFindingRaw) -> str | None:
        """Best-effort extraction of the variable name the finding accuses.

        Returns None if no clear variable can be identified — caller falls
        back to the generic guard check.
        """
        combined = " ".join(filter(None, [
            finding.evidence or "",
            finding.description or "",
        ]))
        if not combined:
            return None

        # Try patterns in order of specificity.
        for match in _VAR_NAME_FROM_EVIDENCE_RE.finditer(combined):
            for group in match.groups():
                if group and len(group) >= 2:
                    # Skip language keywords to avoid false matches.
                    if group.lower() in {
                        "null", "none", "nil", "true", "false", "this", "self",
                        "if", "else", "for", "while", "return", "throw", "raise",
                        "new", "var", "let", "const", "int", "string", "void",
                    }:
                        continue
                    return group
        return None

    def _check_long_lived_resource(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Reject resource-leak findings on process-scoped objects.

        Pattern: HTTP clients / thread pools / DB pools / message brokers
        declared as `static final`, `private final`, or inside @Component-
        annotated classes are intentionally kept alive for the process
        lifetime. Closing them per-method would break the program.
        """
        lines = source.splitlines()
        target_line = finding.line_start
        if target_line <= 0 or target_line > len(lines):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        flagged_line = lines[target_line - 1]
        # Quick gate: is the flagged line about a known long-lived type?
        if not _LONG_LIVED_RESOURCE_TYPES.search(flagged_line):
            # Also check the surrounding window (resource may be declared
            # a few lines above the flagged usage).
            window_start = max(0, target_line - 6)
            window_end = min(len(lines), target_line + 2)
            window = "\n".join(lines[window_start:window_end])
            if not _LONG_LIVED_RESOURCE_TYPES.search(window):
                return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Now check whether the file/class indicates container-managed or
        # singleton lifecycle. If yes → strongly likely FP.
        # Look at the entire file (not just nearby lines) for these hints.
        if _CONTAINER_MANAGED_HINTS.search(source):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason=(
                    "Resource is a long-lived client/pool in a container-"
                    "managed or singleton context (per-call close would be "
                    "incorrect)"
                ),
            )

        # Even without explicit annotation, if the type is one of the
        # well-known process-scoped types AND the declaration is at class
        # level (not inside a method), treat as long-lived.
        # Heuristic: declaration line is indented ≤ 4 spaces and contains
        # "private" or "public" but no surrounding method braces.
        decl_line = flagged_line.lstrip()
        if (
            decl_line.startswith(("private ", "public ", "protected "))
            and "(" not in decl_line.split("=")[0]  # not a method signature
        ):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason=(
                    "Class-level long-lived resource declaration; per-call "
                    "close is not appropriate"
                ),
            )

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _check_intentional_fail_fast(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Reject findings that flag intentional fail-fast singleton design.

        Pattern: a class exposes both `init(...)` and `getInstance()`, and
        `getInstance()` throws when not yet initialised. This is a deliberate
        design contract (callers must init first), not a bug. AI commonly
        mis-classifies this as a critical "uninitialised singleton" issue.

        Trigger heuristic: finding mentions getInstance/singleton/init AND
        the source contains the canonical fail-fast pattern.
        """
        # Cheap textual gate on the finding itself.
        text = " ".join(filter(None, [
            finding.title or "",
            finding.description or "",
            finding.evidence or "",
        ])).lower()
        if not any(kw in text for kw in (
            "getinstance", "未初始化", "uninitialized", "uninitialised",
            "singleton", "单例", "init", "未调用",
        )):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Both patterns must match in the source for this to be the
        # canonical fail-fast singleton design.
        if (_FAIL_FAST_SINGLETON_RE.search(source)
                and _HAS_INIT_METHOD_RE.search(source)):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason=(
                    "Intentional fail-fast singleton: class exposes init() "
                    "and getInstance() throws when not initialised — this "
                    "is a deliberate design contract, not a bug"
                ),
            )

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _check_intentional_infinite_loop(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Reject 'infinite loop' findings on intentional event/worker loops.

        Pattern: `while(true)` / `while True` / `for(;;)` containing a
        sleep/wait/poll call is the canonical worker thread or event loop
        body. AI flags these as "infinite loop" risks but they are by design.
        """
        text = " ".join(filter(None, [
            finding.title or "",
            finding.description or "",
            finding.evidence or "",
        ])).lower()
        # Only run this check if the finding actually claims an infinite loop.
        if not any(kw in text for kw in (
            "infinite loop", "死循环", "无限循环", "while(true)", "while true",
            "while(1)", "for(;;)", "busy loop", "busy-loop", "忙等",
        )):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        lines = source.splitlines()
        target_line = finding.line_start
        if target_line <= 0 or target_line > len(lines):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Examine the loop body: 30 lines after the flagged line should be
        # enough to spot a sleep/wait/poll call.
        end_check = min(len(lines), target_line + 30)
        loop_body = "\n".join(lines[target_line - 1:end_check])

        if _INTENTIONAL_LOOP_BODY_RE.search(loop_body):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason=(
                    "Loop body contains intentional sleep/wait/poll — "
                    "this is a worker/event loop by design, not a busy loop"
                ),
            )

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _check_sanitizer(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Check if input passes through a known sanitizer before use."""
        lines = source.splitlines()
        target_line = finding.line_start

        if target_line <= 0 or target_line > len(lines):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Check surrounding context (10 lines before) for sanitizer calls
        start_check = max(0, target_line - 11)
        preceding_code = "\n".join(lines[start_check:target_line - 1])

        if _SANITIZER_PATTERNS.search(preceding_code):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason="Input sanitizer/validator found in preceding code",
            )

        # Also check if line itself uses parameterized query
        flagged_line = lines[target_line - 1] if target_line <= len(lines) else ""
        if re.search(r"\?\s*,|\%s|:\w+|\$\d+|\bparam|placeholders?\b", flagged_line, re.IGNORECASE):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason="Parameterized query/placeholder detected on flagged line",
            )

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _check_resource_close(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Check if resource has a matching close/release in scope."""
        lines = source.splitlines()
        target_line = finding.line_start

        if target_line <= 0 or target_line > len(lines):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Check lines after the flagged line (up to 20 lines) for close patterns
        end_check = min(len(lines), target_line + 20)
        following_code = "\n".join(lines[target_line:end_check])

        if _RESOURCE_CLOSE_PATTERNS.search(following_code):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason="Resource close/release found in following code",
            )

        # Also check if entire function uses context manager (with/using/defer)
        start_check = max(0, target_line - 5)
        scope_code = "\n".join(lines[start_check:end_check])
        if re.search(r"\bwith\s+|using\s*\(|defer\s+", scope_code):
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason="Context manager/defer pattern in scope",
            )

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _check_exception_handling(
        self, finding: AIFindingRaw, source: str,
    ) -> ValidationResult:
        """Check if exception is truly swallowed or actually handled.

        Updated logic: logger.error alone does NOT constitute "handled".
        Only the following patterns count as genuine handling:
          - re-raise (throw / raise)
          - return an error sentinel (return error / return err / return null)
          - recovery action that restores program state
        Simply logging the exception and continuing = swallowed.
        """
        lines = source.splitlines()
        target_line = finding.line_start

        if target_line <= 0 or target_line > len(lines):
            return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

        # Check the except/catch block for GENUINE handling patterns
        start_check = max(0, target_line - 2)
        end_check = min(len(lines), target_line + 8)
        block_code = "\n".join(lines[start_check:end_check])

        # Patterns that indicate GENUINE handling (not just logging)
        _GENUINE_HANDLE_PATTERNS = re.compile(
            r"\b(?:raise|throw|rethrow|re-raise|"
            r"return\s+(?:err|error|null|None|false|DEFAULT)|"
            r"panic\(|os\.Exit|sys\.exit)\b",
            re.IGNORECASE,
        )

        # Patterns that indicate ONLY logging (swallowed)
        _LOG_ONLY_PATTERNS = re.compile(
            r"\blogger\.\w+|log\.\w+|logging\.\w+|print\(.*exception"
            r"|System\.err\.print",
            re.IGNORECASE,
        )

        has_genuine = bool(_GENUINE_HANDLE_PATTERNS.search(block_code))
        has_log_only = bool(_LOG_ONLY_PATTERNS.search(block_code))

        if has_genuine:
            # Has re-raise or error-return → genuinely handled
            return ValidationResult(
                verdict=ValidationVerdict.LIKELY_FP,
                reason="Exception is genuinely handled (re-raised or returns error sentinel)",
            )

        if has_log_only and not has_genuine:
            # Only logging, no genuine handling → confirm AI's finding
            # Do NOT filter — this IS a swallowed exception
            return ValidationResult(verdict=ValidationVerdict.CONFIRMED)

        return ValidationResult(verdict=ValidationVerdict.UNVERIFIED)

    def _read_file(self, file_path: str) -> str:
        """Read and cache file content."""
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        abs_path = self._project_root / file_path
        try:
            content = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            content = ""

        self._file_cache[file_path] = content
        return content
