"""Shared helpers for rule-based engines."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.evidence import CodeSnippetEvidence, RuleMatchEvidence
from codeguardian.models.finding import Finding


_STATIC_CONFIRMED_RULE_IDS = {
    "SYNTAX-ERROR",
    "DIVISION-BY-ZERO-RISK",
    "COLLECTION-INDEX-OUT-OF-BOUNDS",
    "INFINITE-RECURSION-RISK",
    "EXCEPTION-NOT-RAISED",
    "SELF-ASSIGNMENT",
    "UNREACHABLE-CODE",
}


@dataclass(frozen=True, slots=True)
class RuleSpec:

    """Static metadata for a rule."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    fix_suggestion: str | None = None
    blocks_release: bool = False
    risk_priority: str = "should-fix"
    tags: tuple[str, ...] = field(default_factory=tuple)
    applicable_languages: tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)
    owasp: tuple[str, ...] = field(default_factory=tuple)
    description_zh: str | None = None  # 人工可读的中文解释
    reference_url: str | None = None   # 规则参考链接（CWE/OWASP 等）


@dataclass(frozen=True, slots=True)
class RuleHit:
    """A concrete rule match inside a file."""

    rule: RuleSpec
    file_path: str
    line_start: int
    line_end: int
    message: str | None = None
    language: str | None = None
    metadata: dict[str, str | list[str]] = field(default_factory=dict)





def build_finding(
    hit: RuleHit,
    lines: list[str],
    finding_id: str,
    source_engine: str,
    context_radius: int = 2,
) -> Finding:
    """Convert a normalized rule hit into a Finding with code snippet evidence."""

    start_line = max(1, hit.line_start - context_radius)
    end_line = min(len(lines), hit.line_end + context_radius) if lines else hit.line_end
    snippet_lines = lines[start_line - 1:end_line] if lines else []
    snippet = "\n".join(
        f"{line_no:4d}: {line}"
        for line_no, line in zip(range(start_line, end_line + 1), snippet_lines, strict=False)
    )


    detail = hit.message or f"Matched {hit.rule.rule_id} at lines {hit.line_start}-{hit.line_end}"

    # ── Build rich root_cause ────────────────────────────────────────
    root_cause = _build_root_cause(hit, detail)
    evidence_level, verification_status, verification_summary = _classify_evidence(hit)

    return Finding(

        id=finding_id,
        title=hit.rule.title,
        category=hit.rule.category,
        severity=hit.rule.severity,
        confidence=hit.rule.confidence,
        location=Location(
            file_path=hit.file_path,
            line_start=hit.line_start,
            line_end=hit.line_end,
        ),
        evidences=[
            CodeSnippetEvidence(
                content=snippet,
                file_path=hit.file_path,
                line_start=start_line,
                line_end=end_line,
                source_engine=source_engine,
                language=hit.language,
            ),
            RuleMatchEvidence(
                rule_id=hit.rule.rule_id,
                rule_category=hit.rule.category,
                content=detail,
                file_path=hit.file_path,
                line_start=hit.line_start,
                line_end=hit.line_end,
                source_engine=source_engine,
                language=hit.language,
                extra={
                    **hit.metadata,
                    "cwe_ids": list(hit.rule.cwe_ids),
                    "owasp": list(hit.rule.owasp),
                },
            ),

        ],
        blocks_release=hit.rule.blocks_release,
        risk_priority=hit.rule.risk_priority,
        source_engine=source_engine,
        rule_id=hit.rule.rule_id,
        rule_description=hit.rule.description_zh,
        cwe_ids=list(hit.rule.cwe_ids),
        root_cause=root_cause,
        fix_suggestion=hit.rule.fix_suggestion,
        evidence_level=evidence_level,
        verification_status=verification_status,
        verification_summary=verification_summary,
        tags=list(hit.rule.tags),
    )


def _classify_evidence(hit: RuleHit) -> tuple[str, str, str]:
    """Classify evidence level without claiming absolute certainty."""
    if hit.rule.rule_id in _STATIC_CONFIRMED_RULE_IDS:
        return (
            "static-confirmed",
            "static-confirmed",
            "本地规则提供了足够直接的静态证据；尚未执行临时复现测试。",
        )
    if hit.rule.confidence == Confidence.HIGH:
        return (
            "likely",
            "unverified",
            "本地高置信规则命中，建议结合上下文或测试进一步确认。",
        )
    if hit.rule.confidence == Confidence.MEDIUM:
        return (
            "suspected",
            "unverified",
            "启发式规则命中，属于疑似风险，建议人工复核或后续测试验证。",
        )
    return (
        "needs-review",
        "unverified",
        "低置信提示，主要用于提醒人工检查。",
    )


def _build_root_cause(hit: RuleHit, detail: str) -> str:

    """Compose a human-readable root_cause that includes:

    1. Chinese explanation (description_zh)
    2. English rule title + detail message
    3. CWE / OWASP identifiers with web links
    4. Optional reference URL
    """
    rule = hit.rule
    parts: list[str] = []

    # ① 中文解释
    if rule.description_zh:
        parts.append(rule.description_zh)

    # ② 英文专业描述（rule title + hit-specific detail）
    eng_parts: list[str] = [f"[{rule.rule_id}] {rule.title}"]
    if detail and detail != f"Matched {rule.rule_id} at lines {hit.line_start}-{hit.line_end}":
        eng_parts.append(detail)
    parts.append(" — ".join(eng_parts))

    # ③ CWE / OWASP 标识 + 链接
    refs: list[str] = []
    for cwe in rule.cwe_ids:
        cwe_num = cwe.replace("CWE-", "")
        refs.append(f"{cwe} (https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
    for owasp_id in rule.owasp:
        refs.append(f"OWASP {owasp_id} (https://owasp.org/Top10/)")
    if refs:
        parts.append("参考: " + "; ".join(refs))

    # ④ 额外参考链接
    if rule.reference_url:
        parts.append(f"详细说明: {rule.reference_url}")

    return "\n".join(parts)


# ── False-positive suppression helpers ───────────────────────────────────

# Values that are placeholders or environment references, not real secrets.
PLACEHOLDER_SECRET_VALUES = frozenset({
    "changeme", "password", "secret", "your_secret_here",
    "your_api_key_here", "xxx", "todo", "fixme", "placeholder",
    "your_password_here", "replace_me", "none", "null", "undefined",
})


def is_placeholder_secret(value: str) -> bool:
    """True when a hardcoded-looking secret value is actually a placeholder,
    an environment-variable reference (``$VAR`` / ``${VAR}`` / ``%VAR%``),
    or an empty/whitespace string."""
    stripped = value.strip().strip("\"'`").strip()
    if not stripped:
        return True
    if stripped.lower() in PLACEHOLDER_SECRET_VALUES:
        return True
    return stripped.startswith(("${", "$", "%"))


# Common weak/default words that are almost never real credentials.
_LOW_ENTROPY_SECRET_VALUES = frozenset({
    "admin", "administrator", "root", "localhost", "guest", "user", "test",
    "demo", "default", "qwerty", "letmein", "welcome", "12345", "123456",
    "123456789", "111111", "000000", "123321", "654321",
})


def is_low_entropy_secret(value: str) -> bool:
    """True when a hardcoded-looking value is low-entropy — a common weak/default
    word, or a short single-character-class string (all digits / all lowercase),
    so it is almost certainly not a real credential."""
    stripped = value.strip().strip("\"'`").strip().lower()
    if not stripped:
        return False
    if stripped in _LOW_ENTROPY_SECRET_VALUES:
        return True
    return len(stripped) < 8 and (stripped.isdigit() or (stripped.isalpha() and stripped.islower()))


def is_non_secret_value(value: str) -> bool:
    """True when a hardcoded-looking value is NOT a real credential — either a
    placeholder/env-reference or a low-entropy string. Unified FP filter for
    HARDCODED-PASSWORD across all language branches."""
    return is_placeholder_secret(value) or is_low_entropy_secret(value)


_TEST_DIR_NAMES = frozenset({"test", "tests", "spec", "specs", "__tests__"})
_TEST_FILE_PREFIXES = ("test_", "spec_")
_TEST_FILE_SUFFIXES = (
    "_test.go", "_test.py", "_test.java", "_test.js", "_test.ts",
    ".spec.js", ".spec.ts", ".test.js", ".test.ts",
)


def is_test_file_path(rel_path: str) -> bool:
    """Heuristic: detect a test file from its path (directory or filename)."""
    lower = rel_path.lower().replace("\\", "/")
    parts = lower.split("/")
    if any(p in _TEST_DIR_NAMES for p in parts[:-1]):
        return True
    filename = parts[-1] if parts else ""
    if filename.startswith(_TEST_FILE_PREFIXES):
        return True
    return filename.endswith(_TEST_FILE_SUFFIXES)


# Matches an inline suppression marker, e.g.:
#   # codeguardian: ignore RULE-ID[, OTHER-ID]
#   # noqa: RULE-ID        (also bare `# noqa` / `# codeguardian: ignore`)
#   // codeguardian: ignore RULE-ID   (C-style comments)
_INLINE_IGNORE_RE = re.compile(
    r"(?:#|//)\s*(?:codeguardian:\s*ignore|noqa)\b:?\s*(?P<ids>[A-Z0-9_,\s\-]*)",
    re.IGNORECASE,
)


def is_suppressed_by_inline_comment(rule_id: str, lines: list[str], line_no: int) -> bool:
    """True when the hit line or the line directly above carries an inline
    suppression comment covering this rule.

    A marker with no rule ids (bare ``# noqa`` / ``# codeguardian: ignore``)
    suppresses every rule on that line.
    """
    for ln in (line_no, line_no - 1):
        if 1 <= ln <= len(lines):
            match = _INLINE_IGNORE_RE.search(lines[ln - 1])
            if match is None:
                continue
            ids = {tok.strip().upper() for tok in re.split(r"[,\s]+", match.group("ids")) if tok.strip()}
            if not ids or rule_id.upper() in ids:
                return True
    return False
