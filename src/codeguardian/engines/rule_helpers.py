"""Shared helpers for rule-based engines."""

from __future__ import annotations

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
