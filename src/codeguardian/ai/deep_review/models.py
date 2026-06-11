"""Data models for the AI deep review pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CodeChunk:
    """A unit of code to be reviewed by the AI.

    Represents a file, class, or function-level fragment with metadata
    for prioritisation and context building.
    """

    file_path: str
    source_code: str
    language: str
    line_start: int
    line_end: int

    # Identifiers
    qualified_name: str = ""  # e.g. "module.ClassName.method_name"
    chunk_type: str = "file"  # file / class / function

    # Priority for budget allocation (lower = higher priority)
    priority: int = 2  # 0 = P0 (must review), 1 = P1, 2 = P2

    # Related local findings (finding IDs)
    related_finding_ids: list[str] = field(default_factory=list)

    # Pre-computed metadata
    complexity: int = 0
    loc: int = 0

    def estimate_tokens(self) -> int:
        """Rough token estimate: ~1 token per 4 characters for code."""
        # Code tokens + context overhead (~500 tokens for prompt template)
        code_tokens = len(self.source_code) // 4
        return code_tokens + 500


@dataclass(slots=True)
class ContextPack:
    """Per-chunk context package for AI review.

    Contains the target code plus surrounding context needed for
    accurate AI analysis.
    """

    target_code: str
    file_path: str
    function_name: str = ""
    line_start: int = 0
    line_end: int = 0
    language: str = ""

    # Context elements
    dependency_signatures: list[str] = field(default_factory=list)
    type_definitions: list[str] = field(default_factory=list)
    local_findings_summary: str = ""
    custom_rules: str = ""
    notes: list[str] = field(default_factory=list)

    def build_dependency_section(self) -> str:
        """Format dependency signatures for prompt injection."""
        if not self.dependency_signatures:
            return "无外部依赖签名"
        return "\n".join(self.dependency_signatures)

    def build_notes_section(self) -> str:
        """Format notes (e.g. unresolved dynamic calls) for prompt injection."""
        if not self.notes:
            return ""
        return "\n".join(self.notes)


@dataclass(slots=True)
class AIFindingRaw:
    """A single finding parsed from AI response JSON."""

    title: str
    category: str  # security / null_safety / logic / resource / error_handling
    severity: str  # critical / high / medium / low
    confidence: int  # 1-10
    line_start: int = 0
    line_end: int = 0
    description: str = ""
    evidence: str = ""
    fix_suggestion: str = ""
    self_reflection: str = ""


@dataclass(slots=True)
class ReviewResult:
    """Result from AI review of a single chunk."""

    chunk_file_path: str
    chunk_qualified_name: str = ""
    findings: list[AIFindingRaw] = field(default_factory=list)
    summary: str = ""
    verified_local_findings: list[str] = field(default_factory=list)
    status: str = "done"  # done / skipped / failed
    skip_reason: str = ""  # rate_limit_exceeded / api_unreachable / parse_error / budget_exhausted
    tokens_used: int = 0

    @classmethod
    def skipped(cls, file_path: str, reason: str) -> ReviewResult:
        """Create a skipped result."""
        return cls(
            chunk_file_path=file_path,
            status="skipped",
            skip_reason=reason,
        )
