"""Evidence model — supporting material for findings."""

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    """A piece of evidence that supports or explains a finding."""

    type: str  # "code_snippet" / "rule_match" / "runtime_sample" / "git_evidence" / "ast_node"
    content: str  # The actual content (code text, rule description, etc.)
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    source_engine: str | None = None
    language: str | None = None
    extra: dict[str, object] = Field(default_factory=dict)



class CodeSnippetEvidence(Evidence):
    """A source code snippet as evidence."""

    type: str = "code_snippet"


class RuleMatchEvidence(Evidence):
    """Evidence from a rule engine pattern match."""

    type: str = "rule_match"
    rule_id: str | None = None
    rule_category: str | None = None


class GitEvidence(Evidence):
    """Evidence from Git history analysis."""

    type: str = "git_evidence"
    commit_hash: str | None = None
    author: str | None = None
    date: str | None = None


class AIReviewEvidence(Evidence):
    """Evidence from AI deep review analysis."""

    type: str = "ai_review"
    ai_confidence: int = 5  # 1-10 scale
    self_reflection: str | None = None
    review_dimension: str | None = None  # security / null_safety / logic / resource / error_handling
