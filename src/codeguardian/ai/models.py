"""Shared AI data models — response types and token usage tracking."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class TokenUsage:
    """Token usage from a single API call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(slots=True)
class GenerateResult:
    """Result from an AI provider generate() call.

    Carries both the text response and token usage info.
    """

    text: str = ""
    usage: TokenUsage = field(default_factory=TokenUsage)


@dataclass(slots=True)
class TokenUsageStats:
    """Aggregated token usage statistics for a scan.

    Tracks per-phase breakdown (deep_review, summarize, release_review)
    and overall totals.
    """

    # Deep Review phase
    deep_review_prompt_tokens: int = 0
    deep_review_completion_tokens: int = 0
    deep_review_total_tokens: int = 0
    deep_review_api_calls: int = 0

    # AI Enhancement phase (summarize + release review)
    enhancement_prompt_tokens: int = 0
    enhancement_completion_tokens: int = 0
    enhancement_total_tokens: int = 0
    enhancement_api_calls: int = 0

    # AI Verifier phase (FP second-pass judgement over engine findings)
    ai_verify_prompt_tokens: int = 0
    ai_verify_completion_tokens: int = 0
    ai_verify_total_tokens: int = 0
    ai_verify_api_calls: int = 0
    ai_verify_pass1_count: int = 0
    ai_verify_pass2_count: int = 0
    ai_verify_fp_count: int = 0
    ai_verify_confirmed_count: int = 0
    ai_verify_uncertain_count: int = 0
    ai_verify_cache_hits: int = 0

    # Budget info
    budget_max_tokens: int = 0
    budget_spent_tokens: int = 0

    # Model names (for report display)
    deep_review_model: str = ""
    enhancement_summary_model: str = ""
    enhancement_release_model: str = ""

    @property
    def total_prompt_tokens(self) -> int:
        return (
            self.deep_review_prompt_tokens
            + self.enhancement_prompt_tokens
            + self.ai_verify_prompt_tokens
        )

    @property
    def total_completion_tokens(self) -> int:
        return (
            self.deep_review_completion_tokens
            + self.enhancement_completion_tokens
            + self.ai_verify_completion_tokens
        )

    @property
    def total_tokens(self) -> int:
        return (
            self.deep_review_total_tokens
            + self.enhancement_total_tokens
            + self.ai_verify_total_tokens
        )

    @property
    def total_api_calls(self) -> int:
        return (
            self.deep_review_api_calls
            + self.enhancement_api_calls
            + self.ai_verify_api_calls
        )

    def add_deep_review_usage(self, usage: TokenUsage) -> None:
        """Record token usage from a deep review API call."""
        self.deep_review_prompt_tokens += usage.prompt_tokens
        self.deep_review_completion_tokens += usage.completion_tokens
        self.deep_review_total_tokens += usage.total_tokens
        self.deep_review_api_calls += 1

    def add_enhancement_usage(self, usage: TokenUsage) -> None:
        """Record token usage from an AI enhancement API call."""
        self.enhancement_prompt_tokens += usage.prompt_tokens
        self.enhancement_completion_tokens += usage.completion_tokens
        self.enhancement_total_tokens += usage.total_tokens
        self.enhancement_api_calls += 1

    def to_dict(self) -> dict[str, int]:
        """Serialize for JSON report output."""
        result: dict = {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "total_api_calls": self.total_api_calls,
            "deep_review": {
                "prompt_tokens": self.deep_review_prompt_tokens,
                "completion_tokens": self.deep_review_completion_tokens,
                "total_tokens": self.deep_review_total_tokens,
                "api_calls": self.deep_review_api_calls,
            },
            "enhancement": {
                "prompt_tokens": self.enhancement_prompt_tokens,
                "completion_tokens": self.enhancement_completion_tokens,
                "total_tokens": self.enhancement_total_tokens,
                "api_calls": self.enhancement_api_calls,
            },
            "ai_verify": {
                "prompt_tokens": self.ai_verify_prompt_tokens,
                "completion_tokens": self.ai_verify_completion_tokens,
                "total_tokens": self.ai_verify_total_tokens,
                "api_calls": self.ai_verify_api_calls,
                "pass1_count": self.ai_verify_pass1_count,
                "pass2_count": self.ai_verify_pass2_count,
                "fp_count": self.ai_verify_fp_count,
                "confirmed_count": self.ai_verify_confirmed_count,
                "uncertain_count": self.ai_verify_uncertain_count,
                "cache_hits": self.ai_verify_cache_hits,
            },
            "budget": {
                "max_tokens": self.budget_max_tokens,
                "spent_tokens": self.budget_spent_tokens,
            },
        }
        # Include model names when available
        models: dict[str, str] = {}
        if self.deep_review_model:
            models["deep_review"] = self.deep_review_model
        if self.enhancement_summary_model:
            models["summary"] = self.enhancement_summary_model
        if self.enhancement_release_model:
            models["release_review"] = self.enhancement_release_model
        if models:
            result["models"] = models
        return result
