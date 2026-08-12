"""Configuration schema definitions using Pydantic."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from codeguardian.models.enums import Severity


class ScanConfig(BaseModel):
    """Scan behavior configuration."""

    # Single AI switch (SSOT): ai_off disables AI entirely; standard/ultra pick depth.
    review_mode: str = "standard"  # ai_off / standard / ultra
    languages: list[str] | None = None  # null = auto-detect
    dimensions: list[str] | None = None  # null = all
    exclude_paths: list[str] = Field(default_factory=list)  # user-defined path exclusions


class ReportConfig(BaseModel):
    """Report output configuration."""

    formats: list[str] = Field(default_factory=lambda: ["terminal"])
    output_dir: str = "reports"
    html_template: str | None = None


class AIConfig(BaseModel):
    """AI provider configuration.

    Model routing strategy:
      - ``model``: default model for all tasks (fallback)
      - ``summary_model``: lightweight model for summarize & explain (cost-efficient)
      - ``heavy_model``: flagship model for release review & fix suggestions (highest quality)

    When a specialized model field is empty, it falls back to ``model``.
    """

    enabled: bool = False
    provider: str = "openai"  # openai / dummy
    model: str = "gpt-4o"
    summary_model: str = ""  # lightweight model for summaries (empty = reuse model)
    heavy_model: str = ""  # flagship model for release review (empty = reuse model)
    api_key_env: str = "CODEGUARDIAN_API_KEY"
    base_url: str | None = None  # Custom OpenAI-compatible endpoint; None = official OpenAI
    max_tokens: int = 2000
    temperature: float = 0.3
    timeout: float = 120.0  # HTTP request timeout in seconds
    # Client-side rate limit (TPS). Some API providers enforce per-account
    # request-per-second cap; if it's exceeded, every excess request gets a
    # 429 even when in-flight concurrency is 1. Set this to slightly below
    # the documented TPS quota to avoid 429 storms. 0 = no client throttle.
    requests_per_second: float = 0.0

    @property
    def effective_timeout(self) -> httpx.Timeout:
        """Build httpx Timeout from config."""
        import httpx
        return httpx.Timeout(self.timeout, connect=30.0)


class DeepReviewConfig(BaseModel):
    """AI deep review configuration.

    ``review_mode`` is derived from ``ScanConfig.review_mode`` (SSOT) and is not
    meant to be set independently.
    """

    review_mode: str = "standard"  # standard | ultra (derived from scan.review_mode)
    max_tokens_per_scan: int = 500_000
    max_concurrent: int = 5
    confidence_threshold: int = 6
    review_model: str = ""  # empty = reuse ai.model
    critic_model: str = ""  # ultra mode: model for critic pass (empty = reuse review_model)
    caller_expansion_threshold: int = 20


class RiskConfig(BaseModel):
    """Risk scoring configuration."""

    default_threshold: float = 60.0
    weights: dict[str, float] | None = None


class GitConfig(BaseModel):
    """Git analysis configuration."""

    since: str | None = None  # e.g., HEAD~5, or date string
    max_commits: int = 500


class TestConfig(BaseModel):
    """Test analysis configuration."""

    coverage_files: list[str] = Field(default_factory=list)
    mutation_enabled: bool = False


class GateConfig(BaseModel):
    """Quality gate configuration."""

    config_path: str = "gate.yaml"


class RulesConfig(BaseModel):
    """Rule selection, suppression, and baseline configuration."""

    enabled: list[str] | None = None
    disabled: list[str] = Field(default_factory=list)
    include_tags: list[str] | None = None
    exclude_tags: list[str] = Field(default_factory=list)
    min_severity: Severity | None = None
    baseline_path: str | None = None


class AIVerifyConfig(BaseModel):
    """AI verifier configuration — second-pass true/false judgment over engine findings.

    Covers all engine-produced findings (no category filter). False positives
    are kept but downgraded to ``info`` and tagged ``ai-fp``; the CLI flag
    ``--drop-false-positives`` opts into dropping them entirely.
    """

    enabled: bool = True
    max_tokens_per_scan: int = 200_000
    max_concurrent: int = 5
    verify_model: str = ""  # empty = reuse ai.summary_model, then ai.model
    escalate_model: str = ""  # Pass 2 model; empty = reuse ai.heavy_model, then verify_model
    drop_false_positives: bool = True


class FreeReviewConfig(BaseModel):
    """Scout-phase AI review configuration (high-recall first pass)."""

    enabled: bool = False
    max_tokens_per_scan: int = 200_000
    max_concurrent: int = 3
    review_model: str = ""  # empty = reuse ai.model
    min_suspicion_confidence: int = 3
    max_suspicions: int = 500


class SemgrepConfig(BaseModel):
    """Semgrep engine configuration.

    Semgrep is an external SAST tool integrated as an optional engine.
    Disabled by default to avoid impact on existing users; enable when
    the ``semgrep`` CLI is installed (``pip install semgrep``).
    """

    enabled: bool = False
    config: list[str] = Field(default_factory=lambda: ["p/security-audit"])
    timeout: float = 300.0  # per-scan timeout in seconds
    max_target_bytes: int = 1_000_000  # skip files larger than this
    jobs: int = 1  # parallel workers; 1 keeps memory predictable on Windows
    severity_filter: list[str] = Field(default_factory=list)  # empty = all severities
    extra_args: list[str] = Field(default_factory=list)  # passthrough flags
    local_validate: bool = True  # apply LocalValidator FP filter to security findings


class AppConfig(BaseModel):
    """Top-level application configuration.

    Load order (higher priority overrides lower):
      CLI arguments > environment variables > codeguardian.toml > defaults
    """

    scan: ScanConfig = Field(default_factory=ScanConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    deep_review: DeepReviewConfig = Field(default_factory=DeepReviewConfig)
    ai_verify: AIVerifyConfig = Field(default_factory=AIVerifyConfig)
    free_review: FreeReviewConfig = Field(default_factory=FreeReviewConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)

    git: GitConfig = Field(default_factory=GitConfig)
    test: TestConfig = Field(default_factory=TestConfig)
    gate: GateConfig = Field(default_factory=GateConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)

    @model_validator(mode="after")
    def _post_init(self) -> "AppConfig":
        self._derive_review_mode()
        return self

    def _derive_review_mode(self) -> None:
        """SSOT: ``scan.review_mode`` drives ``ai.enabled`` and ``deep_review.review_mode``.

        - ``ai_off``   -> AI disabled entirely.
        - ``standard`` -> AI enabled, deep review single-pass.
        - ``ultra``    -> AI enabled, deep review multi-pass.
        """
        rm = (self.scan.review_mode or "standard").strip().lower()
        if rm not in ("ai_off", "standard", "ultra"):
            rm = "standard"
        self.scan.review_mode = rm
        self.ai.enabled = rm != "ai_off"
        if rm in ("standard", "ultra"):
            self.deep_review.review_mode = rm

    def apply_review_mode(self, mode: str) -> None:
        """Override review_mode at runtime (e.g. from CLI) and re-derive dependents."""
        self.scan.review_mode = (mode or "").strip().lower()
        self._derive_review_mode()
