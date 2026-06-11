"""AIRouter — routes tasks to appropriate AI providers and models.

Model routing strategy (from COMBINED.md §4.2):
  - Lightweight (summary_model) → summarize_findings, explain_finding
  - Default    (model)          → suggest_fix
  - Heavy      (heavy_model)    → review_release

When a specialized model is not configured, it falls back to the default model.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from codeguardian.ai.models import GenerateResult, TokenUsage
from codeguardian.ai.providers.dummy import DummyAIProvider

if TYPE_CHECKING:
    from codeguardian.ai.base import AIProvider
    from codeguardian.config.schema import AIConfig

logger = logging.getLogger(__name__)


class AIRouter:
    """Routes analysis tasks to the configured AI provider(s).

    Holds up to three provider instances — *lightweight*, *default*, and *heavy* —
    and dispatches each task type to the appropriate one.  When the caller only
    supplies a single ``provider`` (e.g. in tests), all three slots point to
    the same instance so existing behaviour is preserved.
    """

    def __init__(
        self,
        provider: AIProvider | None = None,
        *,
        lightweight_provider: AIProvider | None = None,
        heavy_provider: AIProvider | None = None,
    ) -> None:
        default = provider or DummyAIProvider()
        self.provider = default  # kept for backward-compat / tests
        self._lightweight = lightweight_provider or default
        self._default = default
        self._heavy = heavy_provider or default
        self._total_usage = TokenUsage()

    @property
    def total_usage(self) -> TokenUsage:
        """Total token usage accumulated across all router calls."""
        return self._total_usage

    @classmethod
    def from_config(cls, config: AIConfig) -> AIRouter:
        """Create an AIRouter with providers determined by configuration.

        Resolves ``config.model``, ``config.summary_model``, and
        ``config.heavy_model`` into up to three distinct provider instances.
        When a specialized model is empty or identical to ``config.model``,
        the default provider is reused (no extra instantiation).
        """
        from codeguardian.ai.factory import create_provider, create_provider_for_model

        default_provider = create_provider(config)

        # Build lightweight provider (for summaries / explanations)
        summary_model = config.summary_model
        if summary_model and summary_model != config.model:
            lightweight = create_provider_for_model(config, summary_model)
            logger.info(
                "AI Router: lightweight tasks → model '%s'", summary_model,
            )
        else:
            lightweight = default_provider

        # Build heavy provider (for release reviews)
        heavy_model = config.heavy_model
        if heavy_model and heavy_model != config.model:
            heavy = create_provider_for_model(config, heavy_model)
            logger.info(
                "AI Router: heavy tasks → model '%s'", heavy_model,
            )
        else:
            heavy = default_provider

        if lightweight is not default_provider or heavy is not default_provider:
            logger.info(
                "AI Router: default tasks → model '%s'", config.model,
            )

        return cls(
            provider=default_provider,
            lightweight_provider=lightweight,
            heavy_provider=heavy,
        )

    # ── Task methods ─────────────────────────────────────────────────

    async def explain_finding(self, finding_id: str, context: dict | None = None) -> str:
        """Generate an AI explanation for a specific finding.

        Routes to **lightweight** provider (summary_model).

        Parameters
        ----------
        finding_id : str
            The finding identifier (e.g. "SEC-001").
        context : dict | None
            Optional dict with keys: title, category, severity, confidence,
            location, rule_id, root_cause, impact, fix_suggestion,
            test_suggestion, evidence_snippets, risk_priority.
        """
        prompt = self._build_explain_prompt(finding_id, context)
        return await self._generate_tracked(prompt, self._lightweight)

    async def summarize_findings(self, findings_summary: dict) -> str:
        """Generate an executive summary of all findings.

        Routes to **lightweight** provider (summary_model).
        """
        prompt = self._build_summary_prompt(findings_summary)
        return await self._generate_tracked(prompt, self._lightweight)

    async def suggest_fix(self, finding_data: dict) -> str:
        """Generate fix suggestion for a specific finding.

        Routes to **default** provider (model).
        """
        prompt = self._build_fix_prompt(finding_data)
        return await self._generate_tracked(prompt, self._default)

    async def review_release(self, project_data: dict) -> str:
        """Generate release readiness recommendation.

        Routes to **heavy** provider (heavy_model).
        """
        prompt = self._build_release_prompt(project_data)
        return await self._generate_tracked(prompt, self._heavy)

    # ── Internal helpers ─────────────────────────────────────────────

    async def _generate_tracked(self, prompt: str, provider: AIProvider | None = None) -> str:
        """Generate response via the given provider and accumulate token usage."""
        target = provider or self._default
        result = await target.generate_with_usage(prompt)

        # Use real usage if available; otherwise estimate from character counts
        prompt_tokens = result.usage.prompt_tokens
        completion_tokens = result.usage.completion_tokens
        total_tokens = result.usage.total_tokens

        if total_tokens == 0 and (prompt or result.text):
            # Fallback estimate: ~1 token per 4 characters
            prompt_tokens = len(prompt) // 4
            completion_tokens = len(result.text) // 4
            total_tokens = prompt_tokens + completion_tokens

        self._total_usage.prompt_tokens += prompt_tokens
        self._total_usage.completion_tokens += completion_tokens
        self._total_usage.total_tokens += total_tokens
        return result.text

    @staticmethod
    def _format_payload(payload: object) -> str:
        """Serialize payload as compact JSON for stable LLM consumption."""
        try:
            return json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        except (TypeError, ValueError):
            return str(payload)

    @staticmethod
    def _build_explain_prompt(finding_id: str, context: dict | None = None) -> str:
        if context:
            details = {
                "finding_id": finding_id,
                "title": context.get("title"),
                "category": context.get("category"),
                "severity": context.get("severity"),
                "confidence": context.get("confidence"),
                "priority": context.get("risk_priority"),
                "location": context.get("location"),
                "rule_id": context.get("rule_id"),
                "root_cause": context.get("root_cause"),
                "impact": context.get("impact"),
                "fix_suggestion": context.get("fix_suggestion"),
                "test_suggestion": context.get("test_suggestion"),
                "evidence": (context.get("evidence_snippets") or "")[:800] or None,
            }
            details = {k: v for k, v in details.items() if v not in (None, "", [])}
            payload = AIRouter._format_payload(details)
            return (
                "你是资深软件工程师，正在向同事解释一个代码质量问题。\n"
                "下面是结构化的 finding 数据（JSON）：\n\n"
                f"{payload}\n\n"
                "请用中文回答，覆盖 4 点：\n"
                "1. What is the problem？具体说清楚根因。\n"
                "2. 不修会有什么真实后果（生产/安全/性能/可维护性）。\n"
                "3. 修复步骤，越具体越好（伪代码或文字描述均可）。\n"
                "4. 应补哪些测试以防回归。\n\n"
                "约束：直接给结论，不要寒暄；总长 6-10 句；用 markdown 编号列表。"
            )
        return (
            "你是资深软件工程师。\n"
            f"请解释 finding {finding_id}：\n"
            "1. What is the problem？\n"
            "2. 为什么危险？\n"
            "3. 如何修复？\n"
            "4. 应补什么测试？\n"
            "用中文回答，markdown 编号列表，6-10 句。"
        )

    @staticmethod
    def _build_summary_prompt(findings_summary: dict) -> str:
        payload = AIRouter._format_payload(findings_summary)
        return (
            "你是 CodeGuardian Issue Summarizer，为研发负责人和 QA 写一份 executive summary。\n"
            "下面是本次扫描的结构化结果（JSON）：\n\n"
            f"{payload}\n\n"
            "请用中文输出 4-6 句话，覆盖：\n"
            "- 整体质量状态（结合 overall_score 和 health_status）；\n"
            "- 最关键的发布风险（结合 severity_counts 与 top_findings，举具体例子，不要泛泛）；\n"
            "- 风险集中的模块或文件；\n"
            "- 下一步最该验证或修复的事项。\n\n"
            "约束：纯文本，不用 markdown 标题；不要复述输入；避免空话套话。"
        )

    @staticmethod
    def _build_release_prompt(project_data: dict[str, object]) -> str:
        payload = AIRouter._format_payload(project_data)
        return (
            "你是 CodeGuardian Release Gate Reviewer，给出本次发布的放行建议。\n"
            "下面是本次审计的结构化数据（JSON）：\n\n"
            f"{payload}\n\n"
            "请用中文回答，必须先在第一句明确给出结论，三选一：\n"
            "- blocked（阻塞，不能发布）\n"
            "- conditional（有条件放行，需先满足后续动作）\n"
            "- recommended（建议放行）\n\n"
            "再用 3-5 句解释理由，覆盖：blocking_items、residual_risks、变更覆盖度、"
            "最重要的后续验证。\n\n"
            "约束：纯文本，不用 markdown 标题；结论与 verdict 不一致时必须说明依据。"
        )

    @staticmethod
    def _build_fix_prompt(finding_data: dict[str, object]) -> str:
        payload = AIRouter._format_payload(finding_data)
        return (
            "你是资深软件工程师，正在为一个具体的代码缺陷生成修复方案。\n"
            "下面是 finding 的结构化数据（JSON）：\n\n"
            f"{payload}\n\n"
            "请用中文输出，包含两段：\n"
            "1. 修复思路：1-3 句说明根因与修复策略。\n"
            "2. 修复代码：用 markdown 代码块给出最小可落地的 diff 或片段，"
            "不写未修改的上下文，不编造未给出的 API。\n\n"
            "约束：若信息不足以给出代码，明确指出缺什么并给出排查步骤；不要寒暄。"
        )
