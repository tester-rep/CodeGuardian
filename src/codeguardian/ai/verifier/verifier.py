"""AIVerifier — two-pass AI verification of engine-produced findings.

Pipeline:
  1. For each finding (all categories), check cache → return cached verdict.
  2. Pass 1: minimal context, lightweight model call.
       - "true" / "false" → final verdict
       - "uncertain" → escalate to Pass 2
  3. Pass 2: richer, severity-tiered context with the heavier model.
  4. Apply verdicts to findings:
       - true     → tag ai-confirmed, evidence_level=static-confirmed
       - false    → severity=info, blocks_release=False, tag ai-fp
       - uncertain → keep as-is, tag ai-uncertain
       - skipped (budget/error) → keep as-is, tag ai-skipped-{reason}

Budget: shares no token pool with deep_review — this verifier has its own
``max_tokens_per_scan`` cap. Once exhausted, remaining findings are tagged
``ai-skipped-budget`` and left untouched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from codeguardian.ai.models import TokenUsage
from codeguardian.ai.verifier.cache import VerifyCache, VerifyVerdict, compute_cache_key
from codeguardian.ai.verifier.evidence_collectors import is_enhanced_rule
from codeguardian.ai.verifier.prompts import (
    SYSTEM_MESSAGE,
    build_pass1_context,
    build_pass1_prompt,
    build_pass2_context,
    build_pass2_prompt,
)
from codeguardian.models.enums import Severity
from codeguardian.models.finding import Finding

if TYPE_CHECKING:
    from codeguardian.ai.base import AIProvider
    from codeguardian.config.schema import AIConfig, AIVerifyConfig

logger = logging.getLogger(__name__)

MAX_RETRIES = 4
_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)

# Severities that force Pass 2 even when Pass 1 was decisive.
# Rationale: high/critical findings are too consequential to confirm based
# on ±10 lines of context alone. The user's rule: "怀疑有问题的，必须提供
# 详细的证据和源代码，给到 AI 做二次检查。" High-severity hits must always
# get the richer Pass 2 context (function body + imports + caller/callee).
_FORCE_PASS2_SEVERITIES: frozenset[Severity] = frozenset({Severity.CRITICAL, Severity.HIGH})


@dataclass(slots=True)
class VerifyOutcome:
    """Aggregate stats returned to the orchestrator after a verify run."""

    findings: list[Finding]
    usage: TokenUsage = field(default_factory=TokenUsage)
    pass1_count: int = 0
    pass2_count: int = 0
    pass1_decisive: int = 0
    cache_hits: int = 0
    fp_count: int = 0
    confirmed_count: int = 0
    uncertain_count: int = 0
    skipped_count: int = 0
    budget_max: int = 0
    budget_spent: int = 0


class AIVerifier:
    """Two-pass AI verifier for engine findings."""

    def __init__(
        self,
        *,
        verify_provider: AIProvider,
        escalate_provider: AIProvider,
        cache: VerifyCache,
        project_root: Path,
        max_tokens_per_scan: int,
        max_concurrent: int,
        verify_model_name: str,
        escalate_model_name: str,
        pci: object | None = None,
    ) -> None:
        self._verify_provider = verify_provider
        self._escalate_provider = escalate_provider
        self._cache = cache
        self._project_root = project_root
        self._budget_max = max_tokens_per_scan
        self._budget_spent = 0
        self._budget_exhausted = False
        self._auth_failed = False
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._verify_model_name = verify_model_name
        self._escalate_model_name = escalate_model_name
        self._pci = pci
        self._usage = TokenUsage()

    # ── Public entry ─────────────────────────────────────────────────

    async def verify(self, findings: list[Finding]) -> VerifyOutcome:
        """Verify each finding; return new (replacement) finding list + stats."""
        if not findings:
            return VerifyOutcome(findings=[], budget_max=self._budget_max)

        outcome = VerifyOutcome(findings=[None] * len(findings), budget_max=self._budget_max)  # type: ignore[list-item]
        tasks = [
            self._verify_one(idx, finding, outcome)
            for idx, finding in enumerate(findings)
        ]
        await asyncio.gather(*tasks)
        outcome.usage = self._usage
        outcome.budget_spent = self._budget_spent
        # Persist cache once at the end.
        self._cache.save()
        return outcome

    # ── Per-finding pipeline ────────────────────────────────────────

    async def _verify_one(self, idx: int, finding: Finding, outcome: VerifyOutcome) -> None:
        async with self._semaphore:
            # Cache lookup uses the verify-pass model (Pass 1) since that's
            # what the cache key represents; Pass 2 verdicts overwrite the
            # same key when stored.
            ctx1 = build_pass1_context(finding, self._project_root)
            cache_key = compute_cache_key(
                finding,
                code_lines=ctx1.get("code_lines", []),  # type: ignore[arg-type]
                model=self._verify_model_name,
            )

            cached = self._cache.lookup(cache_key)
            if cached is not None:
                outcome.cache_hits += 1
                outcome.findings[idx] = self._apply_verdict(finding, cached)
                self._tally(outcome, cached)
                return

            if self._budget_exhausted or self._auth_failed:
                outcome.skipped_count += 1
                outcome.findings[idx] = self._mark_skipped(finding, "budget" if self._budget_exhausted else "auth")
                return

            # Pass 1
            outcome.pass1_count += 1
            verdict = await self._call_pass(
                provider=self._verify_provider,
                prompt=build_pass1_prompt(finding, ctx1),
                pass_used=1,
                finding_id=finding.id,
            )
            if verdict is None:
                outcome.skipped_count += 1
                outcome.findings[idx] = self._mark_skipped(
                    finding, "budget" if self._budget_exhausted else "error",
                )
                return

            # Severity gate: critical/high MUST go through Pass 2 regardless
            # of what Pass 1 said. The user explicitly rejected the previous
            # behavior where Pass 1 could finalize a "true" verdict on a
            # high-severity finding using only ±10 lines of context.
            #
            # Rule gate: certain high-FP rule families (static mutable shared
            # state, exception swallowing, resource lifecycle) carry their
            # own Pass 2 evidence collectors and must always escalate so the
            # AI gets the richer evidence before any verdict is finalized.
            # User's hard rule: "宁愿不要检查出问题，也不要检查一堆假问题"。
            force_pass2 = (
                finding.severity in _FORCE_PASS2_SEVERITIES
                or is_enhanced_rule(finding.rule_id)
            )
            pass1_decisive = verdict.status in {"ai-verified-true", "ai-verified-fp"}

            if pass1_decisive and not force_pass2:
                outcome.pass1_decisive += 1
                self._cache.store(cache_key, verdict)
                outcome.findings[idx] = self._apply_verdict(finding, verdict)
                self._tally(outcome, verdict)
                return

            # Either Pass 1 was uncertain, OR severity forces escalation.
            outcome.pass2_count += 1
            ctx2 = build_pass2_context(finding, self._project_root, pci=self._pci)
            verdict2 = await self._call_pass(
                provider=self._escalate_provider,
                prompt=build_pass2_prompt(finding, ctx2),
                pass_used=2,
                finding_id=finding.id,
            )
            if verdict2 is None:
                # Pass 2 itself failed/budget. Two cases:
                #   - Pass 1 was decisive but we forced Pass 2 → fall back to Pass 1.
                #   - Pass 1 was uncertain → keep uncertain.
                self._cache.store(cache_key, verdict)  # store rejects uncertain internally
                outcome.findings[idx] = self._apply_verdict(finding, verdict)
                self._tally(outcome, verdict)
                return

            self._cache.store(cache_key, verdict2)
            outcome.findings[idx] = self._apply_verdict(finding, verdict2)
            self._tally(outcome, verdict2)

    # ── AI call w/ retry & budget ───────────────────────────────────

    async def _call_pass(
        self,
        *,
        provider: AIProvider,
        prompt: str,
        pass_used: int,
        finding_id: str,
        attempt: int = 0,
    ) -> VerifyVerdict | None:
        """Invoke provider, parse JSON, return verdict or None on failure/budget."""
        if self._budget_exhausted:
            return None

        try:
            result = await provider.generate_with_usage(prompt, system_message=SYSTEM_MESSAGE)
        except Exception as exc:  # noqa: BLE001 — branch on message
            return await self._handle_call_error(
                exc, provider=provider, prompt=prompt,
                pass_used=pass_used, finding_id=finding_id, attempt=attempt,
            )

        # Budget accounting (mirror reviewer.py logic).
        usage = result.usage
        actual = usage.total_tokens
        estimated = (len(prompt) + len(result.text)) // 4
        if actual == 0:
            actual = estimated
        self._budget_spent += actual
        if self._budget_max > 0 and self._budget_spent >= self._budget_max:
            self._budget_exhausted = True

        if usage.total_tokens > 0:
            self._usage.prompt_tokens += usage.prompt_tokens
            self._usage.completion_tokens += usage.completion_tokens
            self._usage.total_tokens += usage.total_tokens
        else:
            est_p = len(prompt) // 4
            self._usage.prompt_tokens += est_p
            self._usage.completion_tokens += max(estimated - est_p, 0)
            self._usage.total_tokens += estimated

        verdict = self._parse_response(result.text, pass_used=pass_used)
        if verdict is None:
            logger.warning("Verifier pass %d: failed to parse response for %s", pass_used, finding_id)
            return None
        verdict.tokens_used = actual
        return verdict

    async def _handle_call_error(
        self,
        exc: Exception,
        *,
        provider: AIProvider,
        prompt: str,
        pass_used: int,
        finding_id: str,
        attempt: int,
    ) -> VerifyVerdict | None:
        msg = str(exc).lower()
        if any(tok in msg for tok in ("401", "403", "forbidden", "unauthorized")):
            if not self._auth_failed:
                self._auth_failed = True
                self._budget_exhausted = True
                logger.error(
                    "AI verifier auth failure (401/403). Skipping all remaining findings.",
                )
            return None

        if "429" in msg or "rate" in msg:
            if attempt >= MAX_RETRIES:
                logger.warning("Verifier rate-limited beyond %d retries for %s", MAX_RETRIES, finding_id)
                return None
            await asyncio.sleep(min(2 ** attempt, 30))
            return await self._call_pass(
                provider=provider, prompt=prompt,
                pass_used=pass_used, finding_id=finding_id, attempt=attempt + 1,
            )

        if "timeout" in msg or "connect" in msg:
            if attempt >= MAX_RETRIES:
                logger.warning("Verifier API unreachable for %s", finding_id)
                return None
            await asyncio.sleep(2 ** attempt)
            return await self._call_pass(
                provider=provider, prompt=prompt,
                pass_used=pass_used, finding_id=finding_id, attempt=attempt + 1,
            )

        logger.exception("Verifier unexpected error for %s", finding_id)
        return None

    # ── Response parsing ────────────────────────────────────────────

    @staticmethod
    def _parse_response(raw: str, *, pass_used: int) -> VerifyVerdict | None:
        """Extract {verdict, reason} JSON, normalize into VerifyVerdict."""
        json_str = AIVerifier._extract_json(raw)
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None

        raw_verdict = str(data.get("verdict", "")).strip().lower()
        reason = str(data.get("reason", "")).strip()[:240]

        if raw_verdict in {"true", "real", "tp", "yes"}:
            status = "ai-verified-true"
        elif raw_verdict in {"false", "fp", "no", "false_positive", "false-positive"}:
            status = "ai-verified-fp"
        elif raw_verdict in {"uncertain", "unknown", "unsure"}:
            status = "ai-uncertain"
        else:
            return None

        return VerifyVerdict(status=status, summary=reason, pass_used=pass_used)

    @staticmethod
    def _extract_json(raw: str) -> str:
        m = _JSON_BLOCK_RE.search(raw)
        if m:
            return m.group(1).strip()
        s = raw.strip()
        if s.startswith("{"):
            return s
        a, b = s.find("{"), s.rfind("}")
        if a != -1 and b > a:
            return s[a : b + 1]
        return s

    # ── Verdict application ────────────────────────────────────────

    @staticmethod
    def _apply_verdict(finding: Finding, verdict: VerifyVerdict) -> Finding:
        """Return a new Finding with verdict-driven mutations.

        - true     : tag ai-confirmed, evidence_level=static-confirmed
        - false    : severity=INFO, blocks_release=False, evidence_level=needs-review,
                     tag ai-fp (kept; never silently dropped here — callers may filter)
        - uncertain: tag ai-uncertain (severity untouched)
        """
        existing_summary = finding.verification_summary or ""
        annotated_summary = (
            f"{existing_summary} | AI-Verifier(pass{verdict.pass_used}): {verdict.summary}"
        ).strip(" |")

        if verdict.status == "ai-verified-true":
            return finding.model_copy(update={
                "verification_status": "ai-verified-true",
                "verification_summary": annotated_summary,
                "evidence_level": "static-confirmed",
                "tags": [*finding.tags, "ai-confirmed"],
            })
        if verdict.status == "ai-verified-fp":
            return finding.model_copy(update={
                "severity": Severity.INFO,
                "blocks_release": False,
                "verification_status": "ai-verified-fp",
                "verification_summary": annotated_summary,
                "evidence_level": "needs-review",
                "tags": [*finding.tags, "ai-fp"],
            })
        # uncertain
        return finding.model_copy(update={
            "verification_status": "ai-uncertain",
            "verification_summary": annotated_summary,
            "tags": [*finding.tags, "ai-uncertain"],
        })

    @staticmethod
    def _mark_skipped(finding: Finding, reason: str) -> Finding:
        """Annotate a finding that was not verified due to budget/error/auth."""
        return finding.model_copy(update={
            "verification_status": f"ai-skipped-{reason}",
            "tags": [*finding.tags, f"ai-skipped-{reason}"],
        })

    @staticmethod
    def _tally(outcome: VerifyOutcome, verdict: VerifyVerdict) -> None:
        if verdict.status == "ai-verified-true":
            outcome.confirmed_count += 1
        elif verdict.status == "ai-verified-fp":
            outcome.fp_count += 1
        elif verdict.status == "ai-uncertain":
            outcome.uncertain_count += 1


def build_verifier(
    ai_config: AIConfig,
    verify_config: AIVerifyConfig,
    project_root: Path,
    *,
    no_cache: bool = False,
    pci: object | None = None,
) -> AIVerifier | None:
    """Factory: assemble providers + cache from config; return ``None`` when disabled
    or when the AI provider degrades to dummy (no real keys).
    """
    from codeguardian.ai.factory import create_provider, create_provider_for_model
    from codeguardian.ai.providers.dummy import DummyAIProvider

    if not ai_config.enabled or not verify_config.enabled:
        return None

    default_provider = create_provider(ai_config)
    if isinstance(default_provider, DummyAIProvider):
        return None

    verify_model = verify_config.verify_model or ai_config.summary_model or ai_config.model
    escalate_model = verify_config.escalate_model or ai_config.heavy_model or ai_config.model

    if verify_model == ai_config.model:
        verify_provider = default_provider
    else:
        verify_provider = create_provider_for_model(ai_config, verify_model)

    if escalate_model == verify_model:
        escalate_provider = verify_provider
    elif escalate_model == ai_config.model:
        escalate_provider = default_provider
    else:
        escalate_provider = create_provider_for_model(ai_config, escalate_model)

    cache = VerifyCache(project_root, enabled=not no_cache)
    return AIVerifier(
        verify_provider=verify_provider,
        escalate_provider=escalate_provider,
        cache=cache,
        project_root=project_root,
        max_tokens_per_scan=verify_config.max_tokens_per_scan,
        max_concurrent=verify_config.max_concurrent,
        verify_model_name=verify_model,
        escalate_model_name=escalate_model,
        pci=pci,
    )
