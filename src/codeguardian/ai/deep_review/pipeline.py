"""DeepReviewPipeline — orchestrates the complete AI deep review flow.

Two-phase review:
  Phase 1 — Scout (free_review): high-recall pass, outputs suspicion queue
  Phase 2 — Professional (deep_review): expert verification on suspicions

Pipeline steps:
1. Build project index (function/class signatures)
2. Chunk source files (file → class → function level)
3. Filter & prioritize chunks
4. Token budget allocation
5. [Phase 1] Scout review → build suspicion queue
6. [Phase 2] Professional review (using suspicion queue for context)
7. Merge results into primary + supplementary findings
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING


from codeguardian.ai.deep_review.budget import TokenBudgetManager
from codeguardian.ai.deep_review.cache import ReviewCache
from codeguardian.ai.deep_review.chunker import Chunker
from codeguardian.ai.deep_review.context_builder import ContextPackBuilder, load_custom_rules
from codeguardian.ai.deep_review.filter import CodeFilter, LOW_VALUE_FINDING_CATEGORIES
from codeguardian.ai.deep_review.merger import MergeOutput, ResultMerger
from codeguardian.ai.deep_review.models import CodeChunk, ContextPack, ReviewResult
from codeguardian.ai.deep_review.project_index import ProjectIndex
from codeguardian.ai.deep_review.reviewer import AIReviewer
from codeguardian.ai.deep_review.suspicion_queue import Suspicion, build_suspicions, save_suspicion_queue
from codeguardian.ai.factory import create_provider
from codeguardian.ai.models import TokenUsage
from codeguardian.ai.prompts.deep_review import (
    SCOUT_SYSTEM_MESSAGE,
    SYSTEM_MESSAGE,
    build_review_prompt,
    build_scout_prompt,
)
from codeguardian.ai.providers.dummy import DummyAIProvider
from codeguardian.parsers.base import ParsedStructure, SourceParser
from codeguardian.parsers.factory import get_parser
from codeguardian.parsers.tree_sitter_support import TreeSitterManager


if TYPE_CHECKING:
    from codeguardian.ai.base import AIProvider
    from codeguardian.config.schema import AppConfig, DeepReviewConfig

    from codeguardian.core.context import ScanContext
    from codeguardian.models.finding import Finding

logger = logging.getLogger(__name__)


class DeepReviewPipeline:
    """Complete AI deep review pipeline."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._ts_manager = TreeSitterManager()

    async def run(
        self,
        ctx: ScanContext,
        local_findings: list[Finding],
        file_language_map: dict[str, str],
    ) -> MergeOutput:
        """Execute the full deep review pipeline.

        Parameters
        ----------
        ctx : ScanContext
            Current scan context.
        local_findings : list[Finding]
            Findings from local engines (for context & dedup).
        file_language_map : dict[str, str]
            Mapping of relative file path → language.

        Returns
        -------
        MergeOutput
            Primary + supplementary findings and stats.
        """
        if not self._config.ai.enabled:
            logger.info("AI deep review skipped: AI disabled")
            return MergeOutput(
                primary=[],
                supplementary=[],
                verified_local_finding_ids=[],
                total_chunks=0,
                done_chunks=0,
                skip_counts={"ai_disabled": 1},
            )

        project_root = Path(ctx.project_root)
        dr_config = self._config.deep_review
        provider = self._get_provider()
        return await self._run_pipeline(ctx, local_findings, file_language_map, provider, project_root, dr_config)

    async def _run_pipeline(
        self,
        ctx: ScanContext,
        local_findings: list[Finding],
        file_language_map: dict[str, str],
        provider: AIProvider,
        project_root: Path,
        dr_config: DeepReviewConfig,
    ) -> MergeOutput:
        """Internal pipeline execution (extracted for try/finally cleanup)."""

        # Step 1: Build project index
        logger.info("Building project index...")
        index = self._build_index(project_root, file_language_map)
        logger.info("Project index: %d functions, %d classes", index.function_count, index.class_count)

        # Step 2: Chunk source files
        logger.info("Chunking source files...")
        code_filter = CodeFilter()
        chunker = Chunker(code_filter=code_filter, ts_manager=self._ts_manager)
        all_chunks = self._chunk_files(
            chunker, project_root, file_language_map, ctx,
        )
        logger.info("Total chunks: %d", len(all_chunks))

        if not all_chunks:
            return MergeOutput(
                primary=[],
                supplementary=[],
                verified_local_finding_ids=[],
                total_chunks=0,
                done_chunks=0,
                skip_counts={},
            )

        # Step 3: Assign priorities based on local findings and context
        self._assign_priorities(all_chunks, local_findings, ctx)

        # Step 4: Budget allocation
        budget = TokenBudgetManager(dr_config.max_tokens_per_scan)
        approved_chunks = budget.allocate(all_chunks)
        logger.info("Budget approved %d / %d chunks", len(approved_chunks), len(all_chunks))

        # Step 4.5: Cache lookup — skip AI calls for unchanged code
        cache_enabled = not getattr(ctx, "no_cache", False)
        cache = ReviewCache(project_root, enabled=cache_enabled)
        if not cache_enabled:
            logger.info("Deep review cache disabled (--no-cache)")
        chunks_to_review: list[CodeChunk] = []
        cached_results: list[ReviewResult] = []

        for chunk in approved_chunks:
            cached = cache.lookup(chunk)
            if cached is not None:
                cached_results.append(cached)
            else:
                chunks_to_review.append(chunk)

        cache_hit_count = len(cached_results)
        if cache_hit_count > 0:
            logger.info(
                "Cache hit: %d / %d chunks (saving ~%d estimated tokens)",
                cache_hit_count,
                len(approved_chunks),
                sum(c.estimate_tokens() for c in approved_chunks) - sum(c.estimate_tokens() for c in chunks_to_review),
            )

        # Step 5: Build base context builder (shared by both phases)
        local_findings_by_file = self._group_findings_by_file(local_findings)
        custom_rules = load_custom_rules(project_root)
        ctx_builder = ContextPackBuilder(
            project_index=index,
            local_findings=local_findings_by_file,
            custom_rules=custom_rules,
        )

        # ── Phase 1: Scout (free_review) — high-recall first pass ─────────────
        scout_provider = provider
        scout_model = self._config.free_review.review_model
        if scout_model and scout_model != self._config.ai.model:
            from codeguardian.ai.factory import create_provider_for_model
            scout_provider = create_provider_for_model(self._config.ai, scout_model)

        suspicions: list[Suspicion] = []
        if self._config.free_review.enabled and chunks_to_review:
            logger.info("Phase 1/2: Scout review (free_review mode)")
            scout_budget = TokenBudgetManager(self._config.free_review.max_tokens_per_scan)
            scout_reviewer = AIReviewer(
                provider=scout_provider,
                context_builder=ctx_builder,
                budget=scout_budget,
                max_concurrent=self._config.free_review.max_concurrent,
                system_message=SCOUT_SYSTEM_MESSAGE,
                prompt_builder=build_scout_prompt,
            )
            scout_results = await scout_reviewer.review_chunks(chunks_to_review)

            # Persist suspicion queue for optional second review
            fr_config = self._config.free_review
            suspicions = build_suspicions(
                scout_results,
                min_confidence=fr_config.min_suspicion_confidence,
                max_suspicions=fr_config.max_suspicions,
                source_model=self._config.ai.model,
            )
            if suspicions:
                queue_path = save_suspicion_queue(project_root, suspicions)
                logger.info(
                    "Suspicion queue saved: %d items → %s",
                    len(suspicions),
                    queue_path.relative_to(project_root),
                )

            # Use scout provider for Phase 2
            provider = scout_provider

        # Inject suspicions into context builder notes for Phase 2
        if suspicions:
            by_file: dict[str, list[str]] = {}
            for s in suspicions:
                note = (
                    f"[Scout 可疑点] {s.title} (confidence={s.confidence}, "
                    f"severity={s.severity}) L{s.line_start}: {s.description[:120]}"
                )
                by_file.setdefault(s.file_path, []).append(note)
            # Rebuild context builder with extra notes via public constructor
            # rather than mutating a private attribute.
            ctx_builder = ContextPackBuilder(
                project_index=index,
                local_findings=local_findings_by_file,
                custom_rules=custom_rules,
                extra_notes_by_file=by_file,
            )

        # ── Phase 2: Professional review ───────────────────────────────────────
        review_mode = getattr(dr_config, "review_mode", "standard")
        if review_mode == "ultra":
            from codeguardian.ai.deep_review.ultra_reviewer import UltraReviewer

            # Resolve critic provider (may use heavier model)
            critic_provider = provider
            critic_model = getattr(dr_config, "critic_model", "")
            if critic_model and critic_model != self._config.ai.model:
                from codeguardian.ai.factory import create_provider_for_model
                critic_provider = create_provider_for_model(self._config.ai, critic_model)

            reviewer = UltraReviewer(
                provider=provider,
                context_builder=ctx_builder,
                budget=budget,
                max_concurrent=dr_config.max_concurrent,
                critic_provider=critic_provider,
            )
            logger.info("Phase 2/2: Ultra review (multi-explorer + critic)")
        else:
            reviewer = AIReviewer(
                provider=provider,
                context_builder=ctx_builder,
                budget=budget,
                max_concurrent=dr_config.max_concurrent,
            )
            logger.info("Phase 2/2: Professional review (standard)")

        ai_results: list[ReviewResult] = []
        if chunks_to_review:
            ai_results = await reviewer.review_chunks(chunks_to_review)
            # Store successful results in cache
            for chunk, result in zip(chunks_to_review, ai_results):
                cache.store(chunk, result)
            cache.save()

        results = cached_results + ai_results

        # Step 7: Merge results (with local validation for FP filtering)
        merger = ResultMerger(
            confidence_threshold=dr_config.confidence_threshold,
            existing_findings=local_findings,
            project_root=project_root,
        )
        merge_output = merger.merge(results)

        # Attach reviewer token usage and budget info
        merge_output.reviewer_usage = reviewer.total_usage
        merge_output.budget_max = budget.max_tokens
        merge_output.budget_spent = budget.spent

        logger.info(merge_output.summary_line)
        logger.info(
            "Primary findings: %d, Supplementary: %d, Tokens used: %d",
            len(merge_output.primary),
            len(merge_output.supplementary),
            merge_output.total_tokens_used,
        )

        return merge_output

    def _get_provider(self) -> AIProvider:
        """Resolve the AI provider for deep review."""
        dr_config = self._config.deep_review
        ai_config = self._config.ai

        if not ai_config.enabled:
            return DummyAIProvider()

        if dr_config.review_model:
            # Use a dedicated model for deep review
            review_ai_config = ai_config.model_copy(
                update={"model": dr_config.review_model}
            )
            return create_provider(review_ai_config)

        # Reuse main AI provider
        return create_provider(ai_config)

    def _build_index(
        self,
        project_root: Path,
        file_language_map: dict[str, str],
    ) -> ProjectIndex:
        """Build project symbol index from all source files."""
        index = ProjectIndex()
        structures: dict[str, ParsedStructure] = {}

        # Cache parsers by language to avoid re-creating
        parsers: dict[str, SourceParser] = {}

        for rel_path, language in file_language_map.items():
            abs_path = project_root / rel_path
            if not abs_path.is_file():
                continue
            try:
                if language not in parsers:
                    parser = get_parser(language)
                    if parser is None:
                        logger.debug("No parser available for language: %s", language)
                        continue
                    parsers[language] = parser
                parser = parsers[language]
                structure = parser.parse_file(abs_path, project_root)
                if structure and (structure.functions or structure.classes):
                    structures[rel_path] = structure
            except Exception:
                logger.debug("Failed to parse %s for index", rel_path, exc_info=True)

        index.build_from_structures(structures)
        return index

    def _chunk_files(
        self,
        chunker: Chunker,
        project_root: Path,
        file_language_map: dict[str, str],
        ctx: ScanContext,
    ) -> list[CodeChunk]:
        """Chunk all source files."""
        all_chunks: list[CodeChunk] = []

        for rel_path, language in file_language_map.items():
            abs_path = project_root / rel_path
            if not abs_path.is_file():
                continue

            changed_lines: set[int] | None = None
            if ctx.incremental and rel_path in ctx.changed_lines:
                changed_lines = set(ctx.changed_lines[rel_path])

            chunks = chunker.chunk_file(
                abs_path, project_root, language,
                changed_lines=changed_lines,
            )
            all_chunks.extend(chunks)

        return all_chunks

    def _assign_priorities(
        self,
        chunks: list[CodeChunk],
        local_findings: list[Finding],
        ctx: ScanContext,
    ) -> None:
        """Assign review priority to each chunk based on context."""
        # Build sets for quick lookup.
        # Only HIGH-VALUE findings (security / defect / performance / etc.)
        # escalate their containing chunks to P0. Threshold-based maintainability
        # / architecture findings (complexity, oo_design, git_evolution,
        # dependency) are deterministic and don't benefit from LLM re-review,
        # so we exclude them from the escalation set to save tokens.
        finding_files: set[str] = set()
        finding_lines: dict[str, set[int]] = {}
        for f in local_findings:
            if f.category in LOW_VALUE_FINDING_CATEGORIES:
                continue
            fp = f.location.file_path
            finding_files.add(fp)
            if f.location.line_start:
                finding_lines.setdefault(fp, set()).add(f.location.line_start)

        changed_files = set(ctx.changed_files) if ctx.incremental else set()

        code_filter = CodeFilter()
        for chunk in chunks:
            has_findings = chunk.file_path in finding_files
            is_changed = chunk.file_path in changed_files

            # If already set to P0 by chunker (e.g. changed lines), keep it
            if chunk.priority == 0:
                continue

            chunk.priority = code_filter.classify_priority(
                has_local_findings=has_findings,
                is_changed=is_changed,
                complexity=chunk.complexity,
                line_count=chunk.loc,
            )

    @staticmethod
    def _group_findings_by_file(
        findings: list[Finding],
    ) -> dict[str, list[dict[str, object]]]:
        """Group local findings by file path for context injection."""
        grouped: dict[str, list[dict[str, object]]] = {}
        for f in findings:
            fp = f.location.file_path
            grouped.setdefault(fp, []).append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "line_start": f.location.line_start or 0,
                "line_end": f.location.line_end or f.location.line_start or 0,
            })
        return grouped
