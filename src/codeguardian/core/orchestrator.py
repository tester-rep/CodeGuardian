"""Orchestrator — main controller that coordinates the full scan pipeline.

This is the central entry point after CLI command parsing.
It follows the phase-based execution model defined in COMBINED.md §十.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING
from uuid import uuid4

from codeguardian.ai.providers.dummy import DummyAIProvider
from codeguardian.ai.router import AIRouter
from codeguardian.core.context import ScanContext
from codeguardian.core.planner import build_plan
from codeguardian.core.scheduler import Scheduler
from codeguardian.detectors.project_detector import ProjectDetector
from codeguardian.engines.complexity_engine import ComplexityEngine
from codeguardian.engines.config_risk_engine import ConfigRiskEngine
from codeguardian.engines.defect_engine import DefectEngine
from codeguardian.engines.dependency_engine import DependencyEngine
from codeguardian.engines.git_evolution_engine import GitEvolutionEngine
from codeguardian.engines.metrics_engine import MetricsEngine
from codeguardian.engines.oo_design_engine import OODesignEngine
from codeguardian.engines.performance_engine import PerformanceEngine
from codeguardian.engines.rule_registry import apply_baseline
from codeguardian.engines.security_engine import SecurityEngine
from codeguardian.engines.semgrep_engine import SemgrepEngine
from codeguardian.engines.structure_engine import StructureEngine
from codeguardian.engines.testing_engine import TestingEngine
from codeguardian.core.call_graph.cross_function_engine import CrossFunctionEngine
from codeguardian.languages import EXTENSION_LANGUAGE_MAP, is_language_enabled, language_from_path, sort_paths_by_language_priority
from codeguardian.models.entity import ModuleEntity

from codeguardian.models.metric import Metric, MetricNames
from codeguardian.models.profile import (
    ModuleActionItem,
    ModuleArchitectureProfile,
    ModuleProfile,
    ModuleReportIssue,
    ModuleStabilityProfile,
    ModuleTestingProfile,
    ProjectProfile,
    ReleaseConclusion,
)
from codeguardian.models.scan import ScanRequest, ScanResult
from codeguardian.normalizers.base import ResultNormalizer
from codeguardian.reporters.html_reporter import HtmlReporter
from codeguardian.reporters.json_reporter import JsonReporter
from codeguardian.reporters.pdf_reporter import PdfReporter
from codeguardian.reporters.sarif_reporter import SarifReporter
from codeguardian.reporters.terminal import TerminalReporter
from codeguardian.risk.dimensions import build_dimension_scores
from codeguardian.risk.prioritizer import Prioritizer
from codeguardian.risk.scorer import RiskScorer
from codeguardian.storage.snapshots import save_snapshot
from codeguardian.utils.ignore import configure_exclude_paths, load_gitignore
from codeguardian.parsers.tree_sitter_support import clear_parse_cache

if TYPE_CHECKING:
    from codeguardian.ai.deep_review.merger import MergeOutput
    from codeguardian.ai.verifier import VerifyOutcome
    from codeguardian.config.schema import AppConfig
    from codeguardian.core.planner import AnalysisPlan
    from codeguardian.models.entity import ClassEntity, FileEntity, FunctionEntity
    from codeguardian.models.finding import Finding
    from codeguardian.models.report import ReportArtifact
    from codeguardian.reporters.base import Reporter


# Engine registry — maps engine names to their classes
ENGINE_MAP: dict[str, type] = {
    "structure": StructureEngine,
    "metrics": MetricsEngine,
    "complexity": ComplexityEngine,
    "defect": DefectEngine,
    "security": SecurityEngine,
    "performance": PerformanceEngine,
    "testing": TestingEngine,
    "git": GitEvolutionEngine,
    "config_risk": ConfigRiskEngine,
    "oo_design": OODesignEngine,
    "dependency": DependencyEngine,
    "semgrep": SemgrepEngine,
    "cross_function": CrossFunctionEngine,
}

SUPPORTED_REPORT_FORMATS = ("terminal", "json", "html", "sarif", "pdf")
_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_CORE_MODULE_TOKENS = {"core", "shared", "common", "domain", "service", "api", "controller", "handler", "infra", "platform"}


class Orchestrator:
    """Main orchestrator that drives the complete scan pipeline."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.scheduler = Scheduler()
        self.normalizer = ResultNormalizer()
        self._verifier_outcome: VerifyOutcome | None = None

    async def run_scan(self, request: ScanRequest) -> ScanResult:
        """Execute a full scan pipeline."""
        started_at = datetime.now(UTC)
        start_monotonic = time.monotonic()
        scan_id = uuid4().hex[:12]

        detection = ProjectDetector().detect(request.project_path)

        # Apply user-configured exclude paths before any file scanning
        configure_exclude_paths(self.config.scan.exclude_paths)
        # Load .gitignore patterns for project-specific exclusions
        load_gitignore(request.project_path)
        # Clear tree-sitter parse cache from previous scans
        clear_parse_cache()

        ctx = ScanContext(
            scan_id=scan_id,
            project_root=str(request.project_path),
            config=self.config,
            detected_languages=detection.languages,
            detected_frameworks=detection.frameworks,
            build_systems=detection.build_systems,
            test_frameworks=detection.test_frameworks,
            is_git_repo=detection.is_git_repo,
            repo_type=detection.repo_type,
            review_mode=request.review_mode,
            dimensions=request.dimensions,
            languages=request.languages or self.config.scan.languages,
            incremental=request.incremental or request.since is not None,
            since=request.since,
            no_cache=request.no_cache,
        )
        self._populate_incremental_scope(ctx, request)

        plan = build_plan(ctx)

        # Runtime AI degrade: if AI is requested but the provider resolves to the
        # dummy placeholder (missing key / import error / provider=dummy), force
        # ai_off explicitly and surface it — never silently pretend AI ran.
        runtime_ai_mode = ctx.review_mode
        if ctx.ai_enabled and isinstance(AIRouter.from_config(self.config.ai).provider, DummyAIProvider):
            runtime_ai_mode = "degraded(ai_off)"
            ctx.review_mode = "ai_off"
            self.config.ai.enabled = False
            from codeguardian.cli.output import console

            console.print(
                "[red][!] AI 不可达（缺少 API Key 或 provider=dummy），"
                "已降级为 ai_off，本次不执行 AI 深审/校验[/red]"
            )

        # Build Project Call Graph Index (PCI) for cross-function analysis.
        # PCI always uses the FULL project graph (even in incremental mode) so
        # cross-function analysis never runs on a truncated call graph.
        if "cross_function" in plan.enabled_engines:
            self._build_pci(ctx, no_cache=request.no_cache)

        active_engines = [ENGINE_MAP[name] for name in plan.enabled_engines if name in ENGINE_MAP]
        if not active_engines:
            raise ValueError("No executable engines available for the requested scan dimensions.")
        tasks = [engine_class().analyze(ctx) for engine_class in active_engines]
        engine_results = await self.scheduler.run(tasks, concurrency_limit=plan.concurrency_limit)

        normalized_results = [self.normalizer.normalize(r) for r in engine_results]

        findings = []
        supplementary_findings = []
        metrics = []
        files = []
        functions = []
        classes = []
        modules = []
        engine_warnings: list[str] = []
        engine_errors: list[str] = []

        # Hint when Semgrep CLI is installed but the engine is disabled in config.
        # Helps new users discover that an extra SAST engine is available.
        if not self.config.semgrep.enabled and shutil.which("semgrep") is not None:
            engine_warnings.append(
                "semgrep: 检测到 Semgrep CLI 已安装，但 [semgrep] 段未启用。"
                "可在 codeguardian.toml 中设置 [semgrep] enabled = true 以增强 SAST 覆盖。"
            )

        for idx, result in enumerate(normalized_results):
            engine_name = result.engine_name
            if engine_name.startswith("task-") and idx < len(active_engines):
                engine_name = str(getattr(active_engines[idx], "name", active_engines[idx].__name__))
                result.engine_name = engine_name
            engine_warnings.extend(f"{engine_name}: {warning}" for warning in result.warnings)
            engine_errors.extend(f"{engine_name}: {error}" for error in result.errors)
            engine_findings = result.findings
            # cross_function runs on the FULL call graph (see PCI note above); in
            # incremental mode narrow its findings back to changed files so the
            # report only surfaces issues relevant to the diff.
            if ctx.incremental and "cross_function" in engine_name:
                engine_findings = self._filter_findings_to_changed(engine_findings, ctx.changed_files)
            findings.extend(engine_findings)
            metrics.extend(result.metrics)
            files.extend(result.files)
            functions.extend(result.functions)
            classes.extend(result.classes)
            modules.extend(result.modules)

        baseline_path = self._resolve_baseline_path(request.project_path)
        findings = apply_baseline(findings, baseline_path)

        # T6: zero-cost FP filter for Semgrep security findings (no AI tokens spent).
        if self.config.semgrep.enabled and self.config.semgrep.local_validate:
            findings = self._apply_local_validator_to_engine(
                findings, engine="semgrep", project_root=Path(ctx.project_root),
            )

        # T5: cross-engine de-duplication (Semgrep ↔ local security_engine).
        findings = self._dedupe_overlapping_findings(findings)

        # Impact enrichment: compute blast radius per finding using PCI
        pci_result = getattr(ctx, "_pci_result", None)
        if pci_result is not None:
            from codeguardian.core.call_graph.impact_scorer import enrich_findings_with_impact
            from codeguardian.core.call_graph.process_enricher import enrich_findings_with_process_context
            findings = enrich_findings_with_impact(findings, pci_result)
            findings = enrich_findings_with_process_context(findings, pci_result)

        findings = Prioritizer().apply(findings)

        # AI Verifier phase (FP second-pass judgement over engine findings).
        # Runs before deep_review so the AI reviewer doesn't waste tokens
        # re-reasoning over findings already classified as FP.
        verify_outcome = await self._run_ai_verify(request, findings, ctx)
        if verify_outcome is not None:
            findings = verify_outcome.findings
            if request.drop_false_positives or self.config.ai_verify.drop_false_positives:
                findings = [f for f in findings if f.verification_status != "ai-verified-fp"]

        # AI Deep Review phase (only in deep mode with AI enabled)
        # Allow free_review (scout) to run independently of deep_review
        deep_review_output: MergeOutput | None = None
        if self.config.ai.enabled:
            deep_review_output = await self._run_deep_review(ctx, findings, files)
            if deep_review_output:
                findings.extend(deep_review_output.primary)
                supplementary_findings.extend(deep_review_output.supplementary)

        if request.verify_mode != "off":
            from codeguardian.verification import VerificationEngine

            verifier = VerificationEngine()
            verifier.apply(findings, request.project_path, mode=request.verify_mode)
            verifier.apply(supplementary_findings, request.project_path, mode=request.verify_mode)

        findings = Prioritizer().apply(findings)
        supplementary_findings = Prioritizer().apply(supplementary_findings)

        risk_scorer = RiskScorer(self.config.risk.weights)
        overall_score = risk_scorer.score(findings)
        module_profiles = self._build_module_profiles(modules, files, functions, classes, findings, metrics, risk_scorer)
        metrics.extend(self._build_derived_risk_metrics(module_profiles, overall_score))
        dimension_scores = build_dimension_scores(findings, metrics)


        project_profile = ProjectProfile(
            project_name=ctx.project_name,
            overall_score=overall_score,
            health_status=self._health_status(overall_score),
            languages=ctx.detected_languages,
            frameworks=ctx.detected_frameworks,
            total_files=len(files),
            total_loc=sum(f.loc for f in files),
            total_sloc=sum(f.sloc for f in files),
            total_functions=len(functions),
            total_classes=len(classes),
            dimension_scores=dimension_scores,
            modules=module_profiles,
        )

        ai_summary = self._build_ai_summary(project_profile, findings, ctx)
        release_conclusion = self._build_release_conclusion(project_profile, findings, metrics, ctx)
        ai_summary, release_conclusion, enhancement_usage = await self._apply_ai_enhancement(
            project_profile,
            findings,
            metrics,
            ctx,
            ai_summary,
            release_conclusion,
        )

        # Build AI token usage statistics

        ai_token_usage_dict = None

        if self.config.ai.enabled:
            from codeguardian.ai.models import TokenUsageStats
            usage_stats = TokenUsageStats()

            # Deep Review usage
            if deep_review_output and hasattr(deep_review_output, 'reviewer_usage') and deep_review_output.reviewer_usage:
                reviewer_usage = deep_review_output.reviewer_usage
                usage_stats.deep_review_prompt_tokens = reviewer_usage.prompt_tokens
                usage_stats.deep_review_completion_tokens = reviewer_usage.completion_tokens
                usage_stats.deep_review_total_tokens = reviewer_usage.total_tokens
                usage_stats.deep_review_api_calls = deep_review_output.done_chunks
                usage_stats.budget_max_tokens = deep_review_output.budget_max
                usage_stats.budget_spent_tokens = deep_review_output.budget_spent

            # Enhancement usage (summarize + release review)
            usage_stats.enhancement_prompt_tokens = enhancement_usage.prompt_tokens
            usage_stats.enhancement_completion_tokens = enhancement_usage.completion_tokens
            usage_stats.enhancement_total_tokens = enhancement_usage.total_tokens
            usage_stats.enhancement_api_calls = 1 if enhancement_usage.total_tokens > 0 else 0
            # Count 2 calls if both summarize and release review ran
            if enhancement_usage.total_tokens > 0:
                usage_stats.enhancement_api_calls = 2  # summarize + release_review

            # AI Verifier usage (FP second-pass judgement)
            if self._verifier_outcome is not None:
                vu = self._verifier_outcome.usage
                usage_stats.ai_verify_prompt_tokens = vu.prompt_tokens
                usage_stats.ai_verify_completion_tokens = vu.completion_tokens
                usage_stats.ai_verify_total_tokens = vu.total_tokens
                usage_stats.ai_verify_api_calls = (
                    self._verifier_outcome.pass1_count + self._verifier_outcome.pass2_count
                )
                usage_stats.ai_verify_pass1_count = self._verifier_outcome.pass1_count
                usage_stats.ai_verify_pass2_count = self._verifier_outcome.pass2_count
                usage_stats.ai_verify_fp_count = self._verifier_outcome.fp_count
                usage_stats.ai_verify_confirmed_count = self._verifier_outcome.confirmed_count
                usage_stats.ai_verify_uncertain_count = self._verifier_outcome.uncertain_count
                usage_stats.ai_verify_cache_hits = self._verifier_outcome.cache_hits

            # Record model names for report display
            ai_cfg = self.config.ai
            dr_cfg = self.config.deep_review
            usage_stats.deep_review_model = dr_cfg.review_model or ai_cfg.model
            usage_stats.enhancement_summary_model = ai_cfg.summary_model or ai_cfg.model
            usage_stats.enhancement_release_model = ai_cfg.heavy_model or ai_cfg.model

            if usage_stats.total_tokens > 0:
                ai_token_usage_dict = usage_stats.to_dict()

        finished_at = datetime.now(UTC)
        elapsed = time.monotonic() - start_monotonic

        # Compute issue clustering and tech debt estimate
        from codeguardian.risk.clustering import cluster_findings, estimate_tech_debt
        from dataclasses import asdict

        systemic_issues_raw = cluster_findings(findings)
        systemic_issues_dicts = [asdict(si) for si in systemic_issues_raw]
        tech_debt = estimate_tech_debt(findings)

        scan_result = ScanResult(
            scan_id=scan_id,
            started_at=started_at.isoformat(),
            finished_at=finished_at.isoformat(),
            duration_seconds=round(elapsed, 2),
            project_path=str(request.project_path),
            coverage="incremental" if ctx.incremental else "full",
            ai_mode=runtime_ai_mode,
            project_profile=project_profile,
            findings=findings,
            supplementary_findings=supplementary_findings,
            metrics=metrics,
            engine_warnings=engine_warnings,
            engine_errors=engine_errors,
            report_artifacts=[],
            ai_summary=ai_summary,
            release_conclusion=release_conclusion,
            ai_token_usage=ai_token_usage_dict,
            systemic_issues=systemic_issues_dicts,
            tech_debt_estimate=tech_debt,
        )


        scan_result.report_artifacts = self._render_reports(scan_result, request.report_formats)
        save_snapshot(scan_result, project_path=request.project_path)
        return scan_result

    def _build_plan(self, ctx: ScanContext) -> AnalysisPlan:
        return build_plan(ctx)

    @staticmethod
    def _filter_findings_to_changed(findings: list[Finding], changed_files: list[str] | None) -> list[Finding]:
        """Keep only project-level findings and those located in changed files."""
        if not changed_files:
            return list(findings)
        changed = {path.replace("\\", "/") for path in changed_files}
        return [
            finding
            for finding in findings
            if finding.location.file_path in {"project", ""}
            or finding.location.file_path.replace("\\", "/") in changed
        ]

    def _build_pci(self, ctx: ScanContext, *, no_cache: bool = False) -> None:
        """Build Project Call Graph Index for cross-function analysis.

        Attaches PCI result to ctx as _pci_result for engines to use.
        Gracefully degrades: logs warning and continues if PCI fails.
        """
        try:
            from codeguardian.core.call_graph.pci_builder import PCIBuilder

            builder = PCIBuilder(
                max_files=self.config.scan.get("call_graph_max_files", 5000)
                if hasattr(self.config.scan, "get")
                else 5000,
                use_cache=not no_cache,
            )
            result = builder.build(ctx)
            # Attach to context for engines (using private attr to avoid Pydantic issues)
            object.__setattr__(ctx, "_pci_result", result)
        except Exception:
            import logging
            logging.getLogger(__name__).warning(
                "PCI build failed, cross-function analysis will be skipped",
                exc_info=True,
            )
            object.__setattr__(ctx, "_pci_result", None)

    def _resolve_baseline_path(self, project_path: Path) -> Path | None:
        baseline_path = self.config.rules.baseline_path
        if not baseline_path:
            return None

        candidate = Path(baseline_path)
        if candidate.is_absolute():
            return candidate
        return (project_path / candidate).resolve()

    @staticmethod
    def _dedupe_overlapping_findings(findings: list[Finding]) -> list[Finding]:
        """Merge findings from different engines that describe the same issue.

        Heuristic: two security findings overlap when they share a file, sit
        within 2 lines of each other, and share at least one CWE id. The
        finding with the higher evidence rank wins; ties go to the first one
        seen (which preserves curated local-rule metadata over Semgrep's).
        """
        evidence_rank = {
            "test-confirmed": 5,
            "static-confirmed": 4,
            "likely": 3,
            "suspected": 2,
            "needs-review": 1,
        }

        kept: list[Finding] = []
        for finding in findings:
            if finding.category != "security" or not finding.cwe_ids:
                kept.append(finding)
                continue

            duplicate_idx = None
            for idx, existing in enumerate(kept):
                if existing.category != "security" or not existing.cwe_ids:
                    continue
                if existing.location.file_path != finding.location.file_path:
                    continue
                if abs((existing.location.line_start or 0) - (finding.location.line_start or 0)) > 2:
                    continue
                if not (set(existing.cwe_ids) & set(finding.cwe_ids)):
                    continue
                duplicate_idx = idx
                break

            if duplicate_idx is None:
                kept.append(finding)
                continue

            existing = kept[duplicate_idx]
            existing_rank = evidence_rank.get(existing.evidence_level, 0)
            new_rank = evidence_rank.get(finding.evidence_level, 0)
            if new_rank > existing_rank:
                kept[duplicate_idx] = finding
            # else: keep existing; drop incoming silently
        return kept

    def _apply_local_validator_to_engine(
        self,
        findings: list[Finding],
        *,
        engine: str,
        project_root: Path,
    ) -> list[Finding]:
        """Drop a severity tier on findings the LocalValidator flags as likely FP.

        Only applies to security findings produced by the named engine. We use
        the existing AI-side validator (zero token cost) by mapping each
        Finding into a transient ``AIFindingRaw`` shape it understands.
        Findings flagged ``LIKELY_FP`` are kept (we never silently drop a SAST
        result) but downgraded one severity level and tagged for triage.
        """
        from codeguardian.ai.deep_review.local_validator import LocalValidator, ValidationVerdict
        from codeguardian.ai.deep_review.models import AIFindingRaw
        from codeguardian.models.enums import Severity

        downgrade = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
            Severity.LOW: Severity.INFO,
            Severity.INFO: Severity.INFO,
        }

        validator = LocalValidator(project_root)
        out: list[Finding] = []
        for finding in findings:
            if finding.source_engine != engine or finding.category != "security":
                out.append(finding)
                continue

            raw = AIFindingRaw(
                title=finding.title,
                category="security",
                severity=finding.severity.value,
                confidence=8,  # not used by the security path
                line_start=finding.location.line_start or 0,
                line_end=finding.location.line_end or finding.location.line_start or 0,
                description=finding.root_cause or finding.title,
            )
            results = validator.validate_findings([raw], finding.location.file_path)
            if not results:
                out.append(finding)
                continue

            verdict = results[0][1].verdict
            if verdict != ValidationVerdict.LIKELY_FP:
                out.append(finding)
                continue

            # Likely FP: downgrade severity and annotate; never drop a SAST hit.
            downgraded = finding.model_copy(
                update={
                    "severity": downgrade[finding.severity],
                    "evidence_level": "needs-review",
                    "verification_status": "static-likely-fp",
                    "verification_summary": (
                        (finding.verification_summary or "")
                        + " | LocalValidator: " + results[0][1].reason
                    ).strip(" |"),
                    "tags": [*finding.tags, "local-validator-fp"],
                    "blocks_release": False,
                }
            )
            out.append(downgraded)
        return out

    def _populate_incremental_scope(self, ctx: ScanContext, request: ScanRequest) -> None:
        requested_since = request.since.strip() if request.since else None
        effective_since = requested_since or (self.config.git.since if request.incremental else None)
        ctx.since = effective_since
        if not ctx.incremental or not ctx.is_git_repo:
            return

        changed_files, changed_lines = self._resolve_git_changed_scope(Path(ctx.project_root), effective_since)
        if not changed_files:
            return
        ctx.target_files = changed_files
        ctx.changed_files = changed_files.copy()
        ctx.changed_lines = {file_path: sorted(lines) for file_path, lines in changed_lines.items() if lines}

    def _resolve_git_changed_scope(self, root: Path, since: str | None) -> tuple[list[str], dict[str, set[int]]]:
        base_ref = self._resolve_diff_base(root, since)
        if not base_ref:
            return [], {}

        name_result = self._run_git(
            root,
            ["diff", "--name-only", "--diff-filter=ACMR", base_ref, "HEAD", "--"],
        )
        if name_result is None:
            return [], {}

        changed_files = [
            _normalize_relpath(line)
            for line in name_result.stdout.splitlines()
            if line.strip() and (root / line.strip()).exists()
        ]
        if not changed_files:
            return [], {}

        patch_result = self._run_git(
            root,
            ["diff", "--unified=0", "--diff-filter=ACMR", base_ref, "HEAD", "--", *changed_files],
        )
        changed_lines = self._parse_changed_lines(patch_result.stdout if patch_result else "")
        return list(dict.fromkeys(changed_files)), changed_lines

    def _resolve_diff_base(self, root: Path, since: str | None) -> str | None:
        if not since:
            probe = self._run_git(root, ["rev-parse", "--verify", "HEAD~1"])
            return "HEAD~1" if probe else None

        if _looks_like_date(since):
            history = self._run_git(root, ["log", f"--since={since}", "--reverse", "--format=%H", "HEAD"])
            if history is None:
                return None
            commits = [line.strip() for line in history.stdout.splitlines() if line.strip()]
            if not commits:
                return None
            first_commit = commits[0]
            parent = self._run_git(root, ["rev-parse", "--verify", f"{first_commit}^"])
            if parent is not None and parent.stdout.strip():
                return parent.stdout.strip()
            return first_commit

        probe = self._run_git(root, ["rev-parse", "--verify", since])
        if probe is None:
            return None
        return since

    @staticmethod
    def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        return result

    def _parse_changed_lines(self, diff_text: str) -> dict[str, set[int]]:
        changed_lines: dict[str, set[int]] = {}
        current_file: str | None = None

        for raw_line in diff_text.splitlines():
            if raw_line.startswith("+++ b/"):
                current_file = _normalize_relpath(raw_line[6:])
                changed_lines.setdefault(current_file, set())
                continue
            if raw_line.startswith("@@") and current_file is not None:
                match = _HUNK_RE.search(raw_line)
                if not match:
                    continue
                start = int(match.group(1))
                count = int(match.group(2) or "1")
                if count <= 0:
                    continue
                changed_lines[current_file].update(range(start, start + count))
        return changed_lines

    def _render_reports(self, result: ScanResult, formats: list[str]) -> list[ReportArtifact]:
        configured_output_dir = Path(self.config.reports.output_dir or "reports")
        output_dir = configured_output_dir
        if not configured_output_dir.is_absolute():
            output_dir = Path(result.project_path) / configured_output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        reporters: dict[str, type[Reporter]] = {
            "terminal": TerminalReporter,
            "json": JsonReporter,
            "html": HtmlReporter,
            "sarif": SarifReporter,
            "pdf": PdfReporter,
        }

        unsupported_formats = [fmt for fmt in formats if fmt.lower() not in reporters]
        if unsupported_formats:
            raise ValueError(
                "Unsupported report format(s): "
                f"{', '.join(sorted(set(unsupported_formats)))}. "
                f"Supported: {', '.join(SUPPORTED_REPORT_FORMATS)}"
            )

        artifacts: list[ReportArtifact] = []
        for fmt in formats:
            reporter_cls = reporters[fmt.lower()]
            artifact = reporter_cls().render(result, output_dir)
            if artifact:
                artifacts.append(artifact)

        return artifacts

    def _build_ai_summary(
        self,
        profile: ProjectProfile,
        findings: list[Finding],
        ctx: ScanContext,
    ) -> str:
        if not findings:
            scope = "本次增量范围" if ctx.incremental else "当前项目"
            return f"{scope}未发现阻断发布的问题，整体健康度为 {profile.overall_score:.0f}/100。"

        severity_counts = Counter(f.severity.value for f in findings)
        category_counts = Counter(f.category for f in findings)
        top_categories = "、".join(name for name, _ in category_counts.most_common(3)) or "暂无"
        top_modules = "、".join(module.path for module in profile.modules[:3] if module.findings) or "暂无明显热点模块"

        scope = f"增量范围（{len(ctx.changed_files)} 个变更文件）" if ctx.incremental and ctx.changed_files else "全量扫描范围"
        return (
            f"{scope}共发现 {len(findings)} 个问题，"
            f"其中 critical {severity_counts.get('critical', 0)} 个、high {severity_counts.get('high', 0)} 个。"
            f"主要风险集中在：{top_categories}；优先关注模块：{top_modules}。"
            f"当前总体得分 {profile.overall_score:.0f}/100，状态为 {profile.health_status}。"
        )

    def _build_release_conclusion(
        self,
        profile: ProjectProfile,
        findings: list[Finding],
        metrics: list[Metric],
        ctx: ScanContext,
    ) -> ReleaseConclusion:

        blocking = [finding for finding in findings if finding.is_blocking][:10]
        high_risk = [finding for finding in findings if finding.severity.value in {"critical", "high"}][:10]
        project_metrics = self._project_metric_values(metrics)
        change_coverage = project_metrics.get(MetricNames.CHANGE_LINE_COVERAGE)
        core_module_score = project_metrics.get(MetricNames.CORE_MODULE_SCORE, profile.overall_score)

        if blocking:
            verdict = "blocked"
        elif profile.overall_score < self.config.risk.default_threshold:
            verdict = "not_recommended"
        elif high_risk:
            verdict = "conditional"
        else:
            verdict = "recommended"

        review_bits = [
            {
                "blocked": f"当前存在 {len(blocking)} 个阻断发布项。",
                "not_recommended": f"总体得分 {profile.overall_score:.1f} 低于发布阈值 {self.config.risk.default_threshold:.1f}。",
                "conditional": f"仍有 {len(high_risk)} 个高风险问题需要带条件放行。",
                "recommended": "未发现阻断项，当前质量状态可支持发布。",
            }[verdict],
            f"核心模块风险分 {core_module_score:.1f}。",
        ]
        if change_coverage is not None:
            review_bits.append(f"变更覆盖率 {change_coverage:.1f}%。")
        if ctx.incremental and ctx.changed_files:
            review_bits.append(f"本次增量涉及 {len(ctx.changed_files)} 个变更文件。")

        suggested_verifications = [
            {
                "type": "test",
                "suggestion": finding.test_suggestion or "补充覆盖关键路径、边界条件和失败路径的回归验证。",
            }
            for finding in high_risk[:3]
        ]
        if change_coverage is not None and change_coverage < 80:
            suggested_verifications.insert(
                0,
                {
                    "type": "coverage",
                    "suggestion": "优先为本次改动涉及的关键分支、异常路径和回归热点补齐覆盖率。",
                },
            )

        return ReleaseConclusion(
            verdict=verdict,
            review_summary=" ".join(review_bits),
            review_source="local",
            blocking_items=[
                {
                    "id": finding.id,
                    "title": finding.title,
                    "location": f"{finding.location.file_path}:{finding.location.line_start or 1}",
                }
                for finding in blocking
            ],
            residual_risks=[
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                }
                for finding in high_risk[:5]
            ],
            suggested_verifications=suggested_verifications,
            post_release_monitoring=[
                {
                    "type": "quality",
                    "suggestion": "发布后持续观察错误率、关键接口耗时和新增高优先级问题。",
                },
                {
                    "type": "coverage",
                    "suggestion": "持续跟踪核心模块风险分与变更覆盖率，避免后续增量持续走低。",
                },
            ],
        )


    def _build_module_profiles(
        self,
        modules: list[ModuleEntity],
        files: list[FileEntity],
        functions: list[FunctionEntity],
        classes: list[ClassEntity],
        findings: list[Finding],
        metrics: list[Metric],
        scorer: RiskScorer,
    ) -> list[ModuleProfile]:
        normalized_modules = self._normalize_modules(modules, files)
        profiles: list[ModuleProfile] = []

        for module in normalized_modules:
            file_set = set(module.file_paths)
            module_findings = [finding for finding in findings if self._finding_in_module(finding, file_set, module.path)]
            module_metrics = [metric for metric in metrics if self._metric_in_module(metric, file_set, module.path)]
            module_files = [file for file in files if file.path in file_set]
            module_functions = [fn for fn in functions if fn.file_path in file_set]
            module_classes = [cls for cls in classes if cls.file_path in file_set]
            risk_score = scorer.module_score(module_findings)
            risk_level = self._module_risk_level(risk_score)
            module_dimension_scores = {
                score.dimension: round(score.score, 1)
                for score in build_dimension_scores(module_findings, module_metrics)
            }
            line_coverage = self._average_metric_or_none(module_metrics, MetricNames.LINE_COVERAGE)
            branch_coverage = self._average_metric_or_none(module_metrics, MetricNames.BRANCH_COVERAGE)
            function_coverage = self._average_metric_or_none(module_metrics, MetricNames.FUNCTION_COVERAGE)
            churn_score = self._sum_metric_or_none(module_metrics, MetricNames.CHURN_SCORE)
            avg_complexity = self._average_function_complexity(module_metrics)
            duplication_rate = self._average_metric(module_metrics, MetricNames.DUPLICATION_RATE)
            recommendation = self._module_recommendation(risk_score, module_findings)
            testing_profile = self._build_module_testing_profile(
                line_coverage,
                branch_coverage,
                function_coverage,
            )
            historical_stability = self._build_module_stability_profile(churn_score, module_findings)
            architecture_profile = self._build_module_architecture_profile(module_findings)
            action_items = self._build_module_action_items(
                risk_score,
                module_findings,
                avg_complexity,
                duplication_rate,
                testing_profile,
                historical_stability,
            )

            profiles.append(
                ModuleProfile(
                    name=module.name,
                    path=module.path,
                    file_count=len(file_set),
                    class_count=len(module_classes),
                    function_count=len(module_functions),
                    language=module.language or self._dominant_language(module_files),
                    loc=sum(file.loc for file in module_files),
                    sloc=sum(file.sloc for file in module_files),
                    risk_score=risk_score,
                    risk_level=risk_level,
                    findings=module_findings,
                    top_findings=self._module_top_findings(module_findings),
                    dimension_scores=module_dimension_scores,
                    avg_complexity=avg_complexity,
                    duplication_rate=duplication_rate,
                    test_coverage=line_coverage,
                    branch_coverage=branch_coverage,
                    function_coverage=function_coverage,
                    churn_score=churn_score,
                    testing_profile=testing_profile,
                    historical_stability=historical_stability,
                    architecture_profile=architecture_profile,
                    action_items=action_items,
                    recommendation=recommendation,
                )
            )

        profiles.sort(key=lambda profile: (profile.risk_score, -len(profile.findings), -profile.file_count, profile.path))
        return profiles


    def _build_derived_risk_metrics(self, module_profiles: list[ModuleProfile], overall_score: float) -> list[Metric]:
        core_modules = [profile for profile in module_profiles if self._is_core_module(profile)]
        if not core_modules:
            core_modules = module_profiles[:3]
        core_score = min((profile.risk_score for profile in core_modules), default=overall_score)

        return [
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.RISK_SCORE,
                value=round(overall_score, 1),
                unit="score",
                source_engine="risk",
                extra={"model": "composite-heuristic"},
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.CORE_MODULE_SCORE,
                value=round(core_score, 1),
                unit="score",
                source_engine="risk",
                extra={"modules": [profile.path for profile in core_modules]},
            ),
        ]

    @staticmethod
    def _normalize_modules(
        modules: list[ModuleEntity],
        files: list[FileEntity],
    ) -> list[ModuleEntity]:
        normalized: dict[str, ModuleEntity] = {}
        for module in modules:
            path = module.path or "."
            file_paths = sorted(set(module.file_paths or []))
            if not file_paths:
                file_paths = sorted(file.path for file in files if Orchestrator._file_in_module_path(file.path, path))
            normalized[path] = ModuleEntity(
                name=module.name or (Path(path).name if path not in {"", "."} else "root"),
                path=path,
                module_type=module.module_type,
                file_paths=file_paths,
                language=module.language,
            )

        if normalized:
            return list(normalized.values())
        return Orchestrator._derive_modules_from_files(files)

    @staticmethod
    def _derive_modules_from_files(files: list[FileEntity]) -> list[ModuleEntity]:
        grouped: dict[str, list[str]] = {}
        for file in files:
            parts = PurePosixPath(file.path).parts
            module_path = parts[0] if len(parts) > 1 else "."
            grouped.setdefault(module_path, []).append(file.path)

        return [
            ModuleEntity(
                name=Path(path).name if path not in {"", "."} else "root",
                path=path,
                file_paths=sorted(paths),
            )
            for path, paths in sorted(grouped.items())
        ]

    @staticmethod
    def _file_in_module_path(file_path: str, module_path: str) -> bool:
        normalized_file = file_path.replace("\\", "/")
        normalized_module = module_path.replace("\\", "/")
        if normalized_module in {"", "."}:
            return "/" not in normalized_file
        return normalized_file == normalized_module or normalized_file.startswith(f"{normalized_module}/")

    @classmethod
    def _finding_in_module(
        cls,
        finding: Finding,
        file_set: set[str],
        module_path: str,
    ) -> bool:
        file_path = finding.location.file_path.replace("\\", "/")
        return file_path in file_set or cls._file_in_module_path(file_path, module_path)

    @classmethod
    def _metric_in_module(
        cls,
        metric: Metric,
        file_set: set[str],
        module_path: str,
    ) -> bool:
        target_id = metric.target_id.replace("\\", "/")
        if metric.target_type == "file":
            return target_id in file_set or cls._file_in_module_path(target_id, module_path)
        if metric.target_type == "function":
            return any(target_id.startswith(f"{file_path}:") for file_path in file_set)
        return False

    @staticmethod
    def _module_top_findings(findings: list[Finding]) -> list[ModuleReportIssue]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        priority_order = {"must-fix": 0, "should-fix": 1, "can-fix": 2}
        sorted_findings = sorted(
            findings,
            key=lambda finding: (
                severity_order.get(finding.severity.value, 5),
                priority_order.get(finding.risk_priority, 3),
                -finding.score_impact,
            ),
        )
        return [
            ModuleReportIssue(
                id=finding.id,
                title=finding.title,
                severity=finding.severity.value,
                priority=finding.risk_priority,
                location=f"{finding.location.file_path}:{finding.location.line_start or 1}",
            )
            for finding in sorted_findings[:5]
        ]

    @staticmethod
    def _build_module_testing_profile(
        line_coverage: float | None,
        branch_coverage: float | None,
        function_coverage: float | None,
    ) -> ModuleTestingProfile:
        available_scores = [score for score in (line_coverage, branch_coverage, function_coverage) if score is not None]
        if not available_scores:
            status = "unavailable"
        elif any(score < 60 for score in available_scores):
            status = "critical"
        elif any(score < 80 for score in available_scores):
            status = "warning"
        else:
            status = "good"
        return ModuleTestingProfile(
            line_coverage=line_coverage,
            branch_coverage=branch_coverage,
            function_coverage=function_coverage,
            status=status,
        )

    @staticmethod
    def _build_module_stability_profile(
        churn_score: float | None,
        module_findings: list[Finding],
    ) -> ModuleStabilityProfile:
        hotspot = any(finding.rule_id in {"GIT-HOTSPOT", "OWNERSHIP-RISK"} for finding in module_findings)
        recent_large_change = churn_score is not None and churn_score >= 200
        if hotspot or recent_large_change:
            churn_trend = "rising"
        elif churn_score is None or churn_score == 0:
            churn_trend = "unknown"
        else:
            churn_trend = "stable"
        return ModuleStabilityProfile(
            churn_score=round(churn_score, 1) if churn_score is not None else None,
            churn_trend=churn_trend,
            hotspot=hotspot,
            recent_large_change=recent_large_change,
        )

    @staticmethod
    def _build_module_architecture_profile(
        module_findings: list[Finding],
    ) -> ModuleArchitectureProfile:
        architecture_findings = [
            finding
            for finding in module_findings
            if finding.category in {"architecture", "dependency"}
        ]
        notes = []
        layering_compliant = None
        if architecture_findings:
            layering_compliant = False
            notes.append(f"已发现 {len(architecture_findings)} 个架构/依赖相关问题，建议人工复核模块边界。")
        else:
            notes.append("依赖图与层次分析尚未接通，当前仅提供专项报告占位。")
        return ModuleArchitectureProfile(
            layering_compliant=layering_compliant,
            circular_dependencies=0,
            fan_in=None,
            fan_out=None,
            instability=None,
            notes=notes,
        )

    @staticmethod
    def _build_module_action_items(
        risk_score: float,
        module_findings: list[Finding],
        avg_complexity: float,
        duplication_rate: float,
        testing_profile: ModuleTestingProfile,
        stability_profile: ModuleStabilityProfile,
    ) -> list[ModuleActionItem]:
        items: list[ModuleActionItem] = []
        if any(finding.is_blocking for finding in module_findings) or risk_score < 50:
            items.append(
                ModuleActionItem(
                    type="release",
                    priority="must",
                    summary="优先消除阻断发布项，再讨论模块放行。",
                )
            )
        if testing_profile.status in {"critical", "warning"}:
            items.append(
                ModuleActionItem(
                    type="test",
                    priority="recommended",
                    summary="补齐关键路径、异常分支与失败路径的回归验证。",
                )
            )
        elif testing_profile.status == "unavailable":
            items.append(
                ModuleActionItem(
                    type="test",
                    priority="recommended",
                    summary="接通该模块的覆盖率采集，避免专项报告缺少测试充分性事实。",
                )
            )
        if avg_complexity >= 10 or duplication_rate >= 10:
            items.append(
                ModuleActionItem(
                    type="maintainability",
                    priority="recommended",
                    summary="拆分复杂函数并压降重复逻辑，优先收敛可维护性风险。",
                )
            )
        if stability_profile.hotspot or stability_profile.recent_large_change:
            items.append(
                ModuleActionItem(
                    type="stability",
                    priority="recommended",
                    summary="针对高变更热点增加回归验证与发布后监控。",
                )
            )
        if not items:
            items.append(
                ModuleActionItem(
                    type="observe",
                    priority="optional",
                    summary="维持当前观察频率，继续跟踪模块风险分和关键指标。",
                )
            )
        return items[:4]

    @staticmethod
    def _dominant_language(files: list[FileEntity]) -> str | None:
        counts = Counter(file.language for file in files if file.language)
        return counts.most_common(1)[0][0] if counts else None

    @staticmethod
    def _average_function_complexity(metrics: list[Metric]) -> float:

        values = [
            metric.value
            for metric in metrics
            if metric.target_type == "function" and metric.metric_name == MetricNames.CYCLOMATIC_COMPLEXITY
        ]
        if not values:
            return 0.0
        return round(sum(values) / len(values), 1)

    @staticmethod
    def _average_metric(metrics: list[Metric], metric_name: str) -> float:
        values = [metric.value for metric in metrics if metric.target_type == "file" and metric.metric_name == metric_name]
        if not values:
            return 0.0
        return round(sum(values) / len(values), 1)

    @staticmethod
    def _average_metric_or_none(metrics: list[Metric], metric_name: str) -> float | None:
        values = [metric.value for metric in metrics if metric.target_type == "file" and metric.metric_name == metric_name]
        if not values:
            return None
        return round(sum(values) / len(values), 1)

    @staticmethod
    def _sum_metric_or_none(metrics: list[Metric], metric_name: str) -> float | None:
        values = [metric.value for metric in metrics if metric.target_type == "file" and metric.metric_name == metric_name]

        if not values:
            return None
        return round(sum(values), 1)


    @staticmethod
    def _module_risk_level(score: float) -> str:
        if score >= 85:
            return "good"
        if score >= 70:
            return "medium"
        if score >= 50:
            return "high"
        return "critical"

    @staticmethod
    def _module_recommendation(score: float, findings: list[Finding]) -> str:

        if any(finding.is_blocking for finding in findings) or score < 50:
            return "immediate_refactor"
        if score < 80:
            return "plan_refactor"
        return "continue_observing"

    @staticmethod
    def _is_core_module(profile: ModuleProfile) -> bool:
        path_parts = {part.lower() for part in PurePosixPath(profile.path or ".").parts if part not in {"", "."}}
        return bool(path_parts & _CORE_MODULE_TOKENS)

    @staticmethod
    def _build_deep_review_file_language_map(ctx: ScanContext, files: list[FileEntity]) -> dict[str, str]:
        file_language_map = {
            f.path: f.language
            for f in files
            if f.language and is_language_enabled(f.language, ctx.languages)
        }
        if file_language_map:
            return file_language_map

        root = Path(ctx.project_root).resolve()
        suffixes = set(EXTENSION_LANGUAGE_MAP)
        for path in sort_paths_by_language_priority(ctx.collect_candidate_files(root, suffixes=suffixes)):
            language = language_from_path(path)
            if language is None or not is_language_enabled(language, ctx.languages):
                continue
            try:
                rel_path = str(path.resolve().relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
            file_language_map[rel_path] = language
        return file_language_map

    async def _run_ai_verify(
        self,
        request: ScanRequest,
        findings: list[Finding],
        ctx: ScanContext | None = None,
    ) -> VerifyOutcome | None:
        """Run AI second-pass FP verification over engine findings.

        Returns ``None`` when verifier is disabled, AI is unavailable, or
        there are no findings to verify. The returned outcome carries the
        new (mutated) findings list and aggregated stats.
        """
        if not findings:
            return None
        if not self.config.ai.enabled or not self.config.ai_verify.enabled:
            return None
        try:
            from codeguardian.ai.verifier import VerifyOutcome  # noqa: F401 — type only
            from codeguardian.ai.verifier.verifier import build_verifier

            verifier = build_verifier(
                self.config.ai,
                self.config.ai_verify,
                Path(request.project_path),
                no_cache=request.no_cache,
                pci=getattr(ctx, "_pci_result", None) if ctx else None,
            )
            if verifier is None:
                return None
            self._verifier_outcome = await verifier.verify(findings)
            return self._verifier_outcome
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "AI Verifier failed, continuing without it",
            )
            return None

    async def _run_deep_review(
        self,
        ctx: ScanContext,
        local_findings: list[Finding],
        files: list[FileEntity],
    ) -> MergeOutput | None:
        """Run AI deep review pipeline when depth=deep and AI is enabled."""
        try:
            from codeguardian.ai.deep_review.pipeline import DeepReviewPipeline

            file_language_map = self._build_deep_review_file_language_map(ctx, files)
            if not file_language_map:
                return None


            pipeline = DeepReviewPipeline(self.config)
            return await pipeline.run(ctx, local_findings, file_language_map)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("AI Deep Review failed, continuing without it")
            return None

    async def _apply_ai_enhancement(
        self,
        profile: ProjectProfile,
        findings: list[Finding],
        metrics: list[Metric],
        ctx: ScanContext,
        ai_summary: str,
        release_conclusion: ReleaseConclusion,
    ) -> tuple[str, ReleaseConclusion, object]:
        """Apply AI enhancements and return (summary, conclusion, router_usage)."""
        from codeguardian.ai.models import TokenUsage

        if not self.config.ai.enabled:
            return ai_summary, release_conclusion, TokenUsage()

        router = AIRouter.from_config(self.config.ai)
        if isinstance(router.provider, DummyAIProvider):
            return ai_summary, release_conclusion, TokenUsage()

        # Run summary and release review in parallel (independent tasks)
        summary_task = router.summarize_findings(
            self._build_ai_summary_payload(profile, findings, metrics, ctx)
        )
        review_task = router.review_release(
            self._build_release_review_payload(profile, findings, metrics, ctx, release_conclusion)
        )

        results = await asyncio.gather(summary_task, review_task, return_exceptions=True)

        generated_summary = results[0]
        if isinstance(generated_summary, str) and generated_summary.strip():
            ai_summary = generated_summary.strip()

        generated_review = results[1]
        if isinstance(generated_review, str) and generated_review.strip():
            release_conclusion.review_summary = generated_review.strip()
            release_conclusion.review_source = "ai"

        return ai_summary, release_conclusion, router.total_usage

    @staticmethod
    def _project_metric_values(metrics: list[Metric]) -> dict[str, float]:
        return {
            metric.metric_name: metric.value
            for metric in metrics
            if metric.target_id == "project"
        }

    def _build_ai_summary_payload(
        self,
        profile: ProjectProfile,
        findings: list[Finding],
        metrics: list[Metric],
        ctx: ScanContext,
    ) -> dict[str, object]:

        severity_counts = Counter(finding.severity.value for finding in findings)
        category_counts = Counter(finding.category for finding in findings)
        return {
            "project_name": profile.project_name,
            "overall_score": round(profile.overall_score, 1),
            "health_status": profile.health_status,
            "incremental": ctx.incremental,
            "changed_files": ctx.changed_files[:20],
            "severity_counts": dict(severity_counts),
            "top_categories": [name for name, _ in category_counts.most_common(5)],
            "top_modules": [
                {
                    "path": module.path,
                    "risk_score": round(module.risk_score, 1),
                    "findings": len(module.findings),
                }
                for module in profile.modules[:5]
            ],
            "key_metrics": self._project_metric_values(metrics),
            "top_findings": [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "priority": finding.risk_priority,
                    "location": f"{finding.location.file_path}:{finding.location.line_start or 1}",
                }
                for finding in findings[:8]
            ],
        }

    def _build_release_review_payload(
        self,
        profile: ProjectProfile,
        findings: list[Finding],
        metrics: list[Metric],
        ctx: ScanContext,
        release_conclusion: ReleaseConclusion,
    ) -> dict[str, object]:

        return {
            "project_name": profile.project_name,
            "overall_score": round(profile.overall_score, 1),
            "health_status": profile.health_status,
            "verdict": release_conclusion.verdict,
            "incremental": ctx.incremental,
            "changed_files": ctx.changed_files[:20],
            "blocking_items": release_conclusion.blocking_items[:5],
            "residual_risks": release_conclusion.residual_risks[:5],
            "key_metrics": self._project_metric_values(metrics),
            "top_modules": [
                {
                    "path": module.path,
                    "risk_score": round(module.risk_score, 1),
                    "risk_level": module.risk_level,
                }
                for module in profile.modules[:5]
            ],
            "top_findings": [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "priority": finding.risk_priority,
                }
                for finding in findings[:8]
            ],
        }

    @staticmethod
    def _health_status(score: float) -> str:
        # Keep in sync with codeguardian.risk.dimensions._health_status.
        # See scorer.SCORE_DECAY_K for why these thresholds are loose.
        if score >= 75:
            return "good"
        if score >= 40:
            return "warning"
        return "critical"



def _looks_like_date(value: str) -> bool:

    return bool(re.match(r"^\d{4}-\d{2}-\d{2}", value.strip()))



def _normalize_relpath(value: str) -> str:
    return value.strip().replace("\\", "/")
