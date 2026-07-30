"""Result merger — aggregates AI review results into Finding objects.

Implements the three-tier result classification:
- Primary: confidence >= threshold OR source = "both" (local + AI)
- Supplementary: confidence < threshold, source = "ai" only
- Discarded: confidence < 3
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from pathlib import Path, PurePosixPath

from codeguardian.ai.deep_review.models import AIFindingRaw, ReviewResult
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.evidence import AIReviewEvidence
from codeguardian.models.finding import Finding

logger = logging.getLogger(__name__)

# Category mapping from AI output to FindingCategory values.
# Acts as a WHITELIST — any AI-reported category not in this map will be dropped
# (with a warning log) instead of silently falling back to "defect". This blocks
# hallucinated out-of-spec categories like "syntax" / "compile_error" / "style".
_CATEGORY_MAP: dict[str, str] = {
    "security": "security",
    "null_safety": "defect",
    "logic": "defect",
    "resource": "performance",
    "error_handling": "defect",
    "performance": "performance",
}

# Severity mapping
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class ResultMerger:
    """Merges AI review results into the unified Finding model."""

    def __init__(
        self,
        confidence_threshold: int = 6,
        existing_findings: list[Finding] | None = None,
        project_root: Path | None = None,
    ) -> None:
        self._threshold = confidence_threshold
        self._project_root = project_root
        # Build lookup for existing findings by file+line for dedup
        self._existing_by_location: dict[str, Finding] = {}
        if existing_findings:
            for f in existing_findings:
                key = f"{f.location.file_path}:{f.location.line_start}"
                self._existing_by_location[key] = f

    def merge(
        self,
        results: list[ReviewResult],
    ) -> MergeOutput:
        """Process all review results and classify into tiers.

        Returns
        -------
        MergeOutput
            Contains primary findings, supplementary findings,
            verified local finding IDs, and skip stats.
        """
        primary: list[Finding] = []
        supplementary: list[Finding] = []
        verified_ids: list[str] = []
        skip_counts: Counter[str] = Counter()
        total_chunks = len(results)
        done_chunks = 0
        total_tokens_used = 0

        # Initialize local validator if project root available
        local_validator = None
        if self._project_root is not None:
            try:
                from codeguardian.ai.deep_review.local_validator import LocalValidator
                local_validator = LocalValidator(self._project_root)
            except Exception:
                logger.debug("LocalValidator init failed, skipping local validation")

        for result in results:
            total_tokens_used += result.tokens_used
            if result.status != "done":
                skip_counts[result.skip_reason or "unknown"] += 1
                continue

            done_chunks += 1
            verified_ids.extend(result.verified_local_findings)

            # Local validation: filter obvious FPs before tier classification
            findings_to_process = result.findings
            if local_validator and result.findings:
                kept, _filtered = local_validator.filter_false_positives(
                    result.findings, result.chunk_file_path,
                )
                findings_to_process = kept

            for ai_finding in findings_to_process:
                # WHITELIST defense: drop findings with unknown category.
                # Prevents hallucinated categories (e.g. "syntax", "style",
                # "compile_error") from leaking into the report via the
                # silent "defect" fallback.
                raw_category = ai_finding.category.lower()
                if raw_category not in _CATEGORY_MAP:
                    logger.warning(
                        "Dropping AI finding with unknown category=%r "
                        "(title=%r, file=%s:L%d). Category whitelist: %s",
                        ai_finding.category,
                        ai_finding.title,
                        result.chunk_file_path,
                        ai_finding.line_start,
                        sorted(_CATEGORY_MAP.keys()),
                    )
                    continue

                finding = self._convert_to_finding(ai_finding, result.chunk_file_path)

                if ai_finding.confidence < 3:
                    # Discard — almost certainly false positive
                    continue

                # Check if local engine also found the same issue
                is_confirmed_by_local = self._is_confirmed_by_local(
                    ai_finding, result.chunk_file_path
                )

                if is_confirmed_by_local:
                    # Upgrade the existing local finding in-place instead of
                    # creating a duplicate. The local finding already carries
                    # curated metadata (rule_id, CWE, remediation); the AI
                    # confirmation boosts confidence and adds context.
                    local_finding = self._find_local_finding(
                        ai_finding, result.chunk_file_path,
                    )
                    if local_finding is not None:
                        local_finding.confidence = Confidence.HIGH
                        local_finding.evidence_level = "likely"
                        local_finding.verification_status = "unverified"
                        local_finding.verification_summary = (
                            f"AI 与本地规则在相近位置均发现风险: "
                            f"{ai_finding.description[:200]}"
                        )
                        if "source:both" not in local_finding.tags:
                            local_finding.tags.append("source:both")
                        # Merge AI fix suggestion when local finding lacks one.
                        if not local_finding.fix_suggestion and ai_finding.fix_suggestion:
                            local_finding.fix_suggestion = ai_finding.fix_suggestion
                    else:
                        # Fallback: lookup key missed (e.g. fuzzy match found
                        # but exact key lookup failed). Create new finding.
                        finding.confidence = Confidence.HIGH
                        finding.evidence_level = "likely"
                        finding.verification_status = "unverified"
                        finding.verification_summary = "AI 与本地规则在相近位置均发现风险，证据等级提升；尚未执行临时复现测试。"
                        finding.tags.append("source:both")
                        primary.append(finding)
                elif ai_finding.confidence >= self._threshold:
                    # High AI confidence → primary
                    finding.evidence_level = "suspected"
                    finding.verification_status = "unverified"
                    finding.verification_summary = "AI 深度审查提出的高置信疑似问题，需本地规则、测试或人工复核确认。"
                    finding.tags.append("source:ai")
                    primary.append(finding)

                else:
                    # Low AI confidence → supplementary
                    finding.evidence_level = "needs-review"
                    finding.verification_status = "unverified"
                    finding.verification_summary = "AI 低置信补充发现，仅作为人工复核线索。"
                    finding.tags.append("source:ai")
                    finding.tags.append("tier:supplementary")
                    supplementary.append(finding)


        # Upgrade existing local findings confirmed by AI
        for fid in verified_ids:
            for key, existing in self._existing_by_location.items():
                if existing.id == fid and existing.confidence != Confidence.HIGH:
                    existing.confidence = Confidence.HIGH
                    if "ai_verified" not in existing.tags:
                        existing.tags.append("ai_verified")

        return MergeOutput(
            primary=primary,
            supplementary=supplementary,
            verified_local_finding_ids=list(set(verified_ids)),
            total_chunks=total_chunks,
            done_chunks=done_chunks,
            skip_counts=dict(skip_counts),
            total_tokens_used=total_tokens_used,
        )

    def _convert_to_finding(self, raw: AIFindingRaw, file_path: str) -> Finding:
        """Convert an AI finding to the unified Finding model."""
        severity = _SEVERITY_MAP.get(raw.severity.lower(), Severity.MEDIUM)
        category = _CATEGORY_MAP.get(raw.category.lower(), "defect")

        # ── Severity cap for AI-only findings ────────────────────────────
        # AI alone cannot establish "critical": that level requires confirmed
        # exploitability or reproducible failure. Cap to HIGH here. The merger
        # later promotes back to whatever AI claimed only when the local
        # engine independently confirms the same issue (source = "both").
        if severity == Severity.CRITICAL:
            severity = Severity.HIGH

        # null_safety findings are notoriously over-reported by LLMs (any
        # `x.y()` looks like a potential NPE). Cap them to MEDIUM unless the
        # AI explicitly evidenced "variable X is dereferenced AND no catch".
        # Heuristic: require the evidence to mention "解引用 / dereference /
        # NPE / NullPointerException / 崩溃 / crash". Otherwise medium max.
        if raw.category.lower() == "null_safety" and severity == Severity.HIGH:
            evidence_text = (raw.evidence or "") + " " + (raw.description or "")
            if not re.search(
                r"NullPointerException|NPE|dereference|解引用|崩溃|crash|"
                r"\.get\([^)]*\)\s*\.|\.\w+\(\)\s*\.\w+",
                evidence_text,
                re.IGNORECASE,
            ):
                severity = Severity.MEDIUM

        # Map AI confidence (1-10) to enum
        if raw.confidence >= 8:
            confidence = Confidence.MEDIUM  # AI HIGH = system MEDIUM (conservative)
        elif raw.confidence >= 5:
            confidence = Confidence.LOW
        else:
            confidence = Confidence.LOW

        evidence = AIReviewEvidence(
            content=raw.evidence,
            file_path=file_path,
            line_start=raw.line_start,
            line_end=raw.line_end,
            source_engine="ai_deep_review",
            ai_confidence=raw.confidence,
            self_reflection=raw.self_reflection,
            review_dimension=raw.category,
        )

        # Generate a unique ID using file, line, and title hash.
        # Use os-agnostic basename extraction so Windows-style paths
        # ("src\\app.py") still yield "app.py" instead of the full path.
        basename = PurePosixPath(file_path.replace("\\", "/")).name or file_path
        short_hash = hashlib.sha256(
            f"{file_path}:{raw.line_start}:{raw.title}".encode()
        ).hexdigest()[:8]
        finding_id = f"AI-{basename}-L{raw.line_start}-{short_hash}"

        return Finding(
            id=finding_id,
            title=raw.title,
            category=category,
            severity=severity,
            confidence=confidence,
            location=Location(
                file_path=file_path,
                line_start=raw.line_start,
                line_end=raw.line_end,
            ),
            evidences=[evidence],
            fix_suggestion=raw.fix_suggestion,
            root_cause=raw.description,
            source_engine="ai_deep_review",
            evidence_level="suspected",
            verification_status="unverified",
            verification_summary="AI 深度审查发现，尚未通过本地规则或临时测试验证。",
            tags=["ai_review", raw.category],
        )


    def _find_local_finding(
        self, ai_finding: AIFindingRaw, file_path: str,
    ) -> Finding | None:
        """Return the existing local finding that overlaps with this AI finding."""
        key = f"{file_path}:{ai_finding.line_start}"
        if key in self._existing_by_location:
            return self._existing_by_location[key]

        # Fuzzy match: check nearby lines (±3)
        for offset in range(-3, 4):
            check_key = f"{file_path}:{ai_finding.line_start + offset}"
            if check_key in self._existing_by_location:
                return self._existing_by_location[check_key]

        return None

    def _is_confirmed_by_local(self, ai_finding: AIFindingRaw, file_path: str) -> bool:
        """Check if a local engine finding overlaps with this AI finding."""
        return self._find_local_finding(ai_finding, file_path) is not None


class MergeOutput:
    """Result of the merge operation."""

    def __init__(
        self,
        primary: list[Finding],
        supplementary: list[Finding],
        verified_local_finding_ids: list[str],
        total_chunks: int,
        done_chunks: int,
        skip_counts: dict[str, int],
        total_tokens_used: int = 0,
    ) -> None:
        self.primary = primary
        self.supplementary = supplementary
        self.verified_local_finding_ids = verified_local_finding_ids
        self.total_chunks = total_chunks
        self.done_chunks = done_chunks
        self.skip_counts = skip_counts
        self.total_tokens_used = total_tokens_used
        # These are set by pipeline after merge
        self.reviewer_usage: object = None  # TokenUsage from AIReviewer
        self.budget_max: int = 0
        self.budget_spent: int = 0

    @property
    def summary_line(self) -> str:
        """Human-readable summary for terminal output."""
        skip_detail = ", ".join(f"{count} {reason}" for reason, count in self.skip_counts.items())
        skip_part = f", {sum(self.skip_counts.values())} 跳过 ({skip_detail})" if self.skip_counts else ""
        return (
            f"AI Deep Review: {self.total_chunks} chunks 中 "
            f"{self.done_chunks} 完成{skip_part}"
        )
