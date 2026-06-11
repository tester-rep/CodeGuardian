"""Suspicion queue persistence for two-stage AI deep review."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from codeguardian.ai.deep_review.models import AIFindingRaw, ReviewResult

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(slots=True)
class Suspicion:
    """A scout-model finding queued for optional professional second review."""

    file_path: str
    line_start: int
    line_end: int
    title: str
    category: str
    severity: str
    confidence: int
    description: str = ""
    evidence: str = ""
    fix_suggestion: str = ""
    chunk_qualified_name: str = ""
    source_model: str = ""
    priority_score: float = 0.0


def build_suspicions(
    results: list[ReviewResult],
    *,
    min_confidence: int = 3,
    max_suspicions: int = 500,
    source_model: str = "",
) -> list[Suspicion]:
    """Convert scout ReviewResults into a ranked suspicion list."""
    suspicions: list[Suspicion] = []
    seen: set[tuple[str, int, int, str]] = set()
    for result in results:
        if result.status != "done":
            continue
        for finding in result.findings:
            if finding.confidence < min_confidence:
                continue
            key = (result.chunk_file_path, finding.line_start, finding.line_end, finding.title)
            if key in seen:
                continue
            seen.add(key)
            suspicions.append(_to_suspicion(finding, result, source_model))

    suspicions.sort(key=lambda item: item.priority_score, reverse=True)
    return suspicions[:max_suspicions]


def save_suspicion_queue(project_root: Path, suspicions: list[Suspicion]) -> Path:
    """Persist suspicions as JSONL under .codeguardian/deep_review/."""
    queue_dir = project_root / ".codeguardian" / "deep_review"
    queue_dir.mkdir(parents=True, exist_ok=True)
    queue_path = queue_dir / "suspicion_queue.jsonl"
    payload = "\n".join(json.dumps(asdict(item), ensure_ascii=False) for item in suspicions)
    queue_path.write_text(payload + ("\n" if payload else ""), encoding="utf-8")
    return queue_path


def _to_suspicion(finding: AIFindingRaw, result: ReviewResult, source_model: str) -> Suspicion:
    severity = (finding.severity or "medium").lower()
    severity_score = _SEVERITY_RANK.get(severity, 2) * 10
    confidence_score = max(1, min(10, finding.confidence))
    category_bonus = 4 if finding.category in {"security", "logic", "error_handling"} else 0
    priority_score = float(severity_score + confidence_score + category_bonus)
    return Suspicion(
        file_path=result.chunk_file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        title=finding.title,
        category=finding.category,
        severity=severity,
        confidence=finding.confidence,
        description=finding.description,
        evidence=finding.evidence,
        fix_suggestion=finding.fix_suggestion,
        chunk_qualified_name=result.chunk_qualified_name,
        source_model=source_model,
        priority_score=priority_score,
    )
