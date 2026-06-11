"""MetricsEngine — computes basic code metrics at project level.

Dimension 1 (continued): Scale Analyzer
"""

from __future__ import annotations

import re
from pathlib import Path

from codeguardian.core.context import ScanContext
from codeguardian.languages import (
    ALL_REGISTERED_LANGUAGES,
    is_language_enabled,
    language_from_path,
    language_priority_tier,
    sort_languages,
)
from codeguardian.models.metric import Metric, MetricNames
from codeguardian.models.scan import EngineResult
from codeguardian.utils.ignore import should_ignore

_DUPLICATION_BLOCK_SIZE = 6
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--")
_WHITESPACE_RE = re.compile(r"\s+")


class MetricsEngine:
    """Calculates basic quantitative metrics about the codebase."""

    name = "metrics"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root)
        selected_languages = ctx.languages or []
        language_counts: dict[str, int] = {language: 0 for language in ALL_REGISTERED_LANGUAGES}
        total_files = 0
        duplication_inputs: dict[str, list[str]] = {}

        for path in ctx.collect_candidate_files(root):
            if should_ignore(path) or not path.is_file():
                continue

            language = language_from_path(path)
            if selected_languages and not is_language_enabled(language, selected_languages):
                continue


            total_files += 1
            if language is not None:
                language_counts[language] = language_counts.get(language, 0) + 1
                normalized_lines = _normalized_code_lines(path)
                if normalized_lines:
                    duplication_inputs[str(path.relative_to(root)).replace("\\", "/")] = normalized_lines

        metrics: list[Metric] = [
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.FILE_COUNT,
                value=float(total_files),
                unit="files",
                source_engine=self.name,
                dimension="scale",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.DUPLICATION_RATE,
                value=_duplication_rate(duplication_inputs),
                unit="%",
                source_engine=self.name,
                dimension="scale",
            ),
        ]

        for language in sort_languages(
            [language for language, count in language_counts.items() if count > 0],
        ):
            metrics.append(
                Metric(
                    target_id=language,
                    target_type="language",
                    metric_name=MetricNames.FILE_COUNT,
                    value=float(language_counts[language]),
                    unit="files",
                    source_engine=self.name,
                    extra={"priority_tier": language_priority_tier(language)},
                )
            )

        return EngineResult(engine_name=self.name, metrics=metrics)


def _normalized_code_lines(path: Path) -> list[str]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    normalized: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue
        normalized.append(_WHITESPACE_RE.sub(" ", line))
    return normalized


def _duplication_rate(inputs: dict[str, list[str]]) -> float:
    total_lines = sum(len(lines) for lines in inputs.values())
    if total_lines == 0:
        return 0.0

    block_occurrences: dict[tuple[str, ...], list[tuple[str, int]]] = {}
    for file_path, lines in inputs.items():
        if len(lines) < _DUPLICATION_BLOCK_SIZE:
            continue
        for start in range(len(lines) - _DUPLICATION_BLOCK_SIZE + 1):
            block = tuple(lines[start:start + _DUPLICATION_BLOCK_SIZE])
            block_occurrences.setdefault(block, []).append((file_path, start))

    duplicated_lines_by_file: dict[str, set[int]] = {}
    for occurrences in block_occurrences.values():
        if len(occurrences) < 2:
            continue
        for file_path, start in occurrences:
            duplicated_lines_by_file.setdefault(file_path, set()).update(
                range(start, start + _DUPLICATION_BLOCK_SIZE)
            )

    duplicated_lines = sum(len(line_numbers) for line_numbers in duplicated_lines_by_file.values())
    return round(min(100.0, (duplicated_lines / total_lines) * 100.0), 1)
