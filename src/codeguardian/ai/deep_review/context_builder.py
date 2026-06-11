"""ContextPackBuilder — builds per-chunk context for AI review.

Assembles a ContextPack containing:
1. Target code (the chunk itself)
2. Dependency signatures from the same file (MVP scope)
3. Local engine findings for the chunk's code range
4. Custom project review rules
"""

from __future__ import annotations

import logging
from pathlib import Path

from codeguardian.ai.deep_review.models import CodeChunk, ContextPack
from codeguardian.ai.deep_review.project_index import ProjectIndex

logger = logging.getLogger(__name__)


class ContextPackBuilder:
    """Build AI context packs for code chunks."""

    def __init__(
        self,
        project_index: ProjectIndex,
        local_findings: dict[str, list[dict[str, object]]] | None = None,
        custom_rules: str = "",
        extra_notes_by_file: dict[str, list[str]] | None = None,
    ) -> None:
        self._index = project_index
        self._local_findings = local_findings or {}
        self._custom_rules = custom_rules
        self._extra_notes_by_file = extra_notes_by_file or {}


    def build(self, chunk: CodeChunk) -> ContextPack:
        """Assemble a ContextPack for the given chunk."""
        pack = ContextPack(
            target_code=chunk.source_code,
            file_path=chunk.file_path,
            function_name=chunk.qualified_name,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
            language=chunk.language,
        )

        # Dependency signatures from same file (MVP: same-file only)
        sigs = self._index.get_file_signatures(chunk.file_path)
        # Exclude the chunk's own signature to avoid redundancy
        pack.dependency_signatures = [
            sig for sig in sigs
            if chunk.qualified_name not in sig
        ][:10]  # Cap at 10 to keep context lean

        # Local findings overlapping with this chunk
        pack.local_findings_summary = self._build_local_findings_section(chunk)

        # Custom project rules
        pack.custom_rules = self._custom_rules

        # Extra notes, e.g. scout suspicions for professional second review
        pack.notes.extend(self._extra_notes_by_file.get(chunk.file_path, [])[:8])

        return pack


    def _build_local_findings_section(self, chunk: CodeChunk) -> str:
        """Summarize local engine findings that overlap with this chunk."""
        file_findings = self._local_findings.get(chunk.file_path, [])
        if not file_findings:
            return "无本地引擎发现"

        relevant: list[str] = []
        for finding in file_findings:
            f_line = finding.get("line_start", 0)
            f_end = finding.get("line_end", f_line)
            # Check overlap with chunk range
            if isinstance(f_line, int) and isinstance(f_end, int):
                if f_line <= chunk.line_end and f_end >= chunk.line_start:
                    fid = finding.get("id", "?")
                    title = finding.get("title", "")
                    severity = finding.get("severity", "")
                    relevant.append(f"- [{fid}] {title} (severity={severity}, L{f_line})")

        if not relevant:
            return "该代码范围内无本地引擎发现"

        return "\n".join(relevant)


def load_custom_rules(project_root: Path) -> str:
    """Load custom review rules from .codeguardian/review_rules.yaml if present."""
    rules_path = project_root / ".codeguardian" / "review_rules.yaml"
    if not rules_path.is_file():
        return ""

    try:
        import yaml

        data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return ""

        rules = data.get("rules", [])
        if not rules:
            return ""

        return "\n".join(f"- {rule}" for rule in rules)
    except Exception:
        logger.debug("Failed to load custom review rules from %s", rules_path, exc_info=True)
        return ""
