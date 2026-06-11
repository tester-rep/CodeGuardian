"""Code filtering — decides what enters the AI review pipeline.

Three filtering layers:
1. File-level: skip generated code, vendors, tests, config files
2. Content-level: skip files with auto-generated markers
3. Function-level: skip trivial getters/setters
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# === File-level patterns (glob) ===
SKIP_FILE_PATTERNS: list[str] = [
    # Generated code
    "*/generated/*",
    "*/gen/*",
    "*_generated.*",
    "*.pb.go",
    "*/R.java",
    "*/BuildConfig.java",
    "*/migrations/*",
    # Dependencies / vendor
    "*/vendor/*",
    "vendor/*",
    "*/node_modules/*",
    "node_modules/*",
    "*/third_party/*",
    "third_party/*",
    # SDK / runtime / system code (never spend AI tokens on these)
    "*/jdk/*",
    "*/jre/*",
    "*/sdk/*",
    "*/jdk-*/*",
    "*/jre-*/*",
    "*/openjdk*/*",
    "*/graalvm*/*",
    "*/dotnet/*",
    "*/Program Files/*",
    "*/Program Files (x86)/*",
    # Build artifacts
    "*/build/*",
    "*/dist/*",
    "*/target/*",
    # Config / resource files
    "*.json",
    "*.xml",
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.properties",
    "*.ini",
    "*.cfg",
    # Tests (usually not needed for AI security/performance review)
    "*/test/*",
    "*/tests/*",
    "*_test.*",
    "*_spec.*",
    "*/testdata/*",
    "*/fixtures/*",
]

# === Finding categories considered LOW VALUE for AI deep review ===
#
# These categories come from local engines whose conclusions are already
# threshold-based and deterministic (e.g. complexity / oo_design /
# git_evolution / dependency). Sending them through the LLM rarely produces
# new actionable insights but burns a lot of tokens because every chunk
# co-located with such a finding gets escalated to P0.
#
# Findings of these categories STILL appear in the final report — they are
# only excluded from the "has_local_findings → P0 escalation" rule that
# governs deep_review's LLM feeding pipeline.
LOW_VALUE_FINDING_CATEGORIES: frozenset[str] = frozenset({
    "maintainability",
    "architecture",
})

# === Content markers that indicate auto-generated files ===
SKIP_FILE_MARKERS: list[str] = [
    "// Code generated",
    "// AUTO-GENERATED",
    "@Generated",
    "# This file is auto-generated",
    "# DO NOT EDIT",
    "/* Auto-generated",
]


class CodeFilter:
    """Decides which code units should enter the AI review pipeline."""

    def __init__(
        self,
        skip_patterns: list[str] | None = None,
        skip_markers: list[str] | None = None,
    ) -> None:
        self._skip_patterns = skip_patterns or SKIP_FILE_PATTERNS
        self._skip_markers = skip_markers or SKIP_FILE_MARKERS

    def should_skip_file(self, rel_path: str) -> bool:
        """File-level filter: check against glob patterns."""
        normalized = rel_path.replace("\\", "/")
        return any(
            fnmatch.fnmatch(normalized, pattern) for pattern in self._skip_patterns
        )

    def should_skip_by_content(self, source: str, max_check_lines: int = 10) -> bool:
        """Content-level filter: check first N lines for auto-generated markers."""
        lines = source.split("\n", max_check_lines)[:max_check_lines]
        header = "\n".join(lines)
        return any(marker in header for marker in self._skip_markers)

    def should_skip_function(
        self,
        *,
        line_count: int,
        complexity: int,
        name: str = "",
    ) -> bool:
        """Function-level filter: skip trivial functions."""
        # Trivial getters/setters/toString/equals
        trivial_prefixes = ("get", "set", "is", "has", "to_string", "toString", "equals", "hashCode", "__repr__", "__str__", "__eq__", "__hash__")
        if line_count <= 5 and complexity <= 1:
            if any(name.startswith(p) or name.endswith(p) for p in trivial_prefixes):
                return True
            # Even without matching prefix, <=3 lines with no complexity is trivial
            if line_count <= 3:
                return True
        return False

    def classify_priority(
        self,
        *,
        has_local_findings: bool = False,
        is_security_sensitive: bool = False,
        is_changed: bool = False,
        complexity: int = 0,
        nesting_depth: int = 0,
        line_count: int = 0,
        has_todo: bool = False,
    ) -> int:
        """Assign review priority (0=P0 highest, 1=P1, 2=P2).

        Based on design doc section 四 送审规则.
        """
        # P0 — must review
        if has_local_findings or is_security_sensitive or is_changed:
            return 0

        # P1 — should review
        if complexity >= 15 or nesting_depth >= 5:
            return 1

        # P2 — review if budget allows
        if complexity >= 10 or line_count > 80 or has_todo:
            return 2

        # Default — lowest priority, will be cut by budget
        return 2
