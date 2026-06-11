"""Central language registry, normalization, and priority helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path

LANGUAGE_PRIORITY_GROUPS: tuple[tuple[str, ...], ...] = (
    ("cpp", "java", "go"),
    ("lua", "python", "csharp"),
    ("javascript", "typescript", "rust"),
)

LANGUAGE_ALIASES: dict[str, str] = {
    "c++": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "c#": "csharp",
    "cs": "csharp",
    "golang": "go",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "py": "python",
    "rs": "rust",
}

EXTENSION_LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".pyx": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".dart": "dart",
    ".lua": "lua",
    ".r": "r",
    ".m": "objective-c",
}

CONFIG_LANGUAGE_HINTS: dict[str, tuple[str, ...]] = {
    "pyproject.toml": ("python",),
    "setup.py": ("python",),
    "requirements.txt": ("python",),
    "Pipfile": ("python",),
    "setup.cfg": ("python",),
    "pom.xml": ("java",),
    "build.gradle": ("java",),
    "build.gradle.kts": ("java",),
    "package.json": ("javascript",),
    "tsconfig.json": ("typescript",),
    "go.mod": ("go",),
    "Cargo.toml": ("rust",),
    "Gemfile": ("ruby",),
    "composer.json": ("php",),
    "CMakeLists.txt": ("cpp",),
    "Makefile": ("cpp",),
    "meson.build": ("cpp",),
    "*.csproj": ("csharp",),
    "*.sln": ("csharp",),
}

_PRIORITY_ORDER: dict[str, tuple[int, int]] = {
    language: (tier, position)
    for tier, group in enumerate(LANGUAGE_PRIORITY_GROUPS, start=1)
    for position, language in enumerate(group, start=1)
}


ALL_REGISTERED_LANGUAGES: tuple[str, ...] = tuple(
    sorted({*EXTENSION_LANGUAGE_MAP.values(), *(lang for group in LANGUAGE_PRIORITY_GROUPS for lang in group)})
)


def normalize_language(language: str) -> str:
    """Normalize aliases and case differences to a canonical language id."""
    normalized = language.strip().lower()
    return LANGUAGE_ALIASES.get(normalized, normalized)



def normalize_languages(languages: Iterable[str] | None) -> list[str]:
    """Normalize and de-duplicate a language list while preserving priority order."""
    if not languages:
        return []

    seen: set[str] = set()
    normalized: list[str] = []
    for item in languages:
        candidate = normalize_language(item)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return sort_languages(normalized)



def language_from_extension(extension: str) -> str | None:
    """Resolve a file extension to a canonical language id."""
    normalized = extension.lower().strip()
    if not normalized:
        return None
    if not normalized.startswith("."):
        normalized = f".{normalized}"
    return EXTENSION_LANGUAGE_MAP.get(normalized)



def language_from_path(path: Path) -> str | None:
    """Resolve a file path to a canonical language id."""
    return language_from_extension(path.suffix)



def language_priority_tier(language: str) -> int | None:
    """Return the configured priority tier for a language, if any."""
    normalized = normalize_language(language)
    priority = _PRIORITY_ORDER.get(normalized)
    return priority[0] if priority is not None else None



def language_priority_key(language: str) -> tuple[int, int, str]:
    """Sorting key that prefers user-target languages first."""
    normalized = normalize_language(language)
    tier, position = _PRIORITY_ORDER.get(normalized, (len(LANGUAGE_PRIORITY_GROUPS) + 1, 999))
    return tier, position, normalized



def sort_languages(languages: Iterable[str], scores: Mapping[str, float] | None = None) -> list[str]:
    """Sort languages by score first, then configured priority tiers."""
    unique = {normalize_language(language) for language in languages if language.strip()}

    def score_for(language: str) -> float:
        if scores is None:
            return 0.0
        return float(scores.get(language, scores.get(normalize_language(language), 0.0)))

    return sorted(unique, key=lambda language: (-score_for(language), *language_priority_key(language)))



def is_language_enabled(language: str | None, selected_languages: Iterable[str] | None) -> bool:
    """Return whether a language should be analyzed in the current scan."""
    normalized_selection = {normalize_language(item) for item in selected_languages or [] if item.strip()}
    if not normalized_selection:
        return True
    if language is None:
        return False
    return normalize_language(language) in normalized_selection



def extensions_for_languages(languages: Iterable[str]) -> set[str]:
    """Return all known file extensions for the given languages."""
    normalized_selection = {normalize_language(language) for language in languages if language.strip()}
    return {
        extension
        for extension, language in EXTENSION_LANGUAGE_MAP.items()
        if language in normalized_selection
    }



def sort_paths_by_language_priority(paths: Iterable[Path]) -> list[Path]:
    """Sort file paths so higher-priority languages are scanned first."""
    return sorted(
        paths,
        key=lambda path: (*language_priority_key(language_from_path(path) or ""), str(path).lower()),
    )
