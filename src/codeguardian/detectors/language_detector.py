"""LanguageDetector — identifies programming languages used in a project."""

from fnmatch import fnmatch
from pathlib import Path

from codeguardian.languages import (
    CONFIG_LANGUAGE_HINTS,
    language_from_path,
    normalize_language,
    sort_languages,
)


class LanguageDetector:
    """Detect programming languages from file extensions and config files."""

    def detect(self, root: Path) -> list[str]:
        ext_counts: dict[str, int] = {}
        lang_scores: dict[str, float] = {}

        for path in root.rglob("*"):
            if self._should_skip(path):
                continue
            if not path.is_file():
                continue

            detected_language = language_from_path(path)
            if detected_language is not None:
                ext_counts[detected_language] = ext_counts.get(detected_language, 0) + 1

            hint_languages = CONFIG_LANGUAGE_HINTS.get(path.name)
            if hint_languages is None:
                for pattern, pattern_languages in CONFIG_LANGUAGE_HINTS.items():
                    if "*" in pattern and fnmatch(path.name, pattern):
                        hint_languages = pattern_languages
                        break
            if hint_languages:
                for hint_language in hint_languages:
                    normalized = normalize_language(hint_language)
                    lang_scores[normalized] = lang_scores.get(normalized, 0.0) + 50.0


        for language, count in ext_counts.items():
            lang_scores[language] = lang_scores.get(language, 0.0) + float(count)

        detected = [language for language, score in lang_scores.items() if score >= 1]
        ordered = sort_languages(detected, lang_scores)
        return ordered or ["unknown"]

    @staticmethod
    def _should_skip(path: Path) -> bool:
        from codeguardian.utils.ignore import should_ignore
        return should_ignore(path)
