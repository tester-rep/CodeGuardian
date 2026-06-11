"""Parser registry for language-specific source parsing."""

from __future__ import annotations

from codeguardian.parsers.base import SourceParser
from codeguardian.parsers.heuristic_parser import HeuristicSourceParser
from codeguardian.parsers.python_parser import PythonSourceParser
from codeguardian.parsers.tree_sitter_parser import TreeSitterSourceParser

_PARSERS: dict[str, SourceParser] = {
    "python": PythonSourceParser(),
    "java": TreeSitterSourceParser("java"),
    "javascript": TreeSitterSourceParser("javascript"),
    "typescript": TreeSitterSourceParser("typescript"),
    "go": TreeSitterSourceParser("go"),
    "cpp": TreeSitterSourceParser("cpp"),
    "csharp": HeuristicSourceParser("csharp"),
    "lua": HeuristicSourceParser("lua"),
    "rust": HeuristicSourceParser("rust"),
}



def get_parser(language: str) -> SourceParser | None:
    """Return a parser instance for the requested language, if supported."""
    return _PARSERS.get(language.lower())

