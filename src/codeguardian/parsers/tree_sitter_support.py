"""tree-sitter language loading and parsed document helpers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tree_sitter import Language as TreeSitterLanguage
    from tree_sitter import Node as TreeSitterNode
    from tree_sitter import Tree as TreeSitterTree
else:
    TreeSitterLanguage = TreeSitterNode = TreeSitterTree = Any

try:
    import tree_sitter_java
    import tree_sitter_javascript
    import tree_sitter_python
    import tree_sitter_typescript
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - optional dependency fallback
    Language = None  # type: ignore[assignment]
    Parser = None  # type: ignore[assignment]
    tree_sitter_java = None  # type: ignore[assignment]
    tree_sitter_javascript = None  # type: ignore[assignment]
    tree_sitter_python = None  # type: ignore[assignment]
    tree_sitter_typescript = None  # type: ignore[assignment]

try:
    import tree_sitter_cpp  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    tree_sitter_cpp = None  # type: ignore[assignment]

try:
    import tree_sitter_go  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    tree_sitter_go = None  # type: ignore[assignment]

try:
    import tree_sitter_lua  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    tree_sitter_lua = None  # type: ignore[assignment]

try:
    import tree_sitter_c_sharp  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    tree_sitter_c_sharp = None  # type: ignore[assignment]


@dataclass(slots=True)
class TreeSitterDocument:
    """Parsed source document backed by a tree-sitter syntax tree."""

    language: str
    path: Path
    project_root: Path
    source: str
    tree: TreeSitterTree

    @property
    def relative_path(self) -> str:
        return str(self.path.relative_to(self.project_root)).replace("\\", "/")

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    @property
    def root_node(self) -> TreeSitterNode:
        return self.tree.root_node

    def text_for(self, node: TreeSitterNode) -> str:
        # tree-sitter offsets (start_byte/end_byte) are BYTE offsets, but
        # ``self.source`` is a ``str`` indexed by CHARACTERS. Slicing the str with
        # byte offsets misaligns extraction for any file containing non-ASCII
        # (multi-byte UTF-8) characters — e.g. Chinese comments — corrupting every
        # symbol name/type extracted after the first such character. Use the node's
        # own byte content, which is always the exact source bytes for that node.
        raw = node.text
        if raw is not None:
            return raw.decode("utf-8", errors="ignore")
        return self.source.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def line_range(self, node: TreeSitterNode) -> tuple[int, int]:
        return node.start_point.row + 1, node.end_point.row + 1


class TreeSitterManager:
    """Loads tree-sitter language grammars and parses source files."""

    def __init__(self) -> None:
        self._languages: dict[str, TreeSitterLanguage] = {}

    def is_supported(self, language: str) -> bool:
        return language.lower() in _LANGUAGE_LOADERS

    def parse_file(self, path: Path, project_root: Path, language: str) -> TreeSitterDocument | None:
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        return self.parse_source(source, path, project_root, language)

    def parse_source(
        self,
        source: str,
        path: Path,
        project_root: Path,
        language: str,
    ) -> TreeSitterDocument | None:
        parser = self._build_parser(language)
        if parser is None:
            return None
        tree = parser.parse(source.encode("utf-8"))
        return TreeSitterDocument(
            language=language,
            path=path,
            project_root=project_root,
            source=source,
            tree=tree,
        )

    def _build_parser(self, language: str) -> Any | None:
        tree_sitter_language = self._load_language(language)
        if tree_sitter_language is None or Parser is None:
            return None

        parser = Parser()
        parser.language = tree_sitter_language
        return parser

    def _load_language(self, language: str) -> TreeSitterLanguage | None:
        normalized = language.lower()
        if normalized in self._languages:
            return self._languages[normalized]

        loader = _LANGUAGE_LOADERS.get(normalized)
        if loader is None:
            return None

        loaded = loader()
        if loaded is None:
            return None

        self._languages[normalized] = loaded
        return loaded



def _load_python_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_python is None:
        return None
    return Language(tree_sitter_python.language())



def _load_java_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_java is None:
        return None
    return Language(tree_sitter_java.language())



def _load_javascript_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_javascript is None:
        return None
    return Language(tree_sitter_javascript.language())



def _load_typescript_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_typescript is None:
        return None
    return Language(tree_sitter_typescript.language_typescript())



def _load_cpp_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_cpp is None:
        return None
    return Language(tree_sitter_cpp.language())



def _load_go_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_go is None:
        return None
    return Language(tree_sitter_go.language())



def _load_lua_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_lua is None:
        return None
    return Language(tree_sitter_lua.language())


def _load_csharp_language() -> TreeSitterLanguage | None:
    if Language is None or tree_sitter_c_sharp is None:
        return None
    return Language(tree_sitter_c_sharp.language())


_LANGUAGE_LOADERS: dict[str, Callable[[], TreeSitterLanguage | None]] = {
    "python": _load_python_language,
    "java": _load_java_language,
    "javascript": _load_javascript_language,
    "typescript": _load_typescript_language,
    "cpp": _load_cpp_language,
    "go": _load_go_language,
    "lua": _load_lua_language,
    "csharp": _load_csharp_language,
}

SUPPORTED_TREE_SITTER_LANGUAGES = frozenset(_LANGUAGE_LOADERS)
TREE_SITTER_MANAGER = TreeSitterManager()

# Parse cache: avoids re-parsing same file across multiple engines (defect, security, perf, OO)
_PARSE_CACHE: dict[tuple[Path, str], TreeSitterDocument | None] = {}
_PARSE_CACHE_MAX = 2048


def get_tree_sitter_document(path: Path, project_root: Path, language: str) -> TreeSitterDocument | None:
    """Parse a file with tree-sitter and return its typed document wrapper.

    Results are cached by (path, language) — safe because file content doesn't change mid-scan.
    Multiple engines calling this for the same file reuse the parsed AST.
    """
    cache_key = (path, language)
    if cache_key in _PARSE_CACHE:
        return _PARSE_CACHE[cache_key]

    result = TREE_SITTER_MANAGER.parse_file(path, project_root, language)

    if len(_PARSE_CACHE) < _PARSE_CACHE_MAX:
        _PARSE_CACHE[cache_key] = result

    return result


def clear_parse_cache() -> None:
    """Clear the parse cache (call between scans or in tests)."""
    _PARSE_CACHE.clear()
