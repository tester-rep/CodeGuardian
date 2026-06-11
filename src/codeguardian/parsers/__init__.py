"""Source parser implementations used by analysis engines."""

from codeguardian.parsers.base import (
    ParsedClass,
    ParsedFunction,
    ParsedModule,
    ParsedStructure,
    SourceParser,
)
from codeguardian.parsers.factory import get_parser
from codeguardian.parsers.python_parser import PythonSourceParser
from codeguardian.parsers.tree_sitter_parser import TreeSitterSourceParser
from codeguardian.parsers.tree_sitter_support import (
    SUPPORTED_TREE_SITTER_LANGUAGES,
    TreeSitterDocument,
    get_tree_sitter_document,
)

__all__ = [
    "ParsedClass",
    "ParsedFunction",
    "ParsedModule",
    "ParsedStructure",
    "SourceParser",
    "HeuristicSourceParser",
    "PythonSourceParser",
    "TreeSitterDocument",
    "TreeSitterSourceParser",

    "SUPPORTED_TREE_SITTER_LANGUAGES",
    "get_parser",
    "get_tree_sitter_document",
]

