"""ProjectIndex — lightweight symbol index for AI context building.

MVP scope: index function/class signatures from the same file.
Phase 2 will expand to cross-file call graph analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from codeguardian.parsers.base import ParsedClass, ParsedFunction, ParsedStructure
from codeguardian.parsers.tree_sitter_support import TreeSitterManager

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FunctionSignature:
    """Lightweight function signature (no body)."""

    name: str
    qualified_name: str
    file_path: str
    signature: str  # e.g. "def process_order(order_id: int, amount: float) -> bool"
    line_start: int = 0


@dataclass(slots=True)
class ClassSignature:
    """Lightweight class signature."""

    name: str
    file_path: str
    methods: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)


class ProjectIndex:
    """Lightweight project symbol index built from tree-sitter.

    Used by ContextPackBuilder to provide dependency signatures
    for AI context packs.

    MVP: indexes signatures within each file independently.
    """

    def __init__(self) -> None:
        self._functions: dict[str, FunctionSignature] = {}  # qualified_name → sig
        self._classes: dict[str, ClassSignature] = {}  # qualified_name → sig
        self._file_functions: dict[str, list[str]] = {}  # file_path → [qualified_names]

    @property
    def function_count(self) -> int:
        return len(self._functions)

    @property
    def class_count(self) -> int:
        return len(self._classes)

    def build_from_structures(
        self,
        structures: dict[str, ParsedStructure],
    ) -> None:
        """Build index from pre-parsed structures.

        Parameters
        ----------
        structures : dict[str, ParsedStructure]
            Mapping of relative file path → parsed structure.
        """
        for file_path, structure in structures.items():
            func_names: list[str] = []

            for func in structure.functions:
                qname = f"{file_path}:{func.class_or_module}.{func.name}" if func.class_or_module else f"{file_path}:{func.name}"
                sig = func.signature or f"{func.name}()"
                self._functions[qname] = FunctionSignature(
                    name=func.name,
                    qualified_name=qname,
                    file_path=file_path,
                    signature=sig,
                    line_start=func.start_line or 0,
                )
                func_names.append(qname)

            for cls in structure.classes:
                qname = f"{file_path}:{cls.name}"
                self._classes[qname] = ClassSignature(
                    name=cls.name,
                    file_path=file_path,
                    methods=cls.methods,
                    fields=cls.fields,
                )

            self._file_functions[file_path] = func_names

    def get_file_signatures(self, file_path: str) -> list[str]:
        """Return all function signatures in the same file (for context)."""
        func_names = self._file_functions.get(file_path, [])
        sigs: list[str] = []
        for qname in func_names:
            func = self._functions.get(qname)
            if func:
                sigs.append(func.signature)
        return sigs

    def get_function_signature(self, qualified_name: str) -> str | None:
        """Look up a function signature by qualified name."""
        func = self._functions.get(qualified_name)
        return func.signature if func else None

    def get_class_info(self, file_path: str, class_name: str) -> ClassSignature | None:
        """Look up a class by file path and name."""
        return self._classes.get(f"{file_path}:{class_name}")
