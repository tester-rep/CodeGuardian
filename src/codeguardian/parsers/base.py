"""Parser abstractions for extracting source structure data."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(slots=True)
class ParsedFunction:
    """Language-agnostic function descriptor extracted from source."""

    name: str
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    signature: str | None = None
    class_or_module: str | None = None
    is_method: bool = False
    is_async: bool = False
    param_count: int = 0
    loc: int = 0


@dataclass(slots=True)
class ParsedClass:
    """Language-agnostic class descriptor extracted from source."""

    name: str
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    kind: str = "class"
    methods: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    # Field name -> declared type name (e.g. {"accountDao": "AccountDao"}).
    # Used by PCI to resolve `field.method()` receiver types precisely.
    field_types: dict[str, str] = field(default_factory=dict)
    # Direct superclass names (extends). Interface-only bases go in `interfaces`.
    bases: list[str] = field(default_factory=list)
    # Implemented/extended interface names (implements, TS `implements`).
    interfaces: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ParsedModule:
    """Language-agnostic module descriptor extracted from source."""

    name: str
    path: str
    module_type: str = "module"
    file_paths: list[str] = field(default_factory=list)
    language: str | None = None


@dataclass(slots=True)
class ParsedStructure:
    """Aggregated structural data parsed from a single file."""

    functions: list[ParsedFunction] = field(default_factory=list)
    classes: list[ParsedClass] = field(default_factory=list)
    modules: list[ParsedModule] = field(default_factory=list)


class SourceParser(Protocol):
    """Protocol that language-specific source parsers must implement."""

    language: str

    def parse_file(self, path: Path, project_root: Path) -> ParsedStructure:
        """Parse a source file and return extracted structure data."""
        ...
