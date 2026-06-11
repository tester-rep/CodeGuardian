"""Smart code chunker — splits source files into reviewable units.

Chunking strategy (from design doc section 三):
- File < 300 lines → whole file as one chunk
- Class < 200 lines → whole class as one chunk
- Class >= 200 lines → split into function-level chunks
"""

from __future__ import annotations

import logging
from pathlib import Path

from codeguardian.ai.deep_review.filter import CodeFilter
from codeguardian.ai.deep_review.models import CodeChunk
from codeguardian.parsers.tree_sitter_support import (
    TreeSitterDocument,
    TreeSitterManager,
)

logger = logging.getLogger(__name__)

# Thresholds from design doc section 三
FILE_CHUNK_THRESHOLD = 300  # lines
CLASS_CHUNK_THRESHOLD = 200  # lines


class Chunker:
    """Splits source files into CodeChunk units for AI review."""

    def __init__(
        self,
        code_filter: CodeFilter | None = None,
        ts_manager: TreeSitterManager | None = None,
    ) -> None:
        self._filter = code_filter or CodeFilter()
        self._ts = ts_manager or TreeSitterManager()

    def chunk_file(
        self,
        path: Path,
        project_root: Path,
        language: str,
        *,
        changed_lines: set[int] | None = None,
    ) -> list[CodeChunk]:
        """Produce code chunks for a single file.

        Parameters
        ----------
        path : Path
            Absolute path to the source file.
        project_root : Path
            Project root for relative path computation.
        language : str
            Programming language identifier.
        changed_lines : set[int] | None
            If incremental mode, the set of changed line numbers.
        """
        rel_path = str(path.relative_to(project_root)).replace("\\", "/")

        # File-level filter
        if self._filter.should_skip_file(rel_path):
            return []

        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        if not source.strip():
            return []

        # Content-level filter
        if self._filter.should_skip_by_content(source):
            return []

        line_count = source.count("\n") + 1

        # Try AST-based chunking
        doc = self._ts.parse_source(source, path, project_root, language)
        if doc is None:
            # Fallback: treat whole file as one chunk if small enough
            if line_count <= FILE_CHUNK_THRESHOLD:
                return [
                    CodeChunk(
                        file_path=rel_path,
                        source_code=source,
                        language=language,
                        line_start=1,
                        line_end=line_count,
                        chunk_type="file",
                        loc=line_count,
                    )
                ]
            return []

        # Small file → whole file chunk
        if line_count <= FILE_CHUNK_THRESHOLD:
            return [
                CodeChunk(
                    file_path=rel_path,
                    source_code=source,
                    language=language,
                    line_start=1,
                    line_end=line_count,
                    chunk_type="file",
                    loc=line_count,
                )
            ]

        # Larger file → try class-level then function-level
        return self._chunk_by_ast(doc, rel_path, language, changed_lines)

    def _chunk_by_ast(
        self,
        doc: TreeSitterDocument,
        rel_path: str,
        language: str,
        changed_lines: set[int] | None,
    ) -> list[CodeChunk]:
        """Extract chunks from AST: classes then standalone functions."""
        chunks: list[CodeChunk] = []
        root = doc.root_node

        # Collect class nodes
        class_nodes = _find_class_nodes(root, language)
        class_ranges: set[tuple[int, int]] = set()

        for cls_node in class_nodes:
            cls_start, cls_end = doc.line_range(cls_node)
            cls_lines = cls_end - cls_start + 1
            class_ranges.add((cls_start, cls_end))

            if cls_lines <= CLASS_CHUNK_THRESHOLD:
                # Whole class as a single chunk
                chunks.append(
                    CodeChunk(
                        file_path=rel_path,
                        source_code=doc.text_for(cls_node),
                        language=language,
                        line_start=cls_start,
                        line_end=cls_end,
                        chunk_type="class",
                        qualified_name=_extract_name(cls_node, language),
                        loc=cls_lines,
                    )
                )
            else:
                # Split class into method-level chunks
                method_nodes = _find_function_nodes(cls_node, language)
                cls_signature = _extract_class_signature(doc, cls_node, language)
                for method in method_nodes:
                    m_start, m_end = doc.line_range(method)
                    m_name = _extract_name(method, language)
                    cls_name = _extract_name(cls_node, language)
                    qualified = f"{cls_name}.{m_name}" if cls_name else m_name
                    # Prepend class signature as context
                    method_source = f"// Class context:\n{cls_signature}\n\n{doc.text_for(method)}"
                    chunks.append(
                        CodeChunk(
                            file_path=rel_path,
                            source_code=method_source,
                            language=language,
                            line_start=m_start,
                            line_end=m_end,
                            chunk_type="function",
                            qualified_name=qualified,
                            loc=m_end - m_start + 1,
                        )
                    )

        # Standalone functions (not inside a class)
        top_functions = _find_function_nodes(root, language)
        for fn_node in top_functions:
            fn_start, fn_end = doc.line_range(fn_node)
            # Skip functions that are inside a class range
            if any(cs <= fn_start and fn_end <= ce for cs, ce in class_ranges):
                continue
            fn_name = _extract_name(fn_node, language)
            fn_lines = fn_end - fn_start + 1

            # Apply function-level filter
            if self._filter.should_skip_function(line_count=fn_lines, complexity=0, name=fn_name):
                continue

            chunks.append(
                CodeChunk(
                    file_path=rel_path,
                    source_code=doc.text_for(fn_node),
                    language=language,
                    line_start=fn_start,
                    line_end=fn_end,
                    chunk_type="function",
                    qualified_name=fn_name,
                    loc=fn_lines,
                )
            )

        # If incremental, mark changed chunks as higher priority
        if changed_lines:
            for chunk in chunks:
                chunk_lines = set(range(chunk.line_start, chunk.line_end + 1))
                if chunk_lines & changed_lines:
                    chunk.priority = 0  # P0 — changed code

        return chunks


# ---------------------------------------------------------------------------
# AST node helpers (language-agnostic via tree-sitter node types)
# ---------------------------------------------------------------------------

_CLASS_TYPES = frozenset({
    "class_definition",       # Python
    "class_declaration",      # Java, JS/TS, C++
    "struct_specifier",       # C++
    "interface_declaration",  # Java/TS
    "type_declaration",       # Go
})

_FUNCTION_TYPES = frozenset({
    "function_definition",     # Python, C++
    "function_declaration",    # JS, C++, Go
    "method_definition",       # Python
    "method_declaration",      # Java
    "arrow_function",          # JS/TS
    "function_item",           # Rust
})


def _find_class_nodes(root_node: object, language: str) -> list[object]:
    """Find all top-level class/struct nodes."""
    results: list[object] = []
    for child in root_node.children:  # type: ignore[attr-defined]
        if child.type in _CLASS_TYPES:  # type: ignore[attr-defined]
            results.append(child)
    return results


def _find_function_nodes(parent_node: object, language: str) -> list[object]:
    """Find direct child function/method nodes."""
    results: list[object] = []
    _collect_functions(parent_node, results, depth=0)
    return results


def _collect_functions(node: object, results: list[object], depth: int) -> None:
    """Recursively collect function nodes (limited depth to avoid deep nesting)."""
    if depth > 3:
        return
    for child in node.children:  # type: ignore[attr-defined]
        if child.type in _FUNCTION_TYPES:  # type: ignore[attr-defined]
            results.append(child)
        elif child.type in ("class_body", "block", "declaration_list", "source_file"):  # type: ignore[attr-defined]
            _collect_functions(child, results, depth + 1)


def _extract_name(node: object, language: str) -> str:
    """Extract the identifier name from a class/function node."""
    for child in node.children:  # type: ignore[attr-defined]
        if child.type in ("identifier", "name", "property_identifier", "type_identifier"):  # type: ignore[attr-defined]
            return child.text.decode("utf-8") if isinstance(child.text, bytes) else str(child.text)  # type: ignore[attr-defined]
    return ""


def _extract_class_signature(doc: TreeSitterDocument, cls_node: object, language: str) -> str:
    """Extract just the class signature (first few lines) as context."""
    text = doc.text_for(cls_node)  # type: ignore[arg-type]
    lines = text.split("\n")
    # Take first 5 lines as signature context
    sig_lines = lines[:5]
    if len(lines) > 5:
        sig_lines.append("    // ... (methods omitted)")
    return "\n".join(sig_lines)
