"""Heuristic source parser for languages without full AST integration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from codeguardian.parsers.base import ParsedClass, ParsedFunction, ParsedModule, ParsedStructure

_CPP_CLASS_RE = re.compile(r"^\s*(class|struct|enum)\s+([A-Za-z_]\w*)")
_CSHARP_CLASS_RE = re.compile(
    r"^\s*(?:public|private|protected|internal|abstract|sealed|static|partial\s+)*(class|interface|record|struct|enum)\s+([A-Za-z_]\w*)"
)
_GO_CLASS_RE = re.compile(r"^\s*type\s+([A-Za-z_]\w*)\s+(struct|interface)\b")
_RUST_CLASS_RE = re.compile(r"^\s*(?:pub\s+)?(struct|enum|trait)\s+([A-Za-z_]\w*)\b")
_RUST_IMPL_RE = re.compile(r"^\s*impl(?:<[^>]+>)?\s+([A-Za-z_]\w*)\b")

_GO_FUNCTION_RE = re.compile(
    r"^\s*func\s*(?:\(\s*[A-Za-z_]\w*\s+\*?([A-Za-z_]\w*)\s*\))?\s*([A-Za-z_]\w*)\s*\(([^)]*)\)"
)
_CPP_FUNCTION_RE = re.compile(
    r"^\s*(?!if\b|for\b|while\b|switch\b|catch\b|return\b)(?:template\s*<[^>]+>\s*)?(?:[\w:<>~*&\[\]\s]+)\s+([A-Za-z_~]\w*)\s*\(([^;{}]*)\)\s*(?:const\b[^{}]*)?(?:\{|$)"
)
_CSHARP_FUNCTION_RE = re.compile(
    r"^\s*(?:public|private|protected|internal|static|virtual|override|async|sealed|partial|unsafe|extern|new\s+)+[\w<>,\[\]?\.]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"
)
_RUST_FUNCTION_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
_LUA_FUNCTION_RE = re.compile(r"^\s*(?:local\s+)?function\s+([A-Za-z_]\w*(?::[A-Za-z_]\w*|\.[A-Za-z_]\w*)?)\s*\(([^)]*)\)")

_LUA_OPEN_RE = re.compile(
    r"^\s*(?:local\s+function\b|function\b|if\b.*\bthen\b|for\b.*\bdo\b|while\b.*\bdo\b|repeat\b)"
)
_LUA_CLOSE_RE = re.compile(r"^\s*(?:end\b|until\b)")


@dataclass(slots=True)
class _BlockSpan:
    name: str
    kind: str
    start_line: int
    end_line: int


class HeuristicSourceParser:
    """Best-effort parser for languages that currently lack tree-sitter integration."""

    def __init__(self, language: str) -> None:
        self.language = language.lower()

    def parse_file(self, path: Path, project_root: Path) -> ParsedStructure:
        rel_path = str(path.relative_to(project_root)).replace("\\", "/")
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ParsedStructure()

        module_name = self._module_name(path, project_root)
        module = ParsedModule(
            name=module_name,
            path=str(path.parent.relative_to(project_root)).replace("\\", "/") if path.parent != project_root else ".",
            module_type="module",
            file_paths=[rel_path],
            language=self.language,
        )
        lines = source.splitlines()

        class_spans = self._collect_class_spans(lines)
        impl_spans = self._collect_impl_spans(lines)
        functions = self._collect_functions(lines, rel_path, module_name, class_spans, impl_spans)
        classes = [
            ParsedClass(
                name=span.name,
                file_path=rel_path,
                start_line=span.start_line,
                end_line=span.end_line,
                kind=span.kind,
            )
            for span in class_spans
        ]

        class_map = {item.name: item for item in classes}
        for function in functions:
            if function.is_method and function.class_or_module in class_map:
                class_entity = class_map[function.class_or_module]
                if function.name not in class_entity.methods:
                    class_entity.methods.append(function.name)

        return ParsedStructure(functions=functions, classes=classes, modules=[module])

    def _collect_class_spans(self, lines: list[str]) -> list[_BlockSpan]:
        spans: list[_BlockSpan] = []
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue

            match: re.Match[str] | None = None
            if self.language == "cpp":
                match = _CPP_CLASS_RE.match(stripped)
                if match:
                    kind, name = match.group(1), match.group(2)
                else:
                    continue
            elif self.language == "csharp":
                match = _CSHARP_CLASS_RE.match(stripped)
                if match:
                    kind, name = match.group(1), match.group(2)
                else:
                    continue
            elif self.language == "go":
                match = _GO_CLASS_RE.match(stripped)
                if match:
                    name, kind = match.group(1), match.group(2)
                else:
                    continue
            elif self.language == "rust":
                match = _RUST_CLASS_RE.match(stripped)
                if match:
                    kind, name = match.group(1), match.group(2)
                else:
                    continue
            else:
                continue

            spans.append(
                _BlockSpan(
                    name=name,
                    kind=kind,
                    start_line=index + 1,
                    end_line=self._find_brace_block_end(lines, index),
                )
            )
        return spans

    def _collect_impl_spans(self, lines: list[str]) -> list[_BlockSpan]:
        if self.language != "rust":
            return []

        spans: list[_BlockSpan] = []
        for index, line in enumerate(lines):
            match = _RUST_IMPL_RE.match(line.strip())
            if not match:
                continue
            spans.append(
                _BlockSpan(
                    name=match.group(1),
                    kind="impl",
                    start_line=index + 1,
                    end_line=self._find_brace_block_end(lines, index),
                )
            )
        return spans

    def _collect_functions(
        self,
        lines: list[str],
        rel_path: str,
        module_name: str,
        class_spans: list[_BlockSpan],
        impl_spans: list[_BlockSpan],
    ) -> list[ParsedFunction]:
        functions: list[ParsedFunction] = []
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue

            owner: str | None = None
            name: str | None = None
            params = ""
            is_method = False

            if self.language == "go":
                match = _GO_FUNCTION_RE.match(stripped)
                if not match:
                    continue
                owner = match.group(1)
                name = match.group(2)
                params = match.group(3)
                is_method = owner is not None
            elif self.language == "cpp":
                match = _CPP_FUNCTION_RE.match(stripped)
                if not match:
                    continue
                name = match.group(1)
                params = match.group(2)
                owner = self._enclosing_owner(index + 1, class_spans)
                is_method = owner is not None
            elif self.language == "csharp":
                match = _CSHARP_FUNCTION_RE.match(stripped)
                if not match:
                    continue
                name = match.group(1)
                params = match.group(2)
                owner = self._enclosing_owner(index + 1, class_spans)
                is_method = owner is not None
            elif self.language == "rust":
                match = _RUST_FUNCTION_RE.match(stripped)
                if not match:
                    continue
                name = match.group(1)
                params = match.group(2)
                owner = self._enclosing_owner(index + 1, impl_spans)
                is_method = owner is not None
            elif self.language == "lua":
                match = _LUA_FUNCTION_RE.match(stripped)
                if not match:
                    continue
                qualified_name = match.group(1)
                params = match.group(2)
                if ":" in qualified_name:
                    owner, name = qualified_name.split(":", maxsplit=1)
                    is_method = True
                elif "." in qualified_name:
                    owner, name = qualified_name.rsplit(".", maxsplit=1)
                    is_method = True
                else:
                    name = qualified_name
            else:
                continue

            if name is None:
                continue

            start_line = index + 1
            end_line = self._find_block_end(lines, index)
            signature = stripped.rstrip("{").strip()
            functions.append(
                ParsedFunction(
                    name=name,
                    file_path=rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    signature=signature,
                    class_or_module=owner or module_name,
                    is_method=is_method,
                    param_count=self._count_parameters(params),
                    loc=max(0, end_line - start_line + 1),
                )
            )
        return functions

    def _find_block_end(self, lines: list[str], start_index: int) -> int:
        if self.language == "lua":
            return self._find_lua_block_end(lines, start_index)
        return self._find_brace_block_end(lines, start_index)

    @staticmethod
    def _find_brace_block_end(lines: list[str], start_index: int) -> int:
        depth = 0
        saw_open = False
        for index in range(start_index, len(lines)):
            line = lines[index]
            open_count = line.count("{")
            close_count = line.count("}")
            if open_count:
                saw_open = True
                depth += open_count
            if close_count and saw_open:
                depth -= close_count
                if depth <= 0:
                    return index + 1
        return start_index + 1

    @staticmethod
    def _find_lua_block_end(lines: list[str], start_index: int) -> int:
        depth = 0
        for index in range(start_index, len(lines)):
            stripped = lines[index].strip()
            if not stripped:
                continue
            if _LUA_OPEN_RE.match(stripped):
                depth += 1
            if _LUA_CLOSE_RE.match(stripped):
                depth -= 1
                if depth <= 0:
                    return index + 1
        return start_index + 1

    @staticmethod
    def _enclosing_owner(line_no: int, spans: list[_BlockSpan]) -> str | None:
        enclosing = [span for span in spans if span.start_line <= line_no <= span.end_line]
        if not enclosing:
            return None
        enclosing.sort(key=lambda span: (span.end_line - span.start_line, span.start_line))
        return enclosing[0].name

    @staticmethod
    def _count_parameters(raw_params: str) -> int:
        params = raw_params.strip()
        if not params:
            return 0

        count = 0
        depth = 0
        token: list[str] = []
        for char in params:
            if char in "<([{" :
                depth += 1
            elif char in ">)]}" and depth > 0:
                depth -= 1
            if char == "," and depth == 0:
                if "".join(token).strip():
                    count += 1
                token = []
                continue
            token.append(char)
        if "".join(token).strip():
            count += 1
        return count

    @staticmethod
    def _module_name(path: Path, project_root: Path) -> str:
        rel = path.relative_to(project_root)
        parts = list(rel.parts)
        parts[-1] = path.stem
        return ".".join(parts) if parts else project_root.name
