"""Python source parser based on the standard library AST."""

from __future__ import annotations

import ast
from pathlib import Path

from codeguardian.parsers.base import ParsedClass, ParsedFunction, ParsedModule, ParsedStructure


class PythonSourceParser:
    """Extract module, class, and function structure from Python source files."""

    language = "python"

    def parse_file(self, path: Path, project_root: Path) -> ParsedStructure:
        rel_path = str(path.relative_to(project_root)).replace("\\", "/")

        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError):
            return ParsedStructure()

        module_name = self._module_name(path, project_root)
        module = ParsedModule(
            name=module_name,
            path=str(path.parent.relative_to(project_root)).replace("\\", "/") if path.parent != project_root else ".",
            module_type="module",
            file_paths=[rel_path],
            language=self.language,
        )

        functions: list[ParsedFunction] = []
        classes: list[ParsedClass] = []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(self._build_function(node, rel_path, module_name))
            elif isinstance(node, ast.ClassDef):
                parsed_class, class_functions = self._build_class(node, rel_path, module_name)
                classes.append(parsed_class)
                functions.extend(class_functions)

        return ParsedStructure(functions=functions, classes=classes, modules=[module])

    def _build_class(
        self,
        node: ast.ClassDef,
        rel_path: str,
        module_name: str,
    ) -> tuple[ParsedClass, list[ParsedFunction]]:
        methods: list[str] = []
        fields: list[str] = []
        function_entities: list[ParsedFunction] = []

        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(child.name)
                function_entities.append(
                    self._build_function(child, rel_path, module_name, class_name=node.name, is_method=True)
                )
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    fields.extend(self._extract_assignment_names(target))
            elif isinstance(child, ast.AnnAssign):
                fields.extend(self._extract_assignment_names(child.target))

        bases = [name for name in (self._base_name(b) for b in node.bases) if name]

        class_entity = ParsedClass(
            name=node.name,
            file_path=rel_path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", None),
            kind="class",
            methods=methods,
            fields=fields,
            bases=bases,
        )
        return class_entity, function_entities

    @staticmethod
    def _base_name(expr: ast.expr) -> str | None:
        """Best-effort base class name from a ClassDef base expression."""
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return expr.attr
        if isinstance(expr, ast.Subscript):  # Generic[T], Protocol[...] etc.
            return PythonSourceParser._base_name(expr.value)
        return None

    def _build_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_path: str,
        module_name: str,
        class_name: str | None = None,
        is_method: bool = False,
    ) -> ParsedFunction:
        param_names = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        if node.args.vararg:
            param_names.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            param_names.append(f"**{node.args.kwarg.arg}")

        owner = class_name or module_name
        prefix = f"{class_name}." if class_name else ""
        signature = f"{'async ' if isinstance(node, ast.AsyncFunctionDef) else ''}def {prefix}{node.name}({', '.join(param_names)})"

        start_line = getattr(node, "lineno", None)
        end_line = getattr(node, "end_lineno", None)
        loc = (end_line - start_line + 1) if start_line and end_line else 0

        return ParsedFunction(
            name=node.name,
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            signature=signature,
            class_or_module=owner,
            is_method=is_method,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            param_count=len(param_names),
            loc=loc,
        )

    @staticmethod
    def _extract_assignment_names(target: ast.expr) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for elt in target.elts:
                names.extend(PythonSourceParser._extract_assignment_names(elt))
            return names
        return []

    @staticmethod
    def _module_name(path: Path, project_root: Path) -> str:
        rel = path.relative_to(project_root)
        parts = list(rel.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = path.stem
        return ".".join(parts) if parts else project_root.name
