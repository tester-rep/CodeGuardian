"""Import resolution — maps import statements to qualified symbol names.

Supports Python, Java, Go with graduated accuracy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(slots=True)
class ResolvedImport:
    """A resolved import statement mapping a local name to a qualified symbol."""

    local_name: str  # Name as used in the importing file
    qualified_name: str  # Fully qualified target symbol
    module_path: str  # Module/package path
    is_wildcard: bool = False  # True for * imports
    confidence: float = 0.85  # How confident we are in this resolution


class ImportResolver(Protocol):
    """Protocol for language-specific import resolvers."""

    def resolve_imports(
        self,
        file_path: str,
        source_lines: list[str],
        project_files: dict[str, str],  # rel_path -> module_path mapping
    ) -> list[ResolvedImport]:
        """Resolve all imports in a file to qualified names."""
        ...


class PythonImportResolver:
    """Resolves Python imports to qualified symbols.

    Handles:
    - from module import name
    - import module
    - from . import name (relative imports)
    - from module import * (wildcard)
    """

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        # Cache: module_path -> list of public symbol names
        self._module_exports: dict[str, list[str]] = {}

    def resolve_imports(
        self,
        file_path: str,
        source_lines: list[str],
        project_files: dict[str, str],
    ) -> list[ResolvedImport]:
        """Resolve all Python imports in a file."""
        results: list[ResolvedImport] = []

        for line in source_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("from "):
                results.extend(self._resolve_from_import(stripped, file_path, project_files))
            elif stripped.startswith("import "):
                results.extend(self._resolve_plain_import(stripped, project_files))

        return results

    def _resolve_from_import(
        self,
        line: str,
        current_file: str,
        project_files: dict[str, str],
    ) -> list[ResolvedImport]:
        """Resolve: from module import name1, name2 [as alias]."""
        match = re.match(r"from\s+(\.+\w*(?:\.\w+)*|\w+(?:\.\w+)*)\s+import\s+(.+)", line)
        if not match:
            return []

        module_ref = match.group(1).strip()
        imports_part = match.group(2).strip()

        # Handle relative imports
        if module_ref.startswith("."):
            module_ref = self._resolve_relative(module_ref, current_file)
            if not module_ref:
                return []

        results: list[ResolvedImport] = []

        if imports_part == "*":
            # Wildcard import — resolve to known exports of that module
            results.append(ResolvedImport(
                local_name="*",
                qualified_name=f"{module_ref}.*",
                module_path=module_ref,
                is_wildcard=True,
                confidence=0.60,
            ))
            return results

        # Parse imported names: name1, name2 as alias, name3
        # Handle multi-line imports with parens
        imports_part = imports_part.strip("()")
        for item in imports_part.split(","):
            item = item.strip()
            if not item:
                continue

            # Handle "name as alias"
            if " as " in item:
                parts = item.split(" as ")
                original_name = parts[0].strip()
                local_name = parts[1].strip()
            else:
                original_name = item.strip()
                local_name = original_name

            qualified = f"{module_ref}.{original_name}"
            results.append(ResolvedImport(
                local_name=local_name,
                qualified_name=qualified,
                module_path=module_ref,
                confidence=0.85,
            ))

        return results

    def _resolve_plain_import(
        self,
        line: str,
        project_files: dict[str, str],
    ) -> list[ResolvedImport]:
        """Resolve: import module [as alias], module2 [as alias2]."""
        import_text = line[7:].strip()  # Strip "import "
        results: list[ResolvedImport] = []

        for item in import_text.split(","):
            item = item.strip()
            if not item:
                continue

            if " as " in item:
                parts = item.split(" as ")
                module_path = parts[0].strip()
                local_name = parts[1].strip()
            else:
                module_path = item
                # Local name is last segment: import os.path -> path
                local_name = module_path.split(".")[-1]

            results.append(ResolvedImport(
                local_name=local_name,
                qualified_name=module_path,
                module_path=module_path,
                confidence=0.85,
            ))

        return results

    def _resolve_relative(self, module_ref: str, current_file: str) -> str:
        """Resolve relative import (., .., .module) to absolute module path."""
        # Count leading dots
        dots = 0
        for ch in module_ref:
            if ch == ".":
                dots += 1
            else:
                break

        remainder = module_ref[dots:]

        # Current file's package
        current_parts = Path(current_file).with_suffix("").parts
        # Strip common source roots
        if current_parts and current_parts[0] in ("src", "lib"):
            current_parts = current_parts[1:]

        # Go up 'dots' levels from current package
        if len(current_parts) <= dots:
            return remainder  # Can't go up further

        base_parts = current_parts[:len(current_parts) - dots]
        if remainder:
            return ".".join(base_parts) + "." + remainder
        return ".".join(base_parts)


class JavaImportResolver:
    """Resolves Java imports to qualified symbols.

    Handles:
    - import com.app.ClassName;
    - import com.app.*;  (wildcard)
    - Same-package implicit imports
    - java.lang.* (always implicitly imported)
    """

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root

    def resolve_imports(
        self,
        file_path: str,
        source_lines: list[str],
        project_files: dict[str, str],
    ) -> list[ResolvedImport]:
        """Resolve all Java imports in a file."""
        results: list[ResolvedImport] = []
        current_package = ""

        for line in source_lines:
            stripped = line.strip()

            # Package declaration
            if stripped.startswith("package "):
                current_package = stripped[8:].rstrip(";").strip()
                continue

            if not stripped.startswith("import "):
                continue

            # Strip 'import static' prefix
            import_text = stripped[7:].rstrip(";").strip()
            is_static = import_text.startswith("static ")
            if is_static:
                import_text = import_text[7:].strip()

            if import_text.endswith(".*"):
                # Wildcard import
                package = import_text[:-2]
                results.append(ResolvedImport(
                    local_name="*",
                    qualified_name=f"{package}.*",
                    module_path=package,
                    is_wildcard=True,
                    confidence=0.60,
                ))
            else:
                # Specific import: import com.app.ClassName
                qualified = import_text
                local_name = qualified.split(".")[-1]
                module_path = ".".join(qualified.split(".")[:-1])
                results.append(ResolvedImport(
                    local_name=local_name,
                    qualified_name=qualified,
                    module_path=module_path,
                    confidence=0.90,
                ))

        # Same-package: all classes in the same package are implicitly available
        if current_package:
            for rel_path, mod_path in project_files.items():
                if not rel_path.endswith(".java"):
                    continue
                # Check if same package
                file_package = self._get_java_package(rel_path)
                if file_package == current_package and rel_path != file_path:
                    class_name = Path(rel_path).stem
                    results.append(ResolvedImport(
                        local_name=class_name,
                        qualified_name=f"{current_package}.{class_name}",
                        module_path=current_package,
                        confidence=0.90,
                    ))

        # java.lang.* is always implicitly imported
        for name in ("String", "Integer", "Long", "Boolean", "Object", "System",
                     "Exception", "RuntimeException", "Thread", "Class", "Iterable"):
            results.append(ResolvedImport(
                local_name=name,
                qualified_name=f"java.lang.{name}",
                module_path="java.lang",
                confidence=0.95,
            ))

        return results

    @staticmethod
    def _get_java_package(file_path: str) -> str:
        """Infer package from file path."""
        parts = list(Path(file_path).with_suffix("").parts)
        # Strip standard Maven/Gradle source roots
        for root in ("src/main/java", "src/test/java", "src"):
            root_parts = root.split("/")
            if parts[:len(root_parts)] == root_parts:
                parts = parts[len(root_parts):]
                break
        # Package is all parts except the last (which is the class name)
        if len(parts) > 1:
            return ".".join(parts[:-1])
        return ""


class GoImportResolver:
    """Resolves Go imports to qualified symbols.

    Handles:
    - import "pkg/path"
    - import alias "pkg/path"
    - import . "pkg/path" (dot import)
    - Exported symbols (capitalized)
    """

    def __init__(self, project_root: Path, module_name: str = "") -> None:
        self.project_root = project_root
        self.module_name = module_name  # From go.mod

    def resolve_imports(
        self,
        file_path: str,
        source_lines: list[str],
        project_files: dict[str, str],
    ) -> list[ResolvedImport]:
        """Resolve all Go imports in a file."""
        results: list[ResolvedImport] = []
        in_import_block = False

        for line in source_lines:
            stripped = line.strip()

            if stripped.startswith("import ("):
                in_import_block = True
                continue
            if in_import_block and stripped == ")":
                in_import_block = False
                continue

            if in_import_block:
                result = self._parse_single_import(stripped, project_files)
                if result:
                    results.append(result)
            elif stripped.startswith("import ") and "(" not in stripped:
                # Single-line import
                import_text = stripped[7:].strip()
                result = self._parse_single_import(import_text, project_files)
                if result:
                    results.append(result)

        return results

    def _parse_single_import(
        self,
        text: str,
        project_files: dict[str, str],
    ) -> ResolvedImport | None:
        """Parse a single Go import line."""
        text = text.strip()
        if not text or text.startswith("//"):
            return None

        alias = None
        path = ""

        # Check for alias: alias "path" or . "path" or _ "path"
        if text.startswith('"'):
            path = text.strip('"')
        else:
            parts = text.split(None, 1)
            if len(parts) == 2:
                alias = parts[0]
                path = parts[1].strip('"')
            else:
                return None

        if not path:
            return None

        # Local name is the last segment of the path, or the alias
        local_name = alias if alias and alias != "." and alias != "_" else path.split("/")[-1]
        is_wildcard = alias == "."

        # Check if this is a project-internal import
        confidence = 0.85
        if self.module_name and path.startswith(self.module_name):
            confidence = 0.90

        return ResolvedImport(
            local_name=local_name,
            qualified_name=path,
            module_path=path,
            is_wildcard=is_wildcard,
            confidence=confidence,
        )


def get_resolver(language: str, project_root: Path, **kwargs: object) -> ImportResolver | None:
    """Factory: get the appropriate import resolver for a language."""
    if language == "python":
        return PythonImportResolver(project_root)
    if language == "java":
        return JavaImportResolver(project_root)
    if language == "go":
        module_name = kwargs.get("go_module", "") or _detect_go_module(project_root)
        return GoImportResolver(project_root, module_name=str(module_name))
    return None


def _detect_go_module(project_root: Path) -> str:
    """Detect Go module name from go.mod."""
    go_mod = project_root / "go.mod"
    if go_mod.exists():
        try:
            for line in go_mod.read_text(encoding="utf-8").splitlines():
                if line.startswith("module "):
                    return line[7:].strip()
        except OSError:
            pass
    return ""
