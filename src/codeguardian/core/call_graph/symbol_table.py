"""SymbolTable — project-wide symbol registry with O(1) lookup.

Registers all functions/methods/classes discovered by parsing, provides
efficient lookup by qualified name, short name, and class membership.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class SymbolKind(Enum):
    """Classification of a symbol."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    INTERFACE = "interface"
    MODULE = "module"
    CONSTRUCTOR = "constructor"


class Visibility(Enum):
    """Symbol visibility/access level."""

    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"
    PACKAGE = "package"  # Java package-private, Go unexported
    INTERNAL = "internal"  # C# internal


@dataclass(slots=True)
class Parameter:
    """Function/method parameter descriptor."""

    name: str
    type_hint: str | None = None
    position: int = 0
    has_default: bool = False


@dataclass(slots=True)
class Symbol:
    """A resolved symbol in the project symbol table."""

    name: str  # short name: "findUser"
    qualified_name: str  # full: "app.dao.UserDAO.findUser"
    kind: SymbolKind
    file_path: str  # relative to project root
    start_line: int
    end_line: int
    signature: str = ""  # "(userId: int) -> Optional[User]"
    return_type: str | None = None  # best-effort from annotation
    class_name: str | None = None  # enclosing class
    module_path: str = ""  # "app.dao" or "src/dao"
    visibility: Visibility = Visibility.PUBLIC
    is_static: bool = False
    is_async: bool = False
    parameters: list[Parameter] = field(default_factory=list)
    # For classes: parent class names (for hierarchy resolution)
    parent_classes: list[str] = field(default_factory=list)
    # For classes: implemented interfaces
    interfaces: list[str] = field(default_factory=list)
    # For classes: field name -> declared type name (drives field.method() resolution)
    field_types: dict[str, str] = field(default_factory=dict)
    # Language tag
    language: str = ""


class SymbolTable:
    """Project-wide symbol registry.

    Supports O(1) lookup by qualified name and efficient lookup by short name.
    Maintains class hierarchy information for method resolution.
    """

    def __init__(self) -> None:
        # Primary index: qualified_name -> Symbol
        self._by_qualified: dict[str, Symbol] = {}
        # Secondary index: short_name -> list[Symbol] (for overloads/ambiguity)
        self._by_name: dict[str, list[Symbol]] = {}
        # Class index: class_qualified_name -> list[Symbol] (methods)
        self._class_methods: dict[str, list[Symbol]] = {}
        # Class hierarchy: class_name -> parent_class_names
        self._class_parents: dict[str, list[str]] = {}
        # File index: file_path -> list[Symbol]
        self._by_file: dict[str, list[Symbol]] = {}
        # Module index: module_path -> list[Symbol]
        self._by_module: dict[str, list[Symbol]] = {}

    @property
    def size(self) -> int:
        """Total number of registered symbols."""
        return len(self._by_qualified)

    def register(self, symbol: Symbol) -> None:
        """Register a symbol. Overwrites if qualified_name already exists."""
        self._by_qualified[symbol.qualified_name] = symbol

        # Short name index
        if symbol.name not in self._by_name:
            self._by_name[symbol.name] = []
        self._by_name[symbol.name].append(symbol)

        # File index
        if symbol.file_path not in self._by_file:
            self._by_file[symbol.file_path] = []
        self._by_file[symbol.file_path].append(symbol)

        # Module index
        if symbol.module_path:
            if symbol.module_path not in self._by_module:
                self._by_module[symbol.module_path] = []
            self._by_module[symbol.module_path].append(symbol)

        # Class method index
        if symbol.class_name and symbol.kind in (SymbolKind.METHOD, SymbolKind.CONSTRUCTOR):
            class_key = f"{symbol.module_path}.{symbol.class_name}" if symbol.module_path else symbol.class_name
            if class_key not in self._class_methods:
                self._class_methods[class_key] = []
            self._class_methods[class_key].append(symbol)

        # Class hierarchy
        if symbol.kind in (SymbolKind.CLASS, SymbolKind.INTERFACE) and symbol.parent_classes:
            self._class_parents[symbol.qualified_name] = symbol.parent_classes

    def lookup(self, qualified_name: str) -> Symbol | None:
        """O(1) lookup by fully qualified name."""
        return self._by_qualified.get(qualified_name)

    def lookup_by_name(
        self,
        name: str,
        *,
        context_file: str | None = None,
        context_module: str | None = None,
    ) -> list[Symbol]:
        """Lookup by short name. Returns all matching symbols.

        If context_file is provided, symbols from that file are prioritized.
        If context_module is provided, symbols from that module are prioritized.
        """
        candidates = self._by_name.get(name, [])
        if not candidates:
            return []

        if context_file or context_module:
            # Sort: same-file first, then same-module, then others
            def priority(sym: Symbol) -> int:
                if context_file and sym.file_path == context_file:
                    return 0
                if context_module and sym.module_path == context_module:
                    return 1
                return 2

            return sorted(candidates, key=priority)
        return list(candidates)

    def lookup_methods(self, class_qualified_name: str) -> list[Symbol]:
        """Get all methods of a class (direct, not inherited)."""
        return self._class_methods.get(class_qualified_name, [])

    def lookup_in_file(self, file_path: str) -> list[Symbol]:
        """Get all symbols defined in a file."""
        return self._by_file.get(file_path, [])

    def lookup_in_module(self, module_path: str) -> list[Symbol]:
        """Get all symbols defined in a module."""
        return self._by_module.get(module_path, [])

    def get_class_hierarchy(self, class_qualified_name: str) -> list[str]:
        """Return inheritance chain: [self, parent, grandparent, ...].

        Stops at root or when cycle detected. Max depth 20.
        """
        chain: list[str] = [class_qualified_name]
        visited: set[str] = {class_qualified_name}
        current = class_qualified_name

        for _ in range(20):  # bounded depth
            parents = self._class_parents.get(current, [])
            if not parents:
                break
            # Take first parent (single inheritance primary path)
            parent = parents[0]
            # Try to resolve parent to a qualified name
            resolved = self._resolve_class_name(parent, current)
            if resolved in visited:
                break
            visited.add(resolved)
            chain.append(resolved)
            current = resolved

        return chain

    def get_all_interfaces(self, class_qualified_name: str) -> list[str]:
        """Get all interfaces implemented by a class (including inherited)."""
        sym = self._by_qualified.get(class_qualified_name)
        if sym is None:
            return []

        interfaces: list[str] = list(sym.interfaces)
        # Walk up hierarchy to collect inherited interfaces
        for parent in self.get_class_hierarchy(class_qualified_name)[1:]:
            parent_sym = self._by_qualified.get(parent)
            if parent_sym:
                interfaces.extend(parent_sym.interfaces)
        return interfaces

    def all_symbols(self) -> list[Symbol]:
        """Return all registered symbols (for iteration)."""
        return list(self._by_qualified.values())

    def all_functions(self) -> list[Symbol]:
        """Return all function/method symbols."""
        return [
            s for s in self._by_qualified.values()
            if s.kind in (SymbolKind.FUNCTION, SymbolKind.METHOD, SymbolKind.CONSTRUCTOR)
        ]

    def all_classes(self) -> list[Symbol]:
        """Return all class/interface symbols."""
        return [
            s for s in self._by_qualified.values()
            if s.kind in (SymbolKind.CLASS, SymbolKind.INTERFACE)
        ]

    def _resolve_class_name(self, name: str, context_qualified: str) -> str:
        """Try to resolve a class name to its qualified form."""
        # Already qualified?
        if name in self._by_qualified:
            return name

        # Try in same module as context
        if "." in context_qualified:
            module = context_qualified.rsplit(".", 1)[0]
            candidate = f"{module}.{name}"
            if candidate in self._by_qualified:
                return candidate

        # Try short name lookup
        candidates = self._by_name.get(name, [])
        class_candidates = [
            c for c in candidates
            if c.kind in (SymbolKind.CLASS, SymbolKind.INTERFACE)
        ]
        if len(class_candidates) == 1:
            return class_candidates[0].qualified_name

        # Unresolved — return as-is
        return name


def build_symbol_table_from_parsed(
    parsed_files: dict[str, object],
    project_root: Path,
    language_map: dict[str, str],
) -> SymbolTable:
    """Build a SymbolTable from parsed file structures.

    Args:
        parsed_files: mapping of relative_path -> ParsedStructure
        project_root: absolute project root path
        language_map: mapping of relative_path -> language string
    """
    from codeguardian.parsers.base import ParsedStructure

    table = SymbolTable()

    for rel_path, structure in parsed_files.items():
        if not isinstance(structure, ParsedStructure):
            continue

        language = language_map.get(rel_path, "")
        module_path = _file_to_module_path(rel_path, language)

        # Register classes first (needed for method qualification)
        for cls in structure.classes:
            class_qname = f"{module_path}.{cls.name}" if module_path else cls.name
            visibility = _infer_class_visibility(cls.name, language)

            table.register(Symbol(
                name=cls.name,
                qualified_name=class_qname,
                kind=SymbolKind.INTERFACE if cls.kind == "interface" else SymbolKind.CLASS,
                file_path=rel_path,
                start_line=cls.start_line or 0,
                end_line=cls.end_line or 0,
                module_path=module_path,
                visibility=visibility,
                language=language,
                parent_classes=list(getattr(cls, "bases", []) or []),
                interfaces=list(getattr(cls, "interfaces", []) or []),
                field_types=dict(getattr(cls, "field_types", {}) or {}),
            ))

        # Register functions/methods
        for func in structure.functions:
            if func.class_or_module and func.is_method:
                # Method — qualify with class name
                class_name = func.class_or_module
                func_qname = f"{module_path}.{class_name}.{func.name}" if module_path else f"{class_name}.{func.name}"
                kind = SymbolKind.CONSTRUCTOR if _is_constructor(func.name, language) else SymbolKind.METHOD
            else:
                # Top-level function
                func_qname = f"{module_path}.{func.name}" if module_path else func.name
                class_name = None
                kind = SymbolKind.FUNCTION

            visibility = _infer_function_visibility(func.name, language)
            return_type = _extract_return_type(func.signature, language) if func.signature else None

            params = _extract_parameters(func.signature, language) if func.signature else []

            table.register(Symbol(
                name=func.name,
                qualified_name=func_qname,
                kind=kind,
                file_path=rel_path,
                start_line=func.start_line or 0,
                end_line=func.end_line or 0,
                signature=func.signature or "",
                return_type=return_type,
                class_name=class_name if func.is_method else None,
                module_path=module_path,
                visibility=visibility,
                is_static=False,  # TODO: detect from modifiers
                is_async=func.is_async,
                parameters=params,
                language=language,
            ))

    return table


def _file_to_module_path(rel_path: str, language: str) -> str:
    """Convert a relative file path to a module/package path."""
    normalized = rel_path.replace("\\", "/")

    if language == "python":
        # src/app/dao/user_dao.py -> app.dao.user_dao (strip src/)
        parts = Path(normalized).with_suffix("").parts
        # Remove common source roots
        if parts and parts[0] in ("src", "lib", "source"):
            parts = parts[1:]
        # Remove __init__ (it's the package itself)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)

    if language == "java":
        # src/main/java/com/app/dao/UserDAO.java -> com.app.dao (the package;
        # the trailing UserDAO is the class name, NOT part of the package).
        # Keeping the class name here produced malformed qualified names such as
        # com.app.dao.UserDAO.UserDAO.method and broke import/type matching.
        parts = list(Path(normalized).with_suffix("").parts)
        # Strip standard Maven/Gradle source roots
        for root in ("src/main/java", "src/test/java", "src"):
            root_parts = root.split("/")
            if parts[:len(root_parts)] == root_parts:
                parts = parts[len(root_parts):]
                break
        # Drop the file (class) name — the package is the directory path.
        if len(parts) > 1:
            parts = parts[:-1]
        return ".".join(parts)

    if language == "go":
        # pkg/dao/user.go -> pkg/dao (file is not part of Go package name)
        parent = str(Path(normalized).parent).replace("\\", "/")
        return parent if parent != "." else ""

    # Default: use directory path with dots
    parts = Path(normalized).with_suffix("").parts
    if parts and parts[0] in ("src", "lib", "source"):
        parts = parts[1:]
    return ".".join(parts)


def _infer_class_visibility(name: str, language: str) -> Visibility:
    """Infer visibility from naming conventions."""
    if language == "python":
        if name.startswith("__"):
            return Visibility.PRIVATE
        if name.startswith("_"):
            return Visibility.PROTECTED
        return Visibility.PUBLIC
    if language == "go":
        return Visibility.PUBLIC if name[0:1].isupper() else Visibility.PACKAGE
    return Visibility.PUBLIC


def _infer_function_visibility(name: str, language: str) -> Visibility:
    """Infer visibility from naming conventions."""
    if language == "python":
        if name.startswith("__") and not name.endswith("__"):
            return Visibility.PRIVATE
        if name.startswith("_"):
            return Visibility.PROTECTED
        return Visibility.PUBLIC
    if language == "go":
        return Visibility.PUBLIC if name[0:1].isupper() else Visibility.PACKAGE
    return Visibility.PUBLIC


def _is_constructor(name: str, language: str) -> bool:
    """Check if a function name represents a constructor."""
    if language == "python":
        return name == "__init__"
    if language == "java":
        return name[0:1].isupper()  # Heuristic: Java constructors are ClassName()
    if language in ("javascript", "typescript"):
        return name == "constructor"
    if language == "cpp":
        return name == name  # Can't tell without class context
    return False


def _extract_return_type(signature: str, language: str) -> str | None:
    """Best-effort return type extraction from signature string."""
    if not signature:
        return None

    if language == "python":
        # def func(x: int) -> Optional[User]:
        if " -> " in signature:
            return_part = signature.split(" -> ", 1)[1].strip().rstrip(":")
            return return_part if return_part else None

    if language == "go":
        # func FindUser(id int) (*User, error)
        # Look for return type after closing paren of params
        paren_depth = 0
        for i, ch in enumerate(signature):
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    rest = signature[i + 1:].strip()
                    if rest:
                        return rest.rstrip("{").strip()
                    break

    if language == "java":
        # public Optional<User> findUser(int id)
        # The return type is before the method name
        parts = signature.split("(", 1)
        if parts:
            before_params = parts[0].strip()
            tokens = before_params.split()
            if len(tokens) >= 2:
                # Last token is method name, second-to-last is return type
                return tokens[-2] if tokens[-2] not in ("public", "private", "protected", "static", "final", "abstract", "synchronized") else None

    return None


def _extract_parameters(signature: str, language: str) -> list[Parameter]:
    """Best-effort parameter extraction from signature string."""
    if not signature:
        return []

    # Find content between first ( and matching )
    start = signature.find("(")
    if start == -1:
        return []

    depth = 0
    end = -1
    for i in range(start, len(signature)):
        if signature[i] == "(":
            depth += 1
        elif signature[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break

    if end == -1:
        return []

    params_str = signature[start + 1:end].strip()
    if not params_str:
        return []

    # Split by comma (naive — doesn't handle generics with commas)
    # Use a depth-aware split
    params: list[Parameter] = []
    current = ""
    depth = 0
    for ch in params_str:
        if ch in ("(", "<", "[", "{"):
            depth += 1
            current += ch
        elif ch in (")", ">", "]", "}"):
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            param = _parse_single_param(current.strip(), len(params), language)
            if param:
                params.append(param)
            current = ""
        else:
            current += ch

    if current.strip():
        param = _parse_single_param(current.strip(), len(params), language)
        if param:
            params.append(param)

    return params


def _parse_single_param(text: str, position: int, language: str) -> Parameter | None:
    """Parse a single parameter declaration."""
    if not text:
        return None

    # Skip 'self', 'cls' in Python
    if language == "python" and text.split(":")[0].split("=")[0].strip() in ("self", "cls"):
        return None

    has_default = "=" in text

    if language == "python":
        # name: type = default
        parts = text.split("=", 1)[0].strip()
        if ":" in parts:
            name, type_hint = parts.split(":", 1)
            return Parameter(name=name.strip(), type_hint=type_hint.strip(), position=position, has_default=has_default)
        return Parameter(name=parts.strip(), position=position, has_default=has_default)

    if language == "java":
        # Type name or @Annotation Type name
        tokens = text.split()
        # Filter annotations
        tokens = [t for t in tokens if not t.startswith("@")]
        if len(tokens) >= 2:
            return Parameter(name=tokens[-1], type_hint=tokens[-2], position=position, has_default=has_default)
        if tokens:
            return Parameter(name=tokens[0], position=position, has_default=has_default)

    if language == "go":
        # name type or just type (unnamed)
        tokens = text.split()
        if len(tokens) >= 2:
            return Parameter(name=tokens[0], type_hint=" ".join(tokens[1:]), position=position, has_default=False)
        if tokens:
            return Parameter(name=f"_p{position}", type_hint=tokens[0], position=position, has_default=False)

    # Generic fallback
    tokens = text.split()
    if tokens:
        return Parameter(name=tokens[-1].rstrip(","), position=position, has_default=has_default)

    return None
