"""tree-sitter-backed structure parser for Java, JavaScript, and TypeScript."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from codeguardian.parsers.base import ParsedClass, ParsedFunction, ParsedModule, ParsedStructure
from codeguardian.parsers.tree_sitter_support import TreeSitterDocument, get_tree_sitter_document

if TYPE_CHECKING:
    from tree_sitter import Node
else:
    Node = Any


JAVA_CLASS_TYPES = {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"}
JS_CLASS_TYPES = {"class_declaration"}
TS_CLASS_TYPES = {"class_declaration", "interface_declaration"}
JS_FUNCTION_TYPES = {"function_declaration", "method_definition"}
JS_VARIABLE_FUNCTION_TYPES = {"arrow_function", "function_expression", "generator_function"}
JAVA_FUNCTION_TYPES = {"method_declaration", "constructor_declaration"}

# Go AST node types
GO_FUNCTION_TYPES = {"function_declaration", "method_declaration"}
GO_TYPE_DECLARATION_TYPES = {"type_declaration"}

# C++ AST node types
CPP_CLASS_TYPES = {"class_specifier", "struct_specifier", "enum_specifier"}
CPP_FUNCTION_TYPES = {"function_definition"}


class TreeSitterSourceParser:
    """Extract structural entities for brace-style languages via tree-sitter."""

    def __init__(self, language: str) -> None:
        self.language = language

    def parse_file(self, path: Path, project_root: Path) -> ParsedStructure:
        document = get_tree_sitter_document(path, project_root, self.language)
        if document is None:
            return ParsedStructure()

        module = self._build_module(path, project_root)
        if self.language == "java":
            classes, functions = self._parse_java(document, module.name)
        elif self.language == "go":
            classes, functions = self._parse_go(document, module.name)
        elif self.language == "cpp":
            classes, functions = self._parse_cpp(document, module.name)
        else:
            classes, functions = self._parse_javascript_family(document, module.name)

        return ParsedStructure(functions=functions, classes=classes, modules=[module])

    def _parse_java(
        self,
        document: TreeSitterDocument,
        module_name: str,
    ) -> tuple[list[ParsedClass], list[ParsedFunction]]:
        classes: list[ParsedClass] = []
        functions: list[ParsedFunction] = []

        def visit(node: Node, class_stack: list[str]) -> None:
            if node.type in JAVA_CLASS_TYPES:
                class_name = self._node_name(document, node)
                if class_name is None:
                    return
                body = node.child_by_field_name("body") or self._find_first_child(
                    node,
                    "class_body",
                    "interface_body",
                    "enum_body",
                    "record_body",
                )
                classes.append(self._build_java_class(document, node, body))
                next_stack = [*class_stack, class_name]
                if body is not None:
                    for child in body.named_children:
                        visit(child, next_stack)
                return

            if node.type in JAVA_FUNCTION_TYPES:
                function = self._build_function(document, node, module_name, class_stack)
                if function is not None:
                    functions.append(function)
                return

            for child in node.named_children:
                visit(child, class_stack)

        visit(document.root_node, [])
        return classes, functions

    def _parse_javascript_family(
        self,
        document: TreeSitterDocument,
        module_name: str,
    ) -> tuple[list[ParsedClass], list[ParsedFunction]]:
        classes: list[ParsedClass] = []
        functions: list[ParsedFunction] = []
        class_types = TS_CLASS_TYPES if self.language == "typescript" else JS_CLASS_TYPES

        def visit(node: Node, class_stack: list[str]) -> None:
            if node.type in class_types:
                class_name = self._node_name(document, node)
                if class_name is None:
                    return
                body = node.child_by_field_name("body") or self._find_first_child(
                    node,
                    "class_body",
                    "interface_body",
                )
                classes.append(self._build_javascript_class(document, node, body))
                next_stack = [*class_stack, class_name]
                if body is not None:
                    for child in body.named_children:
                        visit(child, next_stack)
                return

            if node.type in JS_FUNCTION_TYPES:
                function = self._build_function(document, node, module_name, class_stack)
                if function is not None:
                    functions.append(function)
                body = node.child_by_field_name("body") or self._find_first_child(node, "statement_block")
                if body is not None:
                    for child in body.named_children:
                        visit(child, class_stack)
                return

            if node.type == "variable_declarator":
                name = self._node_name(document, node)
                value = node.child_by_field_name("value")
                if name and value is not None and value.type in JS_VARIABLE_FUNCTION_TYPES:
                    function = self._build_function(
                        document,
                        value,
                        module_name,
                        class_stack,
                        name_override=name,
                    )
                    if function is not None:
                        functions.append(function)
                    body = value.child_by_field_name("body") or self._find_first_child(value, "statement_block")
                    if body is not None:
                        for child in body.named_children:
                            visit(child, class_stack)
                    return

            for child in node.named_children:
                visit(child, class_stack)

        visit(document.root_node, [])
        return classes, functions

    def _build_java_class(
        self,
        document: TreeSitterDocument,
        node: Node,
        body: Node | None,
    ) -> ParsedClass:
        methods: list[str] = []
        fields: list[str] = []
        kind = {
            "interface_declaration": "interface",
            "enum_declaration": "enum",
            "record_declaration": "record",
        }.get(node.type, "class")

        if body is not None:
            for child in body.named_children:
                if child.type in JAVA_FUNCTION_TYPES:
                    method_name = self._node_name(document, child)
                    if method_name:
                        methods.append(method_name)
                elif child.type in {"field_declaration", "constant_declaration"}:
                    fields.extend(self._collect_variable_names(document, child))

        start_line, end_line = document.line_range(node)
        return ParsedClass(
            name=self._node_name(document, node) or "<anonymous>",
            file_path=document.relative_path,
            start_line=start_line,
            end_line=end_line,
            kind=kind,
            methods=methods,
            fields=fields,
        )

    def _build_javascript_class(
        self,
        document: TreeSitterDocument,
        node: Node,
        body: Node | None,
    ) -> ParsedClass:
        methods: list[str] = []
        fields: list[str] = []
        kind = "interface" if node.type == "interface_declaration" else "class"

        if body is not None:
            for child in body.named_children:
                if child.type in {"method_definition", "method_signature"}:
                    method_name = self._node_name(document, child)
                    if method_name:
                        methods.append(method_name)
                elif child.type in {"public_field_definition", "property_signature"}:
                    field_name = self._node_name(document, child)
                    if field_name:
                        fields.append(field_name)

        start_line, end_line = document.line_range(node)
        return ParsedClass(
            name=self._node_name(document, node) or "<anonymous>",
            file_path=document.relative_path,
            start_line=start_line,
            end_line=end_line,
            kind=kind,
            methods=methods,
            fields=fields,
        )

    # ════════════════════════════════════════════════════════════════════
    # Go tree-sitter parsing
    # ════════════════════════════════════════════════════════════════════

    def _parse_go(
        self,
        document: TreeSitterDocument,
        module_name: str,
    ) -> tuple[list[ParsedClass], list[ParsedFunction]]:
        classes: list[ParsedClass] = []
        functions: list[ParsedFunction] = []

        for node in document.root_node.named_children:
            # type declarations: type Foo struct/interface { ... }
            if node.type == "type_declaration":
                for spec in node.named_children:
                    if spec.type != "type_spec":
                        continue
                    type_name = self._node_name(document, spec)
                    if type_name is None:
                        continue
                    type_node = spec.child_by_field_name("type")
                    if type_node is None:
                        continue
                    kind = "struct" if type_node.type == "struct_type" else (
                        "interface" if type_node.type == "interface_type" else type_node.type
                    )
                    methods_list: list[str] = []
                    fields_list: list[str] = []
                    # Extract struct fields
                    if type_node.type == "struct_type":
                        field_list = self._find_first_child(type_node, "field_declaration_list")
                        if field_list is not None:
                            for field_decl in field_list.named_children:
                                if field_decl.type == "field_declaration":
                                    fname = self._node_name(document, field_decl)
                                    if fname:
                                        fields_list.append(fname)
                    # Extract interface methods
                    elif type_node.type == "interface_type":
                        method_spec_list = type_node.named_children
                        for ms in method_spec_list:
                            if ms.type == "method_spec":
                                mname = self._node_name(document, ms)
                                if mname:
                                    methods_list.append(mname)

                    start_line, end_line = document.line_range(spec)
                    classes.append(ParsedClass(
                        name=type_name,
                        file_path=document.relative_path,
                        start_line=start_line,
                        end_line=end_line,
                        kind=kind,
                        methods=methods_list,
                        fields=fields_list,
                    ))

            # function declarations: func foo(...) { ... }
            elif node.type == "function_declaration":
                function = self._build_go_function(document, node, module_name, receiver=None)
                if function is not None:
                    functions.append(function)

            # method declarations: func (r *Receiver) foo(...) { ... }
            elif node.type == "method_declaration":
                receiver = self._go_method_receiver(document, node)
                function = self._build_go_function(document, node, module_name, receiver=receiver)
                if function is not None:
                    functions.append(function)
                    # Also add to class methods list
                    if receiver:
                        for cls_obj in classes:
                            if cls_obj.name == receiver and function.name not in cls_obj.methods:
                                cls_obj.methods.append(function.name)

        return classes, functions

    def _build_go_function(
        self,
        document: TreeSitterDocument,
        node: Node,
        module_name: str,
        receiver: str | None,
    ) -> ParsedFunction | None:
        name = self._node_name(document, node)
        if name is None:
            return None

        start_line, end_line = document.line_range(node)
        loc = max(0, end_line - start_line + 1)
        param_count = self._count_go_parameters(node)

        return ParsedFunction(
            name=name,
            file_path=document.relative_path,
            start_line=start_line,
            end_line=end_line,
            signature=self._signature_preview(document.text_for(node)),
            class_or_module=receiver or module_name,
            is_method=receiver is not None,
            is_async=False,
            param_count=param_count,
            loc=loc,
        )

    @staticmethod
    def _go_method_receiver(document: TreeSitterDocument, node: Node) -> str | None:
        """Extract the receiver type name from a Go method declaration."""
        receiver_node = node.child_by_field_name("receiver")
        if receiver_node is None:
            return None
        # receiver is parameter_list containing one parameter_declaration
        for param in receiver_node.named_children:
            if param.type == "parameter_declaration":
                type_node = param.child_by_field_name("type")
                if type_node is not None:
                    type_text = document.text_for(type_node).strip().lstrip("*")
                    return type_text
        return None

    @staticmethod
    def _count_go_parameters(node: Node) -> int:
        """Count Go function parameters accurately."""
        params_node = node.child_by_field_name("parameters")
        if params_node is None:
            return 0
        count = 0
        for child in params_node.named_children:
            if child.type == "parameter_declaration":
                # A parameter_declaration can declare multiple names: a, b int
                names = [c for c in child.named_children if c.type == "identifier"]
                count += max(1, len(names))
        return count

    # ════════════════════════════════════════════════════════════════════
    # C++ tree-sitter parsing
    # ════════════════════════════════════════════════════════════════════

    def _parse_cpp(
        self,
        document: TreeSitterDocument,
        module_name: str,
    ) -> tuple[list[ParsedClass], list[ParsedFunction]]:
        classes: list[ParsedClass] = []
        functions: list[ParsedFunction] = []

        def visit(node: Node, class_stack: list[str]) -> None:
            # Class/struct/enum specifiers
            if node.type in CPP_CLASS_TYPES:
                class_name = self._node_name(document, node)
                if class_name is None:
                    # For anonymous structs/classes, skip
                    for child in node.named_children:
                        visit(child, class_stack)
                    return
                body = self._find_first_child(node, "field_declaration_list")
                methods_list: list[str] = []
                fields_list: list[str] = []
                kind = {
                    "struct_specifier": "struct",
                    "enum_specifier": "enum",
                }.get(node.type, "class")

                if body is not None:
                    for child in body.named_children:
                        if child.type == "function_definition":
                            mname = self._node_name(document, child)
                            if mname:
                                methods_list.append(mname)
                            func = self._build_cpp_function(document, child, module_name, class_stack + [class_name])
                            if func:
                                functions.append(func)
                        elif child.type == "declaration":
                            fname_node = self._find_first_child(child, "init_declarator", "function_declarator")
                            if fname_node is not None:
                                fname = self._node_name(document, fname_node)
                                if fname:
                                    if fname_node.type == "function_declarator":
                                        methods_list.append(fname)
                                    else:
                                        fields_list.append(fname)
                        elif child.type == "field_declaration":
                            for fc in child.named_children:
                                if fc.type in {"field_identifier", "identifier"}:
                                    fname = document.text_for(fc).strip()
                                    if fname:
                                        fields_list.append(fname)

                start_line, end_line = document.line_range(node)
                classes.append(ParsedClass(
                    name=class_name,
                    file_path=document.relative_path,
                    start_line=start_line,
                    end_line=end_line,
                    kind=kind,
                    methods=methods_list,
                    fields=fields_list,
                ))
                return

            # Top-level or namespace-level function definitions
            if node.type == "function_definition":
                func = self._build_cpp_function(document, node, module_name, class_stack)
                if func is not None:
                    functions.append(func)
                return

            # Recurse into namespaces, translation unit, etc.
            for child in node.named_children:
                visit(child, class_stack)

        visit(document.root_node, [])
        return classes, functions

    def _build_cpp_function(
        self,
        document: TreeSitterDocument,
        node: Node,
        module_name: str,
        class_stack: list[str],
    ) -> ParsedFunction | None:
        """Build a ParsedFunction from a C++ function_definition node."""
        # C++ function_definition has a declarator child which contains the function name
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            return None

        name = self._cpp_function_name(document, declarator)
        if name is None:
            return None

        owner = class_stack[-1] if class_stack else module_name
        start_line, end_line = document.line_range(node)
        loc = max(0, end_line - start_line + 1)
        param_count = self._count_cpp_parameters(declarator)

        return ParsedFunction(
            name=name,
            file_path=document.relative_path,
            start_line=start_line,
            end_line=end_line,
            signature=self._signature_preview(document.text_for(node)),
            class_or_module=owner,
            is_method=bool(class_stack),
            is_async=False,
            param_count=param_count,
            loc=loc,
        )

    @staticmethod
    def _cpp_function_name(document: TreeSitterDocument, declarator: Node) -> str | None:
        """Extract function name from a C++ declarator node.

        Handles: function_declarator, pointer_declarator wrapping function_declarator,
        qualified_identifier, destructor_name, etc.
        """
        current = declarator
        # Unwrap pointer_declarator, reference_declarator
        while current.type in {"pointer_declarator", "reference_declarator"}:
            inner = current.child_by_field_name("declarator")
            if inner is None:
                break
            current = inner

        if current.type == "function_declarator":
            name_node = current.child_by_field_name("declarator")
            if name_node is not None:
                text = document.text_for(name_node).strip()
                # For qualified names like ClassName::method, take the method part
                if "::" in text:
                    return text.split("::")[-1]
                return text

        # Fallback: look for identifier children
        for child in current.named_children:
            if child.type in {"identifier", "field_identifier", "destructor_name", "qualified_identifier"}:
                text = document.text_for(child).strip()
                if "::" in text:
                    return text.split("::")[-1]
                return text
        return None

    @staticmethod
    def _count_cpp_parameters(declarator: Node) -> int:
        """Count parameters from a C++ function declarator."""
        current = declarator
        while current.type in {"pointer_declarator", "reference_declarator"}:
            inner = current.child_by_field_name("declarator")
            if inner is None:
                break
            current = inner

        if current.type == "function_declarator":
            params_node = current.child_by_field_name("parameters")
            if params_node is not None:
                # Count parameter_declaration children (skip void)
                count = 0
                for child in params_node.named_children:
                    if child.type == "parameter_declaration":
                        text_content = child.text.decode("utf-8") if hasattr(child.text, "decode") else str(child.text)
                        if text_content.strip() == "void":
                            continue
                        count += 1
                    elif child.type == "variadic_parameter_declaration":
                        count += 1
                return count
        return 0

    def _build_function(
        self,
        document: TreeSitterDocument,
        node: Node,
        module_name: str,
        class_stack: list[str],
        name_override: str | None = None,
    ) -> ParsedFunction | None:
        name = name_override or self._node_name(document, node)
        if name is None:
            return None

        owner = class_stack[-1] if class_stack else module_name
        start_line, end_line = document.line_range(node)
        loc = max(0, end_line - start_line + 1)

        return ParsedFunction(
            name=name,
            file_path=document.relative_path,
            start_line=start_line,
            end_line=end_line,
            signature=self._signature_preview(document.text_for(node)),
            class_or_module=owner,
            is_method=bool(class_stack),
            is_async=document.text_for(node).lstrip().startswith("async "),
            param_count=self._count_parameters(node),
            loc=loc,
        )

    def _build_module(self, path: Path, project_root: Path) -> ParsedModule:
        rel_path = path.relative_to(project_root)
        dotted_name = ".".join(rel_path.with_suffix("").parts)
        parent_path = rel_path.parent.as_posix() if rel_path.parent != Path(".") else "."
        return ParsedModule(
            name=dotted_name,
            path=parent_path,
            module_type="module",
            file_paths=[str(rel_path).replace("\\", "/")],
            language=self.language,
        )

    @staticmethod
    def _find_first_child(node: Node, *types: str) -> Node | None:
        wanted = set(types)
        for child in node.named_children:
            if child.type in wanted:
                return child
        return None

    @staticmethod
    def _signature_preview(text: str) -> str:
        collapsed = " ".join(text.strip().split())
        for marker in (" {", "{", ":"):
            if marker in collapsed:
                return collapsed.split(marker, maxsplit=1)[0].strip()
        return collapsed[:160]

    @staticmethod
    def _node_name(document: TreeSitterDocument, node: Node) -> str | None:
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return document.text_for(name_node).strip()

        for child in node.named_children:
            if child.type in {
                "identifier",
                "type_identifier",
                "property_identifier",
                "private_property_identifier",
                "variable_identifier",
            }:
                return document.text_for(child).strip()
        return None

    @staticmethod
    def _collect_variable_names(document: TreeSitterDocument, node: Node) -> list[str]:
        names: list[str] = []
        for child in node.named_children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                if name_node is not None:
                    names.append(document.text_for(name_node).strip())
        return names

    @staticmethod
    def _count_parameters(node: Node) -> int:
        params_node = node.child_by_field_name("parameters")
        if params_node is None:
            for child in node.named_children:
                if child.type in {"formal_parameters", "parameters"}:
                    params_node = child
                    break

        if params_node is not None:
            return len(params_node.named_children)

        param_node = node.child_by_field_name("parameter")
        return 1 if param_node is not None else 0
