"""Call site extraction from function bodies using tree-sitter.

Extracts all call sites within a function, classifying each by CallForm
(free/method/constructor/static/super) and extracting argument info.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from codeguardian.core.call_graph.graph import CallForm

if TYPE_CHECKING:
    from tree_sitter import Node
else:
    Node = Any


@dataclass(slots=True)
class RawCallSite:
    """A raw call site extracted from source before target resolution."""

    caller_qualified_name: str  # Enclosing function's qualified name
    caller_file: str  # File path
    callee_name: str  # Called name (may be short or dotted)
    receiver: str | None  # For method calls: the receiver expression text
    line: int  # Line number
    form: CallForm  # Classification
    arg_count: int = 0  # Number of arguments passed
    # For method calls on typed receivers: best-guess type
    receiver_type: str | None = None


def extract_call_sites_from_source(
    lines: list[str],
    language: str,
    caller_qualified_name: str,
    caller_file: str,
    start_line: int,
) -> list[RawCallSite]:
    """Extract call sites from function source lines using regex/pattern matching.

    This is a fallback when tree-sitter document is not available.
    Less accurate but works for all languages.
    """
    sites: list[RawCallSite] = []

    # Pre-pass: collect explicitly-declared local variable types for THIS function
    # body (``Lock lock = new Lock(id);`` / ``AccountDao dao = ...;``). The declared
    # type lets us type ``lock.acquire()`` receivers precisely instead of falling
    # back to a low-confidence global name match. Java/C++/C#/Go-style only —
    # Python/JS have no `Type var` declaration form.
    local_types = _collect_local_var_types(lines, language)

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comments
        if stripped.startswith(("#", "//", "/*", "*", "'''", '"""')):
            continue
        # Skip string-heavy lines (rough heuristic)
        if stripped.count('"') >= 4 or stripped.count("'") >= 4:
            continue

        new_sites = _extract_calls_from_line(
            stripped, language, caller_qualified_name, caller_file, start_line + i,
            local_types=local_types,
        )
        sites.extend(new_sites)

    return sites


# Explicit local declaration: `Type var = ...` (Java/C++/C#/Go typed locals).
# Captures the declared type (group 1) and variable name (group 2). Anchored so
# we only match declarations, not assignments or calls. Type may carry generics
# (`List<Foo>`) or qualifiers — only the raw head token is kept.
_LOCAL_DECL_RE = re.compile(
    r"^\s*(?:final\s+|static\s+|const\s+|volatile\s+)*"
    r"([A-Z]\w*(?:\s*<[^;=]*>)?(?:\[\])?)\s+"   # declared type
    r"([a-zA-Z_]\w*)\s*"                          # variable name
    r"=\s*[^=]",                                   # `=` but not `==`
)


def _collect_local_var_types(lines: list[str], language: str) -> dict[str, str]:
    """Map explicitly-declared local variable names to their declared type head.

    Only ``Type var = ...`` declarations are considered (the user-scoped rule for
    local type inference); constructor/assignment/return-type inference is out of
    scope. Applies to statically-typed languages; returns empty for Python/JS.
    """
    if language in ("python", "javascript", "typescript"):
        return {}

    local_types: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*")):
            continue
        m = _LOCAL_DECL_RE.match(stripped)
        if not m:
            continue
        type_name = m.group(1).split("<", 1)[0].strip().rstrip("[]").strip()
        var_name = m.group(2)
        if type_name:
            local_types[var_name] = type_name
    return local_types


def extract_call_sites_from_node(
    node: Node,
    document: Any,  # TreeSitterDocument
    language: str,
    caller_qualified_name: str,
    caller_file: str,
) -> list[RawCallSite]:
    """Extract call sites from a tree-sitter function body node.

    More accurate than regex: uses AST structure to identify calls.
    """
    sites: list[RawCallSite] = []
    _visit_for_calls(node, document, language, caller_qualified_name, caller_file, sites)
    return sites


def _visit_for_calls(
    node: Node,
    document: Any,
    language: str,
    caller_qname: str,
    caller_file: str,
    results: list[RawCallSite],
) -> None:
    """Recursively visit AST nodes to find call expressions."""
    if node.type in _CALL_NODE_TYPES.get(language, _CALL_NODE_TYPES["default"]):
        site = _parse_call_node(node, document, language, caller_qname, caller_file)
        if site:
            results.append(site)
        # Don't recurse into nested calls' children — they're separate calls
        # But do recurse into arguments (they may contain calls)
        for child in node.named_children:
            if child.type not in _CALL_NODE_TYPES.get(language, _CALL_NODE_TYPES["default"]):
                _visit_for_calls(child, document, language, caller_qname, caller_file, results)
        return

    # New expressions (constructors)
    if node.type in ("object_creation_expression", "new_expression"):
        site = _parse_constructor_node(node, document, language, caller_qname, caller_file)
        if site:
            results.append(site)

    for child in node.named_children:
        _visit_for_calls(child, document, language, caller_qname, caller_file, results)


_CALL_NODE_TYPES: dict[str, set[str]] = {
    "python": {"call"},
    "java": {"method_invocation"},
    "go": {"call_expression"},
    "javascript": {"call_expression"},
    "typescript": {"call_expression"},
    "cpp": {"call_expression"},
    "csharp": {"invocation_expression"},
    "default": {"call_expression", "call", "method_invocation", "invocation_expression"},
}


def _parse_call_node(
    node: Node,
    document: Any,
    language: str,
    caller_qname: str,
    caller_file: str,
) -> RawCallSite | None:
    """Parse a call expression node into a RawCallSite."""
    line = node.start_point[0] + 1  # 1-indexed

    if language == "python":
        return _parse_python_call(node, document, caller_qname, caller_file, line)
    elif language == "java":
        return _parse_java_call(node, document, caller_qname, caller_file, line)
    elif language == "go":
        return _parse_go_call(node, document, caller_qname, caller_file, line)
    elif language in ("javascript", "typescript"):
        return _parse_js_call(node, document, caller_qname, caller_file, line)
    elif language == "cpp":
        return _parse_cpp_call(node, document, caller_qname, caller_file, line)

    # Generic fallback
    text = document.text_for(node) if document else ""
    if "(" in text:
        callee = text.split("(")[0].strip()
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=callee,
            receiver=None,
            line=line,
            form=CallForm.FREE,
        )
    return None


def _parse_python_call(
    node: Node, document: Any, caller_qname: str, caller_file: str, line: int,
) -> RawCallSite | None:
    """Parse Python call node: func(), obj.method(), Class()."""
    func_node = node.child_by_field_name("function")
    if func_node is None:
        return None

    args_node = node.child_by_field_name("arguments")
    arg_count = len(args_node.named_children) if args_node else 0

    text = document.text_for(func_node)

    if func_node.type == "attribute":
        # obj.method()
        obj_node = func_node.child_by_field_name("object")
        attr_node = func_node.child_by_field_name("attribute")
        if obj_node and attr_node:
            receiver = document.text_for(obj_node)
            callee = document.text_for(attr_node)
            # super().method()
            if receiver == "super()":
                return RawCallSite(
                    caller_qualified_name=caller_qname,
                    caller_file=caller_file,
                    callee_name=callee,
                    receiver="super",
                    line=line,
                    form=CallForm.SUPER,
                    arg_count=arg_count,
                )
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=receiver,
                line=line,
                form=CallForm.METHOD,
                arg_count=arg_count,
                receiver_type=_guess_receiver_type(receiver),
            )

    elif func_node.type == "identifier":
        callee = text
        # Constructor heuristic: starts with uppercase
        if callee and callee[0].isupper():
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=None,
                line=line,
                form=CallForm.CONSTRUCTOR,
                arg_count=arg_count,
            )
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=callee,
            receiver=None,
            line=line,
            form=CallForm.FREE,
            arg_count=arg_count,
        )

    # Fallback
    if text:
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=text.split("(")[0] if "(" in text else text,
            receiver=None,
            line=line,
            form=CallForm.FREE,
            arg_count=arg_count,
        )
    return None


def _parse_java_call(
    node: Node, document: Any, caller_qname: str, caller_file: str, line: int,
) -> RawCallSite | None:
    """Parse Java method_invocation node."""
    name_node = node.child_by_field_name("name")
    obj_node = node.child_by_field_name("object")
    args_node = node.child_by_field_name("arguments")
    arg_count = len(args_node.named_children) if args_node else 0

    if name_node is None:
        return None

    callee = document.text_for(name_node)

    if obj_node:
        receiver = document.text_for(obj_node)
        # super.method()
        if receiver == "super":
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver="super",
                line=line,
                form=CallForm.SUPER,
                arg_count=arg_count,
            )
        # Static method: ClassName.method()
        if receiver and receiver[0:1].isupper() and "." not in receiver:
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=receiver,
                line=line,
                form=CallForm.STATIC,
                arg_count=arg_count,
                receiver_type=receiver,
            )
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=callee,
            receiver=receiver,
            line=line,
            form=CallForm.METHOD,
            arg_count=arg_count,
            receiver_type=_guess_receiver_type(receiver),
        )

    # Unqualified call — could be same-class method or imported static
    return RawCallSite(
        caller_qualified_name=caller_qname,
        caller_file=caller_file,
        callee_name=callee,
        receiver=None,
        line=line,
        form=CallForm.FREE,
        arg_count=arg_count,
    )


def _parse_go_call(
    node: Node, document: Any, caller_qname: str, caller_file: str, line: int,
) -> RawCallSite | None:
    """Parse Go call_expression node."""
    func_node = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    arg_count = len(args_node.named_children) if args_node else 0

    if func_node is None:
        return None

    text = document.text_for(func_node)

    if func_node.type == "selector_expression":
        # pkg.Function() or receiver.Method()
        operand = func_node.child_by_field_name("operand")
        field_node = func_node.child_by_field_name("field")
        if operand and field_node:
            receiver = document.text_for(operand)
            callee = document.text_for(field_node)
            # Package-level call (lowercase receiver = variable, uppercase = likely pkg)
            if receiver and receiver[0:1].islower() and callee[0:1].isupper():
                # Could be either pkg.Func() or var.Method()
                return RawCallSite(
                    caller_qualified_name=caller_qname,
                    caller_file=caller_file,
                    callee_name=callee,
                    receiver=receiver,
                    line=line,
                    form=CallForm.METHOD,
                    arg_count=arg_count,
                    receiver_type=receiver,
                )
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=receiver,
                line=line,
                form=CallForm.METHOD,
                arg_count=arg_count,
            )

    elif func_node.type == "identifier":
        callee = text
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=callee,
            receiver=None,
            line=line,
            form=CallForm.FREE,
            arg_count=arg_count,
        )

    return None


def _parse_js_call(
    node: Node, document: Any, caller_qname: str, caller_file: str, line: int,
) -> RawCallSite | None:
    """Parse JavaScript/TypeScript call_expression node."""
    func_node = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    arg_count = len(args_node.named_children) if args_node else 0

    if func_node is None:
        return None

    if func_node.type == "member_expression":
        obj_node = func_node.child_by_field_name("object")
        prop_node = func_node.child_by_field_name("property")
        if obj_node and prop_node:
            receiver = document.text_for(obj_node)
            callee = document.text_for(prop_node)
            if receiver == "super":
                return RawCallSite(
                    caller_qualified_name=caller_qname,
                    caller_file=caller_file,
                    callee_name=callee,
                    receiver="super",
                    line=line,
                    form=CallForm.SUPER,
                    arg_count=arg_count,
                )
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=receiver,
                line=line,
                form=CallForm.METHOD,
                arg_count=arg_count,
            )

    elif func_node.type == "identifier":
        callee = document.text_for(func_node)
        form = CallForm.CONSTRUCTOR if callee and callee[0].isupper() else CallForm.FREE
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=callee,
            receiver=None,
            line=line,
            form=form,
            arg_count=arg_count,
        )

    # Fallback
    text = document.text_for(func_node)
    if text:
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=text,
            receiver=None,
            line=line,
            form=CallForm.FREE,
            arg_count=arg_count,
        )
    return None


def _parse_cpp_call(
    node: Node, document: Any, caller_qname: str, caller_file: str, line: int,
) -> RawCallSite | None:
    """Parse C++ call_expression node."""
    func_node = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    arg_count = len(args_node.named_children) if args_node else 0

    if func_node is None:
        return None

    text = document.text_for(func_node)

    if func_node.type == "field_expression":
        # obj.method() or obj->method()
        arg_node = func_node.child_by_field_name("argument")
        field_node = func_node.child_by_field_name("field")
        if arg_node and field_node:
            receiver = document.text_for(arg_node)
            callee = document.text_for(field_node)
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=receiver,
                line=line,
                form=CallForm.METHOD,
                arg_count=arg_count,
            )

    elif func_node.type == "qualified_identifier":
        # Namespace::function() or Class::staticMethod()
        parts = text.split("::")
        if len(parts) >= 2:
            receiver = "::".join(parts[:-1])
            callee = parts[-1]
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=receiver,
                line=line,
                form=CallForm.STATIC,
                arg_count=arg_count,
                receiver_type=receiver,
            )

    elif func_node.type == "identifier":
        callee = text
        return RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=callee,
            receiver=None,
            line=line,
            form=CallForm.FREE,
            arg_count=arg_count,
        )

    return None


def _parse_constructor_node(
    node: Node, document: Any, language: str, caller_qname: str, caller_file: str,
) -> RawCallSite | None:
    """Parse constructor/new expression node."""
    line = node.start_point[0] + 1

    if language == "java":
        type_node = node.child_by_field_name("type")
        args_node = node.child_by_field_name("arguments")
        if type_node:
            callee = document.text_for(type_node)
            arg_count = len(args_node.named_children) if args_node else 0
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=None,
                line=line,
                form=CallForm.CONSTRUCTOR,
                arg_count=arg_count,
            )

    elif language in ("javascript", "typescript"):
        # new_expression has constructor field
        constructor_node = node.child_by_field_name("constructor")
        args_node = node.child_by_field_name("arguments")
        if constructor_node:
            callee = document.text_for(constructor_node)
            arg_count = len(args_node.named_children) if args_node else 0
            return RawCallSite(
                caller_qualified_name=caller_qname,
                caller_file=caller_file,
                callee_name=callee,
                receiver=None,
                line=line,
                form=CallForm.CONSTRUCTOR,
                arg_count=arg_count,
            )

    return None


def _guess_receiver_type(receiver: str) -> str | None:
    """Heuristic: guess type from receiver variable name."""
    if not receiver:
        return None
    # If receiver starts with uppercase, it's likely a type/class itself
    if receiver[0].isupper():
        return receiver
    # If receiver is 'self' or 'this', type is the enclosing class
    if receiver in ("self", "this"):
        return "__self__"
    return None


# ═══════════════════════════════════════════════════════════════════════
# Regex-based fallback extraction (when tree-sitter not available)
# ═══════════════════════════════════════════════════════════════════════

# Patterns for common call forms
_FREE_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
_METHOD_CALL_RE = re.compile(r"(\w+(?:\.\w+)*)\s*\.\s*(\w+)\s*\(")
_CONSTRUCTOR_RE = re.compile(r"\bnew\s+([A-Z]\w*)\s*\(")


def _extract_calls_from_line(
    line: str,
    language: str,
    caller_qname: str,
    caller_file: str,
    line_num: int,
    local_types: dict[str, str] | None = None,
) -> list[RawCallSite]:
    """Regex fallback for call extraction from a single line."""
    results: list[RawCallSite] = []
    local_types = local_types or {}

    # Skip keywords that look like calls
    skip_keywords = {
        "if", "while", "for", "switch", "catch", "return", "yield",
        "import", "from", "class", "def", "func", "elif", "except",
        "assert", "print",  # print is too noisy
    }

    # Constructor: new ClassName(...)
    for m in _CONSTRUCTOR_RE.finditer(line):
        results.append(RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=m.group(1),
            receiver=None,
            line=line_num,
            form=CallForm.CONSTRUCTOR,
        ))

    # Method call: receiver.method(...)
    for m in _METHOD_CALL_RE.finditer(line):
        receiver = m.group(1)
        method = m.group(2)
        if method in skip_keywords:
            continue
        # Skip if it's part of a constructor match
        full_match = m.group(0)
        if f"new {receiver}" in line:
            continue
        form = CallForm.SUPER if receiver in ("super", "super()") else CallForm.METHOD
        # Prefer an explicitly-declared local variable type over the name heuristic:
        # `lock.acquire()` where `Lock lock = new Lock(...)` was declared resolves
        # to type `Lock`, not the lowercase-name fallback (which returns None).
        receiver_type = local_types.get(receiver) or _guess_receiver_type(receiver)
        results.append(RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=method,
            receiver=receiver,
            line=line_num,
            form=form,
            receiver_type=receiver_type,
        ))

    # Free function call: func(...)
    # Only if not already captured as method call
    method_positions = {m.start(2) for m in _METHOD_CALL_RE.finditer(line)}
    for m in _FREE_CALL_RE.finditer(line):
        if m.start(1) in method_positions:
            continue
        callee = m.group(1)
        if callee in skip_keywords:
            continue
        # Skip if constructor
        if f"new {callee}" in line:
            continue
        form = CallForm.CONSTRUCTOR if callee[0:1].isupper() else CallForm.FREE
        results.append(RawCallSite(
            caller_qualified_name=caller_qname,
            caller_file=caller_file,
            callee_name=callee,
            receiver=None,
            line=line_num,
            form=form,
        ))

    return results
