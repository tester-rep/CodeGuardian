"""Lightweight intra-function taint analysis for Python security rules."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from codeguardian.engines.rule_helpers import RuleHit, RuleSpec

SQL_CALL_RE = re.compile(r"(?:^|\.)(?:execute|executeQuery|executeUpdate|query|raw)$", re.IGNORECASE)
SOURCE_CALL_PREFIXES = (
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.headers.get",
    "request.cookies.get",
    "request.json.get",
    "flask.request.args.get",
    "flask.request.form.get",
)
SOURCE_SUBSCRIPT_PREFIXES = {
    "os.environ",
    "environ",
    "sys.argv",
    "argv",
    "request.args",
    "request.form",
    "request.values",
    "request.headers",
    "request.cookies",
    "request.GET",
    "request.POST",
}
SANITIZER_CALLS = {
    "shlex.quote",
    "quote",
    "escape",
    "html.escape",
    "urllib.parse.quote",
    "os.path.normpath",
    "normpath",
    "os.path.abspath",
    "pathlib.Path.resolve",
    "Path.resolve",
    "resolve",
    "sanitize",
    "sanitize_path",
    "safe_join",
}
PATH_SINK_CALLS = {"open", "os.open", "Path.open", "pathlib.Path.open"}
COMMAND_SINK_CALLS = {"os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}


@dataclass(frozen=True, slots=True)
class PythonTaintRules:
    """Rule references used by the taint analyzer."""

    sql: RuleSpec
    command: RuleSpec
    path: RuleSpec


class PythonTaintAnalyzer:
    """Performs lightweight intra-function taint tracking for Python AST."""

    def __init__(self, relative_path: str, rules: PythonTaintRules) -> None:
        self.relative_path = relative_path
        self.rules = rules

    def analyze_module(self, tree: ast.Module) -> list[RuleHit]:
        """Analyze a parsed module and return taint-based rule hits."""
        hits = self._analyze_block(tree.body, "<module>", {})
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                hits.extend(self._analyze_function(node))
        return hits

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[RuleHit]:
        taint: dict[str, set[str]] = {}
        for arg in self._iter_function_args(node.args):
            taint[arg.arg] = {f"parameter `{arg.arg}`"}
        return self._analyze_block(node.body, node.name, taint)

    def _analyze_block(
        self,
        statements: list[ast.stmt],
        function_name: str,
        initial_taint: dict[str, set[str]],
    ) -> list[RuleHit]:
        taint = {name: set(labels) for name, labels in initial_taint.items()}
        hits: list[RuleHit] = []
        for stmt in statements:
            hits.extend(self._analyze_statement(stmt, function_name, taint))
        return hits

    def _analyze_statement(
        self,
        stmt: ast.stmt,
        function_name: str,
        taint: dict[str, set[str]],
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return hits
        if isinstance(stmt, ast.Assign):
            labels = self._expr_sources(stmt.value, taint)
            self._assign_targets(stmt.targets, labels, taint)
        elif isinstance(stmt, ast.AnnAssign):
            labels = self._expr_sources(stmt.value, taint)
            self._assign_name_set(self._assignment_names(stmt.target), labels, taint)
        elif isinstance(stmt, ast.AugAssign):
            labels = self._expr_sources(stmt.target, taint) | self._expr_sources(stmt.value, taint)
            self._assign_name_set(self._assignment_names(stmt.target), labels, taint)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_labels = self._expr_sources(stmt.iter, taint)
            body_taint = self._clone_taint(taint)
            self._assign_name_set(self._assignment_names(stmt.target), iter_labels, body_taint)
            hits.extend(self._analyze_block(stmt.body, function_name, body_taint))
            orelse_taint = self._clone_taint(taint)
            hits.extend(self._analyze_block(stmt.orelse, function_name, orelse_taint))
            self._merge_taint(taint, body_taint, orelse_taint)
        elif isinstance(stmt, (ast.While, ast.If)):

            body_taint = self._clone_taint(taint)
            orelse_taint = self._clone_taint(taint)
            hits.extend(self._analyze_block(stmt.body, function_name, body_taint))
            hits.extend(self._analyze_block(stmt.orelse, function_name, orelse_taint))
            self._merge_taint(taint, body_taint, orelse_taint)
        elif isinstance(stmt, ast.With):
            body_taint = self._clone_taint(taint)
            for item in stmt.items:
                if item.optional_vars is not None:
                    labels = self._expr_sources(item.context_expr, taint)
                    self._assign_name_set(self._assignment_names(item.optional_vars), labels, body_taint)
            hits.extend(self._analyze_block(stmt.body, function_name, body_taint))
            self._merge_taint(taint, body_taint)
        elif isinstance(stmt, ast.Try):
            branch_states = []
            body_taint = self._clone_taint(taint)
            hits.extend(self._analyze_block(stmt.body, function_name, body_taint))
            branch_states.append(body_taint)
            for handler in stmt.handlers:
                handler_taint = self._clone_taint(taint)
                if handler.name:
                    handler_taint[handler.name] = {f"exception `{handler.name}`"}
                hits.extend(self._analyze_block(handler.body, function_name, handler_taint))
                branch_states.append(handler_taint)
            orelse_taint = self._clone_taint(taint)
            hits.extend(self._analyze_block(stmt.orelse, function_name, orelse_taint))
            branch_states.append(orelse_taint)
            final_taint = self._clone_taint(taint)
            hits.extend(self._analyze_block(stmt.finalbody, function_name, final_taint))
            branch_states.append(final_taint)
            self._merge_taint(taint, *branch_states)

        for call in self._iter_calls(stmt):
            sink_hit = self._build_sink_hit(call, function_name, taint)
            if sink_hit is not None:
                hits.append(sink_hit)
        return hits

    def _build_sink_hit(
        self,
        call: ast.Call,
        function_name: str,
        taint: dict[str, set[str]],
    ) -> RuleHit | None:
        call_name = self._call_name(call.func)
        if self._looks_like_sql_call(call_name) and call.args:
            labels = self._expr_sources(call.args[0], taint)
            if labels:
                return self._taint_hit(self.rules.sql, call, call_name, function_name, labels)
        if self._is_command_sink(call_name, call) and call.args:
            labels = self._expr_sources(call.args[0], taint)
            if labels:
                return self._taint_hit(self.rules.command, call, call_name, function_name, labels)
        if call_name in PATH_SINK_CALLS and call.args:
            labels = self._expr_sources(call.args[0], taint)
            if labels:
                return self._taint_hit(self.rules.path, call, call_name, function_name, labels)
        return None

    def _taint_hit(
        self,
        rule: RuleSpec,
        call: ast.Call,
        sink_call: str,
        function_name: str,
        labels: set[str],
    ) -> RuleHit:
        ordered_sources = sorted(labels)
        message = (
            f"Tainted data from {', '.join(ordered_sources)} reaches sink `{sink_call}` "
            f"inside function `{function_name}`."
        )
        return RuleHit(
            rule=rule,
            file_path=self.relative_path,
            line_start=call.lineno,
            line_end=getattr(call, "end_lineno", call.lineno),
            message=message,
            language="python",
            metadata={
                "analysis": "python-taint",
                "function": function_name,
                "sink_call": sink_call,
                "sources": ordered_sources,
            },
        )

    def _expr_sources(self, expr: ast.expr | None, taint: dict[str, set[str]]) -> set[str]:
        if expr is None:
            return set()
        if isinstance(expr, ast.Name):
            return set(taint.get(expr.id, set()))
        if isinstance(expr, ast.Attribute):
            return self._expr_sources(expr.value, taint)
        if isinstance(expr, ast.Subscript):
            full_name = self._expr_name(expr.value)
            if full_name in SOURCE_SUBSCRIPT_PREFIXES:
                return {f"user input via `{full_name}`"}
            return self._expr_sources(expr.value, taint) | self._expr_sources(expr.slice, taint)
        if isinstance(expr, ast.Call):
            call_name = self._call_name(expr.func)
            if self._is_sanitizer_call(call_name):
                return set()
            source_label = self._source_label_for_call(call_name)
            nested = self._collect_arg_sources(expr.args, expr.keywords, taint)
            if source_label is not None:
                return {source_label}
            return nested
        if isinstance(expr, ast.JoinedStr):
            labels: set[str] = set()
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    labels |= self._expr_sources(value.value, taint)
            return labels
        if isinstance(expr, ast.FormattedValue):
            return self._expr_sources(expr.value, taint)
        if isinstance(expr, ast.BinOp):
            return self._expr_sources(expr.left, taint) | self._expr_sources(expr.right, taint)
        if isinstance(expr, ast.BoolOp):
            labels: set[str] = set()
            for value in expr.values:
                labels |= self._expr_sources(value, taint)
            return labels
        if isinstance(expr, ast.UnaryOp):
            return self._expr_sources(expr.operand, taint)
        if isinstance(expr, ast.Compare):
            labels = self._expr_sources(expr.left, taint)
            for comparator in expr.comparators:
                labels |= self._expr_sources(comparator, taint)
            return labels
        if isinstance(expr, ast.IfExp):
            return (
                self._expr_sources(expr.test, taint)
                | self._expr_sources(expr.body, taint)
                | self._expr_sources(expr.orelse, taint)
            )
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            labels: set[str] = set()
            for item in expr.elts:
                labels |= self._expr_sources(item, taint)
            return labels
        if isinstance(expr, ast.Dict):
            labels: set[str] = set()
            for key in expr.keys:
                labels |= self._expr_sources(key, taint)
            for value in expr.values:
                labels |= self._expr_sources(value, taint)
            return labels
        return set()

    def _collect_arg_sources(
        self,
        args: list[ast.expr],
        keywords: list[ast.keyword],
        taint: dict[str, set[str]],
    ) -> set[str]:
        labels: set[str] = set()
        for arg in args:
            labels |= self._expr_sources(arg, taint)
        for keyword in keywords:
            labels |= self._expr_sources(keyword.value, taint)
        return labels

    def _source_label_for_call(self, call_name: str) -> str | None:
        if call_name == "input":
            return "user input via `input()`"
        if call_name in {"os.getenv", "getenv", "os.environ.get", "environ.get"}:
            return f"environment input via `{call_name}`"
        if any(call_name.startswith(prefix) for prefix in SOURCE_CALL_PREFIXES):
            return f"user input via `{call_name}`"
        return None

    @staticmethod
    def _is_sanitizer_call(call_name: str) -> bool:
        return call_name in SANITIZER_CALLS or call_name.endswith((".escape", ".quote", ".sanitize"))

    @staticmethod
    def _looks_like_sql_call(call_name: str) -> bool:
        return bool(SQL_CALL_RE.search(call_name))

    @staticmethod
    def _is_command_sink(call_name: str, call: ast.Call) -> bool:
        if call_name in {"os.system", "os.popen"}:
            return True
        if call_name not in COMMAND_SINK_CALLS:
            return False
        for keyword in call.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return True
        return False

    @staticmethod
    def _iter_function_args(arguments: ast.arguments) -> list[ast.arg]:
        args = list(arguments.posonlyargs)
        args.extend(arguments.args)
        args.extend(arguments.kwonlyargs)
        if arguments.vararg is not None:
            args.append(arguments.vararg)
        if arguments.kwarg is not None:
            args.append(arguments.kwarg)
        return args

    @staticmethod
    def _iter_calls(node: ast.AST) -> list[ast.Call]:
        calls: list[ast.Call] = []
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child is not node:
                continue
            if isinstance(child, ast.Call):
                calls.append(child)
        return calls

    @staticmethod
    def _assignment_names(target: ast.expr) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute):
            return [target.attr]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for item in target.elts:
                names.extend(PythonTaintAnalyzer._assignment_names(item))
            return names
        return []

    def _assign_targets(
        self,
        targets: list[ast.expr],
        labels: set[str],
        taint: dict[str, set[str]],
    ) -> None:
        names: list[str] = []
        for target in targets:
            names.extend(self._assignment_names(target))
        self._assign_name_set(names, labels, taint)

    @staticmethod
    def _assign_name_set(names: list[str], labels: set[str], taint: dict[str, set[str]]) -> None:
        for name in names:
            if labels:
                taint[name] = set(labels)
            else:
                taint.pop(name, None)

    @staticmethod
    def _clone_taint(taint: dict[str, set[str]]) -> dict[str, set[str]]:
        return {name: set(labels) for name, labels in taint.items()}

    @staticmethod
    def _merge_taint(target: dict[str, set[str]], *branches: dict[str, set[str]]) -> None:
        for branch in branches:
            for name, labels in branch.items():
                if name in target:
                    target[name] |= labels
                else:
                    target[name] = set(labels)

    def _expr_name(self, expr: ast.expr) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            prefix = self._expr_name(expr.value)
            return f"{prefix}.{expr.attr}" if prefix else expr.attr
        return ""

    def _call_name(self, func: ast.expr) -> str:
        return self._expr_name(func)
