"""Tests for the Project Call Graph Index (PCI) infrastructure."""

from __future__ import annotations

import pytest
from pathlib import Path

from codeguardian.core.call_graph.symbol_table import (
    Symbol,
    SymbolKind,
    SymbolTable,
    Visibility,
    Parameter,
    build_symbol_table_from_parsed,
    _file_to_module_path,
)
from codeguardian.core.call_graph.graph import CallEdge, CallForm, CallGraph, CallPath
from codeguardian.core.call_graph.function_summary import (
    FunctionSummary,
    compute_local_summary,
    ResourceKind,
)
from codeguardian.core.call_graph.call_extractor import (
    extract_call_sites_from_source,
    RawCallSite,
)
from codeguardian.core.call_graph.import_resolver import (
    PythonImportResolver,
    JavaImportResolver,
    GoImportResolver,
)


# ═══════════════════════════════════════════════════════════════════════
# SymbolTable Tests
# ═══════════════════════════════════════════════════════════════════════


class TestSymbolTable:
    def test_register_and_lookup(self):
        table = SymbolTable()
        sym = Symbol(
            name="findUser",
            qualified_name="app.dao.UserDAO.findUser",
            kind=SymbolKind.METHOD,
            file_path="src/dao/user_dao.py",
            start_line=10,
            end_line=20,
            class_name="UserDAO",
            module_path="app.dao",
            language="python",
        )
        table.register(sym)
        assert table.lookup("app.dao.UserDAO.findUser") is sym
        assert table.size == 1

    def test_lookup_by_name(self):
        table = SymbolTable()
        sym1 = Symbol(
            name="process",
            qualified_name="app.service.process",
            kind=SymbolKind.FUNCTION,
            file_path="src/service.py",
            start_line=1,
            end_line=10,
            module_path="app.service",
            language="python",
        )
        sym2 = Symbol(
            name="process",
            qualified_name="app.worker.process",
            kind=SymbolKind.FUNCTION,
            file_path="src/worker.py",
            start_line=5,
            end_line=15,
            module_path="app.worker",
            language="python",
        )
        table.register(sym1)
        table.register(sym2)

        results = table.lookup_by_name("process")
        assert len(results) == 2

        # With context file, same-file is prioritized
        results = table.lookup_by_name("process", context_file="src/service.py")
        assert results[0].qualified_name == "app.service.process"

    def test_class_hierarchy(self):
        table = SymbolTable()
        table.register(Symbol(
            name="Animal",
            qualified_name="app.models.Animal",
            kind=SymbolKind.CLASS,
            file_path="models.py",
            start_line=1,
            end_line=10,
            module_path="app.models",
            language="python",
        ))
        table.register(Symbol(
            name="Dog",
            qualified_name="app.models.Dog",
            kind=SymbolKind.CLASS,
            file_path="models.py",
            start_line=12,
            end_line=20,
            module_path="app.models",
            parent_classes=["app.models.Animal"],
            language="python",
        ))

        hierarchy = table.get_class_hierarchy("app.models.Dog")
        assert hierarchy == ["app.models.Dog", "app.models.Animal"]

    def test_lookup_methods(self):
        table = SymbolTable()
        table.register(Symbol(
            name="get",
            qualified_name="app.dao.UserDAO.get",
            kind=SymbolKind.METHOD,
            file_path="dao.py",
            start_line=5,
            end_line=10,
            class_name="UserDAO",
            module_path="app.dao",
            language="python",
        ))
        table.register(Symbol(
            name="save",
            qualified_name="app.dao.UserDAO.save",
            kind=SymbolKind.METHOD,
            file_path="dao.py",
            start_line=12,
            end_line=20,
            class_name="UserDAO",
            module_path="app.dao",
            language="python",
        ))

        methods = table.lookup_methods("app.dao.UserDAO")
        assert len(methods) == 2
        assert {m.name for m in methods} == {"get", "save"}


# ═══════════════════════════════════════════════════════════════════════
# CallGraph Tests
# ═══════════════════════════════════════════════════════════════════════


class TestCallGraph:
    def test_add_edge_and_query(self):
        graph = CallGraph()
        edge = CallEdge(
            caller="app.service.process",
            callee="app.dao.findUser",
            call_site_line=15,
            call_site_file="service.py",
            confidence=0.9,
        )
        graph.add_edge(edge)

        assert graph.node_count == 2
        assert graph.edge_count == 1

        callees = graph.callees_of("app.service.process")
        assert len(callees) == 1
        assert callees[0].callee == "app.dao.findUser"

        callers = graph.callers_of("app.dao.findUser")
        assert len(callers) == 1
        assert callers[0].caller == "app.service.process"

    def test_paths_between(self):
        graph = CallGraph()
        graph.add_edge(CallEdge("A", "B", 1, "f1.py", confidence=0.9))
        graph.add_edge(CallEdge("B", "C", 2, "f2.py", confidence=0.8))
        graph.add_edge(CallEdge("A", "C", 3, "f1.py", confidence=0.7))

        paths = graph.paths_between("A", "C")
        assert len(paths) == 2
        # Direct path (A→C) should have higher confidence than indirect (A→B→C)
        direct = [p for p in paths if p.depth == 1]
        indirect = [p for p in paths if p.depth == 2]
        assert len(direct) == 1
        assert len(indirect) == 1

    def test_reachable_from(self):
        graph = CallGraph()
        graph.add_edge(CallEdge("A", "B", 1, "f.py", confidence=0.9))
        graph.add_edge(CallEdge("B", "C", 2, "f.py", confidence=0.9))
        graph.add_edge(CallEdge("C", "D", 3, "f.py", confidence=0.9))

        reachable = graph.reachable_from("A", max_depth=2)
        assert "B" in reachable
        assert "C" in reachable
        assert "D" not in reachable  # Depth 3, beyond max_depth=2

    def test_entry_points(self):
        graph = CallGraph()
        graph.add_edge(CallEdge("main", "process", 1, "f.py", confidence=0.9))
        graph.add_edge(CallEdge("process", "helper", 2, "f.py", confidence=0.9))

        entries = graph.entry_points()
        assert "main" in entries
        assert "process" not in entries


# ═══════════════════════════════════════════════════════════════════════
# FunctionSummary Tests
# ═══════════════════════════════════════════════════════════════════════


class TestFunctionSummary:
    def test_null_return_python(self):
        lines = [
            "def find_user(user_id):",
            "    user = db.get(user_id)",
            "    if user is None:",
            "        return None",
            "    return user",
        ]
        summary = compute_local_summary(
            "app.find_user", "app.py", lines, 1, 5, "python",
        )
        assert summary.may_return_null is True
        assert 4 in summary.null_return_lines

    def test_exception_detection_python(self):
        lines = [
            "def validate(data):",
            "    if not data:",
            "        raise ValueError('empty')",
            "    return True",
        ]
        summary = compute_local_summary(
            "app.validate", "app.py", lines, 1, 4, "python",
        )
        assert "ValueError" in summary.may_throw

    def test_resource_detection_python(self):
        lines = [
            "def read_file(path):",
            "    f = open(path, 'r')",
            "    data = f.read()",
            "    return data",
        ]
        summary = compute_local_summary(
            "app.read_file", "app.py", lines, 1, 4, "python",
        )
        assert len(summary.acquires) == 1
        assert summary.acquires[0].kind == ResourceKind.FILE
        assert summary.requires_cleanup is True

    def test_resource_with_context_manager(self):
        lines = [
            "def read_file(path):",
            "    with open(path, 'r') as f:",
            "        return f.read()",
        ]
        summary = compute_local_summary(
            "app.read_file", "app.py", lines, 1, 3, "python",
        )
        assert summary.uses_context_manager is True

    def test_taint_source_detection(self):
        lines = [
            "def get_user_input():",
            "    name = request.args.get('name')",
            "    return name",
        ]
        summary = compute_local_summary(
            "app.get_user_input", "app.py", lines, 1, 3, "python",
        )
        assert summary.is_source is True

    def test_taint_sink_detection(self):
        lines = [
            "def run_query(sql):",
            "    cursor.execute(sql)",
            "    return cursor.fetchall()",
        ]
        summary = compute_local_summary(
            "app.run_query", "app.py", lines, 1, 3, "python",
        )
        assert summary.is_sink is True

    def test_lock_detection(self):
        lines = [
            "def process(self):",
            "    self.lock.acquire()",
            "    result = self.do_work()",
            "    return result",
        ]
        summary = compute_local_summary(
            "app.Service.process", "app.py", lines, 1, 4, "python",
        )
        assert summary.acquires_lock is not None


# ═══════════════════════════════════════════════════════════════════════
# Call Site Extraction Tests
# ═══════════════════════════════════════════════════════════════════════


class TestCallExtractor:
    def test_python_free_call(self):
        lines = [
            "def main():",
            "    result = process_data(input_data)",
            "    return result",
        ]
        sites = extract_call_sites_from_source(
            lines, "python", "app.main", "app.py", 1,
        )
        free_calls = [s for s in sites if s.form == CallForm.FREE]
        assert any(s.callee_name == "process_data" for s in free_calls)

    def test_python_method_call(self):
        lines = [
            "def handle(self):",
            "    user = self.dao.find_user(user_id)",
            "    return user",
        ]
        sites = extract_call_sites_from_source(
            lines, "python", "app.Handler.handle", "app.py", 1,
        )
        method_calls = [s for s in sites if s.form == CallForm.METHOD]
        assert any(s.callee_name == "find_user" for s in method_calls)

    def test_python_constructor(self):
        lines = [
            "def create():",
            "    obj = MyService(config)",
            "    return obj",
        ]
        sites = extract_call_sites_from_source(
            lines, "python", "app.create", "app.py", 1,
        )
        constructors = [s for s in sites if s.form == CallForm.CONSTRUCTOR]
        assert any(s.callee_name == "MyService" for s in constructors)


# ═══════════════════════════════════════════════════════════════════════
# Import Resolver Tests
# ═══════════════════════════════════════════════════════════════════════


class TestPythonImportResolver:
    def test_from_import(self):
        resolver = PythonImportResolver(Path("/project"))
        lines = [
            "from app.dao import UserDAO",
            "from app.service import process_user",
        ]
        results = resolver.resolve_imports("src/handler.py", lines, {})
        assert len(results) == 2
        assert results[0].local_name == "UserDAO"
        assert results[0].qualified_name == "app.dao.UserDAO"
        assert results[1].local_name == "process_user"
        assert results[1].qualified_name == "app.service.process_user"

    def test_import_as(self):
        resolver = PythonImportResolver(Path("/project"))
        lines = [
            "from app.dao import UserDAO as DAO",
        ]
        results = resolver.resolve_imports("src/handler.py", lines, {})
        assert results[0].local_name == "DAO"
        assert results[0].qualified_name == "app.dao.UserDAO"

    def test_plain_import(self):
        resolver = PythonImportResolver(Path("/project"))
        lines = [
            "import os.path",
        ]
        results = resolver.resolve_imports("app.py", lines, {})
        assert results[0].local_name == "path"
        assert results[0].qualified_name == "os.path"


class TestJavaImportResolver:
    def test_specific_import(self):
        resolver = JavaImportResolver(Path("/project"))
        lines = [
            "package com.app.service;",
            "import com.app.dao.UserDAO;",
            "import java.util.List;",
        ]
        results = resolver.resolve_imports("src/main/java/com/app/service/UserService.java", lines, {})
        # Should find UserDAO and List (plus java.lang.* implicit)
        named_imports = [r for r in results if not r.is_wildcard and r.module_path != "java.lang"]
        user_dao = [r for r in named_imports if r.local_name == "UserDAO"]
        assert len(user_dao) == 1
        assert user_dao[0].qualified_name == "com.app.dao.UserDAO"


class TestGoImportResolver:
    def test_single_import(self):
        resolver = GoImportResolver(Path("/project"), module_name="github.com/app")
        lines = [
            'import "github.com/app/dao"',
        ]
        results = resolver.resolve_imports("service/handler.go", lines, {})
        assert len(results) == 1
        assert results[0].local_name == "dao"
        assert results[0].qualified_name == "github.com/app/dao"

    def test_import_block(self):
        resolver = GoImportResolver(Path("/project"), module_name="github.com/app")
        lines = [
            "import (",
            '    "fmt"',
            '    "github.com/app/dao"',
            '    custom "github.com/app/utils"',
            ")",
        ]
        results = resolver.resolve_imports("main.go", lines, {})
        assert len(results) == 3
        assert results[0].local_name == "fmt"
        assert results[1].local_name == "dao"
        assert results[2].local_name == "custom"


# ═══════════════════════════════════════════════════════════════════════
# Module Path Conversion Tests
# ═══════════════════════════════════════════════════════════════════════


class TestModulePath:
    def test_python_module_path(self):
        assert _file_to_module_path("src/app/dao/user_dao.py", "python") == "app.dao.user_dao"
        assert _file_to_module_path("app/service.py", "python") == "app.service"
        assert _file_to_module_path("src/app/__init__.py", "python") == "app"

    def test_java_module_path(self):
        assert _file_to_module_path("src/main/java/com/app/dao/UserDAO.java", "java") == "com.app.dao.UserDAO"

    def test_go_module_path(self):
        assert _file_to_module_path("pkg/dao/user.go", "go") == "pkg/dao"
        assert _file_to_module_path("main.go", "go") == ""
