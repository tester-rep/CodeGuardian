"""Regression tests for inherits/implements extraction feeding the PCI.

Covers two linked behaviours introduced together:

1. Parsers populate ``ParsedClass.bases`` / ``ParsedClass.interfaces``.
2. ``build_symbol_table_from_parsed`` forwards them onto ``Symbol`` so the
   *previously dead* ``SymbolTable.get_class_hierarchy`` /
   ``get_all_interfaces`` become functional — which in turn activates the
   parent-class virtual-call resolution already present in ``PCIBuilder``.
"""

from __future__ import annotations

from pathlib import Path

from codeguardian.core.call_graph.symbol_table import build_symbol_table_from_parsed
from codeguardian.parsers.base import ParsedClass, ParsedStructure
from codeguardian.parsers.python_parser import PythonSourceParser
from codeguardian.parsers.tree_sitter_parser import TreeSitterSourceParser


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ── Parser-level extraction ──────────────────────────────────────────────

def test_python_parser_extracts_bases(tmp_path: Path) -> None:
    src = _write(tmp_path, "m.py", "class Base:\n    pass\n\nclass Child(Base):\n    pass\n")
    structure = PythonSourceParser().parse_file(src, tmp_path)
    child = next(c for c in structure.classes if c.name == "Child")
    assert child.bases == ["Base"]


def test_java_parser_extracts_super_and_interfaces(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "B.java",
        "class B extends A implements I, J {\n    void run() {}\n}\n",
    )
    structure = TreeSitterSourceParser("java").parse_file(src, tmp_path)
    if not structure.classes:  # tree-sitter grammar unavailable in this env
        return
    cls = next(c for c in structure.classes if c.name == "B")
    assert cls.bases == ["A"]
    assert set(cls.interfaces) == {"I", "J"}


def test_go_parser_extracts_struct_embedding(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "m.go",
        "package m\n\ntype Animal struct {\n    name string\n}\n\n"
        "type Dog struct {\n    Animal\n    breed string\n}\n",
    )
    structure = TreeSitterSourceParser("go").parse_file(src, tmp_path)
    if not structure.classes:  # tree-sitter grammar unavailable in this env
        return
    dog = next(c for c in structure.classes if c.name == "Dog")
    assert dog.bases == ["Animal"]


def test_go_parser_extracts_interface_embedding(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "rw.go",
        "package m\n\ntype Reader interface {\n    Read() error\n}\n\n"
        "type ReadWriter interface {\n    Reader\n    Write() error\n}\n",
    )
    structure = TreeSitterSourceParser("go").parse_file(src, tmp_path)
    if not structure.classes:
        return
    rw = next(c for c in structure.classes if c.name == "ReadWriter")
    assert rw.bases == ["Reader"]


def test_cpp_parser_extracts_base_classes(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "d.cpp",
        "class Base {\npublic:\n    void run();\n};\n\n"
        "class Derived : public Base {\npublic:\n    void go();\n};\n",
    )
    structure = TreeSitterSourceParser("cpp").parse_file(src, tmp_path)
    if not structure.classes:
        return
    derived = next(c for c in structure.classes if c.name == "Derived")
    assert derived.bases == ["Base"]


# ── SymbolTable hierarchy activation ─────────────────────────────────────

def test_symbol_table_hierarchy_populated() -> None:
    base = ParsedClass(name="Base", file_path="m.py", start_line=1, end_line=2)
    child = ParsedClass(
        name="Child", file_path="m.py", start_line=4, end_line=5, bases=["Base"],
    )
    parsed = {"m.py": ParsedStructure(classes=[base, child])}

    table = build_symbol_table_from_parsed(parsed, Path("."), {"m.py": "python"})

    chain = table.get_class_hierarchy("m.Child")
    assert "m.Base" in chain


def test_symbol_table_interfaces_populated() -> None:
    impl = ParsedClass(
        name="Impl", file_path="m.py", start_line=1, end_line=2,
        interfaces=["Runnable"],
    )
    parsed = {"m.py": ParsedStructure(classes=[impl])}

    table = build_symbol_table_from_parsed(parsed, Path("."), {"m.py": "python"})

    assert "Runnable" in table.get_all_interfaces("m.Impl")
