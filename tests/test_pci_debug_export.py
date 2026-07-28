"""Tests for the opt-in PCI debug graph export (graph.json)."""

from __future__ import annotations

import json
from pathlib import Path

from codeguardian.core.call_graph.graph import CallEdge, CallForm, CallGraph
from codeguardian.core.call_graph.pci_builder import PCIResult
from codeguardian.core.call_graph.symbol_table import (
    Symbol,
    SymbolKind,
    SymbolTable,
)


def _graph() -> CallGraph:
    g = CallGraph()
    g.add_edge(CallEdge(
        caller="m.a", callee="m.b", call_site_line=3, call_site_file="m.py",
        call_form=CallForm.FREE, confidence=0.9,
    ))
    return g


def _symbol_table() -> SymbolTable:
    t = SymbolTable()
    t.register(Symbol(
        name="Base", qualified_name="m.Base", kind=SymbolKind.CLASS,
        file_path="m.py", start_line=1, end_line=2,
    ))
    t.register(Symbol(
        name="Child", qualified_name="m.Child", kind=SymbolKind.CLASS,
        file_path="m.py", start_line=4, end_line=5,
        parent_classes=["Base"], interfaces=["Runnable"],
    ))
    return t


def test_call_graph_to_debug_dict() -> None:
    d = _graph().to_debug_dict()
    assert d["edge_count"] == 1
    assert d["call_edges"][0]["caller"] == "m.a"
    assert d["call_edges"][0]["callee"] == "m.b"


def test_pci_result_debug_dict_has_type_edges() -> None:
    result = PCIResult(symbol_table=_symbol_table(), call_graph=_graph())
    d = result.to_debug_dict()

    kinds = {(e["type"], e["source"], e["target"]) for e in d["type_edges"]}
    assert ("inherits", "m.Child", "Base") in kinds
    assert ("implements", "m.Child", "Runnable") in kinds
    assert len(d["call_edges"]) == 1


def test_export_debug_json_writes_file(tmp_path: Path) -> None:
    result = PCIResult(symbol_table=_symbol_table(), call_graph=_graph())
    out = tmp_path / "sub" / "graph.json"

    result.export_debug_json(out)

    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["edge_count"] == 1
    assert any(e["type"] == "inherits" for e in loaded["type_edges"])
