"""Regression: RESOURCE-NEVER-CLOSED-XFUNC must consider *callee* release paths.

Root cause (false positive): ``_detect_resource_lifecycle`` searched the
reachable set with ``direction="reverse"``, i.e. it only inspected *callers* of
the acquiring function. But the rule message claims to check "the entire
reachable call chain". A function that acquires a resource and then releases it
through a *callee* helper (e.g. ``NetworkMgr.doWork()`` closing its socket via a
private ``closeSocket()`` inside a ``finally`` block) was therefore reported as a
leak, because the release lived on the forward (callee) side that was never
traversed.

Fix: traverse both directions (callers *and* callees) when looking for a
release. A positive test guards against over-widening into a blanket exemption.
"""

from __future__ import annotations

from types import SimpleNamespace

from codeguardian.core.call_graph.cross_function_engine import CrossFunctionEngine
from codeguardian.core.call_graph.function_summary import (
    FunctionSummary,
    ResourceAction,
    ResourceKind,
)
from codeguardian.core.call_graph.graph import CallEdge, CallForm, CallGraph
from codeguardian.core.call_graph.symbol_table import Symbol, SymbolKind, SymbolTable


def _sym(qname: str, name: str, file_path: str) -> Symbol:
    return Symbol(
        name=name,
        qualified_name=qname,
        kind=SymbolKind.METHOD,
        file_path=file_path,
        start_line=1,
        end_line=50,
        class_name=qname.split(".")[0],
        module_path=qname.rsplit(".", 1)[0],
        language="java",
    )


def _resource_leak_findings(engine: CrossFunctionEngine, pci: SimpleNamespace):
    findings = engine._detect_resource_lifecycle(pci, SimpleNamespace())
    return [f for f in findings if f.rule_id == "RESOURCE-NEVER-CLOSED-XFUNC"]


def _engine() -> CrossFunctionEngine:
    engine = CrossFunctionEngine()
    engine._project_root = "."
    return engine


def test_release_via_callee_is_not_a_leak():
    """doWork() acquires a socket and closes it via callee closeSocket()."""
    summaries = {
        "NetworkMgr.doWork": FunctionSummary(
            qualified_name="NetworkMgr.doWork",
            file_path="NetworkMgr.java",
            acquires=[ResourceAction(kind=ResourceKind.STREAM, line=146)],
            has_finally=True,
        ),
        "NetworkMgr.closeSocket": FunctionSummary(
            qualified_name="NetworkMgr.closeSocket",
            file_path="NetworkMgr.java",
            releases=[ResourceAction(kind=ResourceKind.GENERIC, line=191)],
        ),
    }
    graph = CallGraph()
    graph.add_edge(CallEdge(
        caller="NetworkMgr.doWork",
        callee="NetworkMgr.closeSocket",
        call_site_line=178,
        call_site_file="NetworkMgr.java",
        call_form=CallForm.METHOD,
        confidence=0.9,
    ))
    table = SymbolTable()
    table.register(_sym("NetworkMgr.doWork", "doWork", "NetworkMgr.java"))
    table.register(_sym("NetworkMgr.closeSocket", "closeSocket", "NetworkMgr.java"))

    pci = SimpleNamespace(
        function_summaries=summaries,
        call_graph=graph,
        symbol_table=table,
    )
    assert _resource_leak_findings(_engine(), pci) == []


def test_no_release_anywhere_is_still_a_leak():
    """Guard against over-widening: a genuine leak must still be reported."""
    summaries = {
        "Cfg.loadConf": FunctionSummary(
            qualified_name="Cfg.loadConf",
            file_path="Cfg.java",
            acquires=[ResourceAction(kind=ResourceKind.FILE, line=321)],
        ),
    }
    graph = CallGraph()
    table = SymbolTable()
    table.register(_sym("Cfg.loadConf", "loadConf", "Cfg.java"))

    pci = SimpleNamespace(
        function_summaries=summaries,
        call_graph=graph,
        symbol_table=table,
    )
    leaks = _resource_leak_findings(_engine(), pci)
    assert len(leaks) == 1
    assert leaks[0].location.line_start == 321
