"""Project Call Graph Index (PCI) — cross-function/file call analysis infrastructure.

Provides:
- SymbolTable: project-wide symbol registry
- CallGraph: directed graph of function calls with confidence-weighted edges
- FunctionSummary: per-function behavioral summaries (null/throw/resource/taint)
- PCIBuilder: orchestrates full PCI construction from project source
"""

from codeguardian.core.call_graph.symbol_table import (
    Symbol,
    SymbolKind,
    SymbolTable,
    Visibility,
)
from codeguardian.core.call_graph.graph import CallEdge, CallForm, CallGraph, CallPath
from codeguardian.core.call_graph.function_summary import FunctionSummary, TaintFlow
from codeguardian.core.call_graph.pci_builder import PCIBuilder

__all__ = [
    "CallEdge",
    "CallForm",
    "CallGraph",
    "CallPath",
    "FunctionSummary",
    "PCIBuilder",
    "Symbol",
    "SymbolKind",
    "SymbolTable",
    "TaintFlow",
    "Visibility",
]
