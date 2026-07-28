"""Regression: ``field.method()`` / ``localVar.method()`` must resolve by *type*, not name.

Root cause (13 cross-function bugs missed on benchmark-java): a method call on a
lowercase receiver such as ``accountDao.deduct(...)`` / ``processor.process(...)``
/ ``lock.acquire(...)`` had no receiver type — ``_guess_receiver_type`` only maps
Capitalized names to types — so ``_resolve_method_call`` fell through to a global
name search and returned confidence 0.50, below the 0.7 threshold every
cross-function rule requires. The call edge was silently dropped.

Fix (two linked channels):
1. Field-type channel — parsers extract ``ParsedClass.field_types`` (field name →
   declared type), forwarded onto ``Symbol``; ``_resolve_method_call`` resolves a
   receiver that matches a declared field of the caller's class via that type.
2. Local-declaration channel — ``extract_call_sites_from_source`` pre-scans the
   enclosing function body for explicit ``Type var = ...`` declarations and types
   the receiver accordingly (covers ``Lock lock = new Lock(...)``).

These tests pin both channels so a future refactor cannot silently regress
benchmark-java back to 0.50-confidence (dropped) edges.
"""

from __future__ import annotations

from pathlib import Path

from codeguardian.core.call_graph.call_extractor import (
    RawCallSite,
    extract_call_sites_from_source,
)
from codeguardian.core.call_graph.graph import CallForm
from codeguardian.core.call_graph.pci_builder import PCIBuilder
from codeguardian.core.call_graph.symbol_table import (
    Symbol,
    SymbolKind,
    SymbolTable,
    build_symbol_table_from_parsed,
)
from codeguardian.parsers.base import ParsedClass, ParsedFunction, ParsedStructure
from codeguardian.parsers.tree_sitter_parser import TreeSitterSourceParser


# ── Parser-level field type extraction ──────────────────────────────────

def test_java_parser_extracts_field_types(tmp_path: Path) -> None:
    src = tmp_path / "PaymentService.java"
    src.write_text(
        "public class PaymentService {\n"
        "    private final AccountDao accountDao;\n"
        "    private final TransactionDao transactionDao;\n"
        "    void transfer() {}\n"
        "}\n",
        encoding="utf-8",
    )
    structure = TreeSitterSourceParser("java").parse_file(src, tmp_path)
    if not structure.classes:  # tree-sitter grammar unavailable in this env
        return
    cls = next(c for c in structure.classes if c.name == "PaymentService")
    assert cls.field_types.get("accountDao") == "AccountDao"
    assert cls.field_types.get("transactionDao") == "TransactionDao"


def test_java_parser_generic_field_keeps_raw_head(tmp_path: Path) -> None:
    src = tmp_path / "Repo.java"
    src.write_text(
        "public class Repo {\n"
        "    private List<Foo> foos;\n"
        "}\n",
        encoding="utf-8",
    )
    structure = TreeSitterSourceParser("java").parse_file(src, tmp_path)
    if not structure.classes:
        return
    cls = next(c for c in structure.classes if c.name == "Repo")
    assert cls.field_types.get("foos") == "List"


# ── SymbolTable forwarding ───────────────────────────────────────────────

def test_symbol_table_forwards_field_types() -> None:
    path = "src/main/java/paygw/PaymentService.java"  # package dir => module_path=paygw
    cls = ParsedClass(
        name="PaymentService", file_path=path,
        start_line=1, end_line=5,
        field_types={"accountDao": "AccountDao"},
    )
    parsed = {path: ParsedStructure(classes=[cls])}

    table = build_symbol_table_from_parsed(parsed, Path("."), {path: "java"})

    sym = table.lookup("paygw.PaymentService")
    assert sym is not None
    assert sym.field_types == {"accountDao": "AccountDao"}


# ── Local declaration pre-scan ───────────────────────────────────────────

def test_local_declaration_types_collected_for_java() -> None:
    lines = [
        "public void executeUnderLock(String resourceId) {",
        "    Lock lock = new Lock(resourceId);",
        "    lock.acquire();",
        "}",
    ]
    sites = extract_call_sites_from_source(
        lines, "java", "DistributedLockManager.executeUnderLock",
        "DistributedLockManager.java", 1,
    )
    acquire = next(s for s in sites if s.callee_name == "acquire")
    assert acquire.form == CallForm.METHOD
    assert acquire.receiver == "lock"
    assert acquire.receiver_type == "Lock"


def test_local_declaration_scan_skipped_for_python() -> None:
    # Python has no `Type var` declaration form; the pre-scan must be a no-op.
    lines = ["def f():", "    lock.acquire()"]
    sites = extract_call_sites_from_source(
        lines, "python", "m.f", "m.py", 1,
    )
    acquire = next(s for s in sites if s.callee_name == "acquire")
    assert acquire.receiver_type is None


# ── End-to-end resolution confidence ────────────────────────────────────

def _payment_service_table() -> SymbolTable:
    """SymbolTable mirroring benchmark-java's PaymentService + AccountDao."""
    table = SymbolTable()
    table.register(Symbol(
        name="PaymentService", qualified_name="paygw.PaymentService",
        kind=SymbolKind.CLASS, file_path="PaymentService.java",
        start_line=10, end_line=41, module_path="paygw",
        language="java",
        field_types={"accountDao": "AccountDao", "transactionDao": "TransactionDao"},
    ))
    table.register(Symbol(
        name="AccountDao", qualified_name="paygw.AccountDao",
        kind=SymbolKind.CLASS, file_path="AccountDao.java",
        start_line=1, end_line=50, module_path="paygw", language="java",
    ))
    table.register(Symbol(
        name="transfer", qualified_name="paygw.PaymentService.transfer",
        kind=SymbolKind.METHOD, file_path="PaymentService.java",
        start_line=20, end_line=40, class_name="PaymentService",
        module_path="paygw", language="java",
    ))
    table.register(Symbol(
        name="deduct", qualified_name="paygw.AccountDao.deduct",
        kind=SymbolKind.METHOD, file_path="AccountDao.java",
        start_line=5, end_line=15, class_name="AccountDao",
        module_path="paygw", language="java",
    ))
    return table


def test_field_receiver_resolves_above_threshold() -> None:
    """``accountDao.deduct()`` must clear the 0.7 cross-function threshold."""
    table = _payment_service_table()
    builder = PCIBuilder(use_cache=False)
    site = RawCallSite(
        caller_qualified_name="paygw.PaymentService.transfer",
        caller_file="PaymentService.java",
        callee_name="deduct", receiver="accountDao",
        line=25, form=CallForm.METHOD,
        receiver_type=None,  # lowercase name: heuristic yields nothing
    )

    targets = builder._resolve_method_call(site, table, {})

    assert targets, "field receiver should resolve to AccountDao.deduct"
    qname, conf = targets[0]
    assert qname == "paygw.AccountDao.deduct"
    assert conf >= 0.7, f"edge would be dropped below threshold: {conf}"


def test_this_qualified_field_receiver_resolves() -> None:
    """``this.accountDao.deduct()`` resolves via the same field-type channel."""
    table = _payment_service_table()
    builder = PCIBuilder(use_cache=False)
    site = RawCallSite(
        caller_qualified_name="paygw.PaymentService.transfer",
        caller_file="PaymentService.java",
        callee_name="deduct", receiver="this.accountDao",
        line=25, form=CallForm.METHOD,
        receiver_type=None,
    )

    targets = builder._resolve_method_call(site, table, {})

    assert targets
    assert targets[0][0] == "paygw.AccountDao.deduct"
    assert targets[0][1] >= 0.7


def test_unknown_field_still_falls_back_safely() -> None:
    """Guard against over-widening: a receiver that is NOT a declared field must
    not gain field-type confidence; it keeps the old low-confidence fallback."""
    table = _payment_service_table()
    builder = PCIBuilder(use_cache=False)
    site = RawCallSite(
        caller_qualified_name="paygw.PaymentService.transfer",
        caller_file="PaymentService.java",
        callee_name="deduct", receiver="someOtherDao",  # not a declared field
        line=25, form=CallForm.METHOD,
        receiver_type=None,
    )

    targets = builder._resolve_method_call(site, table, {})

    # Falls to the global unique-method fallback (0.50), NOT the field channel.
    for _qname, conf in targets:
        assert conf < 0.7, f"non-field receiver must not be promoted: {conf}"
