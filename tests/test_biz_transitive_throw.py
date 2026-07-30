"""Regression: BIZ-PARTIAL-FAILURE-RISK must consider transitive throws.

Root cause (漏报 root cause #2): ``transitive_may_throw`` is propagated along
call edges (``pci_builder._propagate_summaries``) but the transaction-consistency
check only read the *local* ``may_throw``. A middle function that itself does not
raise, yet transitively propagates an uncaught exception from a deeper callee,
was invisible — so a real "write → (transitively throwing call) → write" flow was
reported merely as BIZ-NO-TRANSACTION-BOUNDARY instead of the more severe
BIZ-PARTIAL-FAILURE-RISK.

Fix: ``_check_transaction_consistency`` now reads
``s.may_throw or s.transitive_may_throw``.
"""

from __future__ import annotations

from types import SimpleNamespace

from codeguardian.core.call_graph.function_summary import FunctionSummary
from codeguardian.core.call_graph.process_analyzer import ProcessAnalyzer
from codeguardian.core.call_graph.process_detector import (
    BusinessProcess,
    EntryType,
)


def _make_process() -> BusinessProcess:
    process = BusinessProcess(
        entry_point="svc.handle",
        entry_type=EntryType.PUBLIC_API,
        entry_file="Svc.java",
        entry_line=10,
    )
    process.all_functions = {"svc.handle", "svc.mid", "dao.saveA", "dao.saveB"}
    process.write_operations = ["dao.saveA", "dao.saveB"]  # has_multiple_writes → True
    process.has_transaction = False
    process.max_depth = 3
    return process


def _pci(summaries: dict[str, FunctionSummary]) -> SimpleNamespace:
    entry_sym = SimpleNamespace(name="handle", file_path="Svc.java", start_line=10)
    symbol_table = SimpleNamespace(lookup=lambda name: entry_sym)
    return SimpleNamespace(function_summaries=summaries, symbol_table=symbol_table)


def test_transitive_throw_triggers_partial_failure_risk():
    """Middle function with only transitive_may_throw must trigger PARTIAL-FAILURE."""
    summaries = {
        "svc.mid": FunctionSummary(
            qualified_name="svc.mid", file_path="Svc.java",
            # No local throw; the exception only bubbles up transitively.
            transitive_may_throw={"IOException"},
        ),
        "dao.saveA": FunctionSummary(
            qualified_name="dao.saveA", file_path="Dao.java", is_sink=True,
        ),
        "dao.saveB": FunctionSummary(
            qualified_name="dao.saveB", file_path="Dao.java", is_sink=True,
        ),
    }
    process = _make_process()

    findings = ProcessAnalyzer()._check_transaction_consistency(process, _pci(summaries))

    rule_ids = {f.rule_id for f in findings}
    assert "BIZ-PARTIAL-FAILURE-RISK" in rule_ids
    assert "BIZ-NO-TRANSACTION-BOUNDARY" not in rule_ids


def test_no_throw_falls_back_to_no_transaction_boundary():
    """Guard: without any (local or transitive) throw it stays NO-TRANSACTION-BOUNDARY."""
    summaries = {
        "svc.mid": FunctionSummary(
            qualified_name="svc.mid", file_path="Svc.java",
            # Neither local nor transitive throw.
        ),
        "dao.saveA": FunctionSummary(
            qualified_name="dao.saveA", file_path="Dao.java", is_sink=True,
        ),
        "dao.saveB": FunctionSummary(
            qualified_name="dao.saveB", file_path="Dao.java", is_sink=True,
        ),
    }
    process = _make_process()

    findings = ProcessAnalyzer()._check_transaction_consistency(process, _pci(summaries))

    rule_ids = {f.rule_id for f in findings}
    assert "BIZ-PARTIAL-FAILURE-RISK" not in rule_ids
    assert "BIZ-NO-TRANSACTION-BOUNDARY" in rule_ids
