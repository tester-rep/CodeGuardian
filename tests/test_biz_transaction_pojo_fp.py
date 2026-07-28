"""Regression: POJO setters must NOT be classified as transaction-relevant writes.

Root cause (BIZ-NO-TRANSACTION-BOUNDARY false positives): a function that only
writes instance fields (``this.x = y`` — a POJO setter) had ``writes_fields``
non-empty, which ``_compute_aggregated_properties`` counted as a "write
operation". Two setters on a DTO (e.g. ``GridRes`` / ``GridRowData``) then
tripped ``has_multiple_writes`` and were flagged as a business process lacking a
transaction boundary. In-memory field mutation is NOT persistence and never
needs a DB transaction; only real sinks (SQL/command via ``is_sink``) or
write-token method names (save/insert/update/persist/commit...) are
transaction-relevant.
"""

from __future__ import annotations

from types import SimpleNamespace

from codeguardian.core.call_graph.process_detector import (
    BusinessProcess,
    EntryType,
    ProcessDetector,
)
from codeguardian.core.call_graph.function_summary import FunctionSummary


def _make_process(func_names: list[str]) -> BusinessProcess:
    process = BusinessProcess(
        entry_point=func_names[0],
        entry_type=EntryType.PUBLIC_API,
        entry_file="GridRes.java",
        entry_line=1,
    )
    process.all_functions = set(func_names)
    return process


def _pci_stub() -> SimpleNamespace:
    # _detect_flow_properties_from_source reads pci.file_lines; empty dict makes
    # it a no-op so write_operations is populated solely by field/sink signals.
    return SimpleNamespace(file_lines={})


def test_pojo_setters_are_not_transaction_writes():
    """Two setters that only write instance fields must not count as writes."""
    detector = ProcessDetector()
    summaries = {
        "GridRes.setInfor": FunctionSummary(
            qualified_name="GridRes.setInfor", file_path="GridRes.java",
            writes_fields={"infor"},
        ),
        "GridRes.setDetail": FunctionSummary(
            qualified_name="GridRes.setDetail", file_path="GridRes.java",
            writes_fields={"detail"},
        ),
    }
    process = _make_process(["GridRes.setInfor", "GridRes.setDetail"])

    detector._compute_aggregated_properties(process, summaries, _pci_stub())

    assert process.write_operations == []
    assert process.has_multiple_writes is False


def test_real_sinks_still_counted_as_writes():
    """Guard against over-narrowing: real sinks must remain write operations."""
    detector = ProcessDetector()
    summaries = {
        "dao.saveOrder": FunctionSummary(
            qualified_name="dao.saveOrder", file_path="OrderDao.java",
            is_sink=True,
        ),
        "dao.saveItem": FunctionSummary(
            qualified_name="dao.saveItem", file_path="OrderDao.java",
            is_sink=True,
        ),
    }
    process = _make_process(["dao.saveOrder", "dao.saveItem"])

    detector._compute_aggregated_properties(process, summaries, _pci_stub())

    assert set(process.write_operations) == {"dao.saveOrder", "dao.saveItem"}
    assert process.has_multiple_writes is True
