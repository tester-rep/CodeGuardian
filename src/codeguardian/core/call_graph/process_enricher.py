"""Process Context Enricher — annotates findings with business process membership.

For each finding, checks if its enclosing function participates in any
detected business process. If so, attaches process metadata to help
users understand the finding's operational context.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codeguardian.core.call_graph.pci_builder import PCIResult
    from codeguardian.core.call_graph.process_detector import BusinessProcess
    from codeguardian.models.finding import Finding

logger = logging.getLogger(__name__)


def enrich_findings_with_process_context(
    findings: list[Finding],
    pci: object | None,
) -> list[Finding]:
    """Add business process context to findings whose functions participate in flows.

    Metadata added:
    - business_process: entry point function name
    - process_entry_type: HTTP_HANDLER, MQ_CONSUMER, etc.
    - process_is_sensitive: whether the flow involves sensitive operations
    - process_depth: how deep in the flow the finding sits
    """
    from codeguardian.core.call_graph.pci_builder import PCIResult

    if not isinstance(pci, PCIResult) or pci.is_empty:
        return findings

    # Build reverse index: qname → list of processes
    processes = _detect_processes(pci)
    if not processes:
        return findings

    func_to_processes: dict[str, list[dict]] = {}
    for proc in processes:
        proc_info = {
            "entry": proc.entry_point.split(".")[-1],
            "entry_type": proc.entry_type.value,
            "is_sensitive": proc.is_sensitive,
        }
        for node in proc.nodes:
            if node.qualified_name not in func_to_processes:
                func_to_processes[node.qualified_name] = []
            func_to_processes[node.qualified_name].append({
                **proc_info,
                "depth": node.depth,
            })

    # Build file→function index for finding lookup
    symbol_table = pci.symbol_table
    file_func_index: dict[str, list[tuple[int, int, str]]] = {}
    for sym in symbol_table.all_functions():
        if sym.start_line <= 0 or sym.end_line <= 0:
            continue
        if sym.file_path not in file_func_index:
            file_func_index[sym.file_path] = []
        file_func_index[sym.file_path].append(
            (sym.start_line, sym.end_line, sym.qualified_name)
        )

    enriched: list[Finding] = []
    enriched_count = 0

    for finding in findings:
        file_path = finding.location.file_path
        line = finding.location.line_start or 0

        # Find enclosing function
        qname = _find_enclosing(file_path, line, file_func_index)
        if qname is None or qname not in func_to_processes:
            enriched.append(finding)
            continue

        # Pick the most relevant process (prefer sensitive, then shallowest depth)
        proc_list = func_to_processes[qname]
        proc_list.sort(key=lambda p: (not p["is_sensitive"], p["depth"]))
        best = proc_list[0]

        meta = dict(finding.metadata) if finding.metadata else {}
        meta["business_process"] = best["entry"]
        meta["process_entry_type"] = best["entry_type"]
        meta["process_is_sensitive"] = str(best["is_sensitive"])
        meta["process_depth"] = str(best["depth"])

        enriched.append(finding.model_copy(update={"metadata": meta}))
        enriched_count += 1

    logger.info(
        "Process context enrichment: %d/%d findings linked to business processes",
        enriched_count, len(findings),
    )
    return enriched


def _detect_processes(pci: object) -> list:
    """Run ProcessDetector on PCI to get business processes."""
    try:
        from codeguardian.core.call_graph.process_detector import ProcessDetector
        detector = ProcessDetector(max_depth=8, max_processes=100)
        return detector.detect(pci)
    except Exception as e:
        logger.debug("Process detection for enrichment failed: %s", e)
        return []


def _find_enclosing(
    file_path: str,
    line: int,
    file_func_index: dict[str, list[tuple[int, int, str]]],
) -> str | None:
    """Find smallest function containing line."""
    funcs = file_func_index.get(file_path)
    if not funcs:
        return None
    best: str | None = None
    best_span = 10**9
    for start, end, qname in funcs:
        if start <= line <= end:
            span = end - start
            if span < best_span:
                best, best_span = qname, span
    return best
