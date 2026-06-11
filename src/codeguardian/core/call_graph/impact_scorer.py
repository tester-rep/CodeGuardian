"""Impact Scorer — computes blast radius for each finding using PCI call graph.

For each finding, determines how many callers (direct + transitive) are
affected. High impact findings get priority boost in reporting.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codeguardian.core.call_graph.pci_builder import PCIResult
    from codeguardian.models.finding import Finding

logger = logging.getLogger(__name__)


def enrich_findings_with_impact(
    findings: list[Finding],
    pci: object | None,
) -> list[Finding]:
    """Add impact_score and affected_callers to finding metadata.

    Uses PCI to count how many functions transitively call the function
    containing each finding. Findings in highly-called functions are more
    impactful (a bug there affects more code paths).

    Returns mutated findings list (in-place metadata update via model_copy).
    """
    from codeguardian.core.call_graph.pci_builder import PCIResult

    if not isinstance(pci, PCIResult) or pci.is_empty:
        return findings

    symbol_table = pci.symbol_table
    call_graph = pci.call_graph

    # Build a cache: file_path -> [(start, end, qualified_name)]
    file_func_index: dict[str, list[tuple[int, int, str]]] = {}
    for sym in symbol_table.all_functions():
        if sym.start_line <= 0 or sym.end_line <= 0:
            continue
        if sym.file_path not in file_func_index:
            file_func_index[sym.file_path] = []
        file_func_index[sym.file_path].append(
            (sym.start_line, sym.end_line, sym.qualified_name)
        )

    # Sort function ranges for binary search
    for funcs in file_func_index.values():
        funcs.sort(key=lambda t: (t[0], -t[1]))

    enriched: list[Finding] = []
    for finding in findings:
        file_path = finding.location.file_path
        line = finding.location.line_start or 0

        # Find enclosing function
        qname = _find_enclosing_function(file_path, line, file_func_index)
        if qname is None:
            enriched.append(finding)
            continue

        # Count callers (depth 2 = direct + one transitive hop)
        callers = call_graph.callers_of(qname, depth=2, min_confidence=0.5)
        caller_count = len(callers)

        # Compute impact score (0-100 scale)
        # 0 callers = 0, 1-3 = low (10-30), 4-10 = medium (40-60), 10+ = high (70-100)
        if caller_count == 0:
            impact_score = 0
        elif caller_count <= 3:
            impact_score = caller_count * 10
        elif caller_count <= 10:
            impact_score = 30 + (caller_count - 3) * 5
        else:
            impact_score = min(100, 65 + (caller_count - 10) * 3)

        # Update finding metadata
        meta = dict(finding.metadata) if finding.metadata else {}
        meta["impact_score"] = str(impact_score)
        meta["affected_callers"] = str(caller_count)
        meta["affected_function"] = qname

        enriched.append(finding.model_copy(update={"metadata": meta}))

    logger.info(
        "Impact enrichment: %d findings processed, avg impact=%.1f",
        len(enriched),
        sum(int(f.metadata.get("impact_score", "0")) for f in enriched) / max(len(enriched), 1),
    )
    return enriched


def _find_enclosing_function(
    file_path: str,
    line: int,
    file_func_index: dict[str, list[tuple[int, int, str]]],
) -> str | None:
    """Find the smallest function containing the given line."""
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
