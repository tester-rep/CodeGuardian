"""CallGraph — directed graph of function calls with confidence-weighted edges.

Provides efficient querying: callers_of, callees_of, paths_between, reachability.
All traversals are bounded by depth and fan-out limits.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum


class CallForm(Enum):
    """Classification of a call site."""

    FREE = "free"  # standalone function call: foo()
    METHOD = "method"  # receiver.method()
    CONSTRUCTOR = "constructor"  # new Class() / Class()
    SUPER = "super"  # super.method()
    STATIC = "static"  # Class.staticMethod()


@dataclass(slots=True)
class CallEdge:
    """A directed edge in the call graph."""

    caller: str  # qualified name of calling function
    callee: str  # qualified name of called function
    call_site_line: int  # line number of the call
    call_site_file: str  # file containing the call
    call_form: CallForm = CallForm.FREE
    confidence: float = 0.5  # 0.0–1.0
    # Argument index mapping: caller_arg_position -> callee_param_position
    arg_mapping: dict[int, int] | None = None


@dataclass(slots=True)
class CallPath:
    """A path through the call graph (sequence of edges)."""

    edges: list[CallEdge] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        """Minimum confidence across all edges in the path."""
        if not self.edges:
            return 0.0
        return min(e.confidence for e in self.edges)

    @property
    def depth(self) -> int:
        return len(self.edges)

    @property
    def source(self) -> str:
        """First caller in the path."""
        return self.edges[0].caller if self.edges else ""

    @property
    def sink(self) -> str:
        """Last callee in the path."""
        return self.edges[-1].callee if self.edges else ""

    def symbols(self) -> list[str]:
        """All symbols in the path, in order."""
        if not self.edges:
            return []
        result = [self.edges[0].caller]
        for edge in self.edges:
            result.append(edge.callee)
        return result


class CallGraph:
    """Directed graph of function calls with confidence-weighted edges.

    Supports efficient querying with bounded traversals.
    Max fan-out per node during traversal is configurable.
    """

    MAX_FANOUT = 50  # max edges to follow per node in traversals
    MAX_PATHS = 20  # max paths returned by paths_between

    def __init__(self) -> None:
        # Forward edges: caller -> list[CallEdge]
        self._forward: dict[str, list[CallEdge]] = {}
        # Reverse edges: callee -> list[CallEdge]
        self._reverse: dict[str, list[CallEdge]] = {}
        # All nodes
        self._nodes: set[str] = set()
        # Entry points cache (lazily computed)
        self._entry_points: list[str] | None = None

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._forward.values())

    def add_edge(self, edge: CallEdge) -> None:
        """Add a call edge to the graph."""
        self._nodes.add(edge.caller)
        self._nodes.add(edge.callee)

        if edge.caller not in self._forward:
            self._forward[edge.caller] = []
        self._forward[edge.caller].append(edge)

        if edge.callee not in self._reverse:
            self._reverse[edge.callee] = []
        self._reverse[edge.callee].append(edge)

        # Invalidate entry points cache
        self._entry_points = None

    def callees_of(
        self,
        symbol: str,
        *,
        depth: int = 1,
        min_confidence: float = 0.0,
    ) -> list[CallEdge]:
        """Get direct (depth=1) or transitive callees of a symbol.

        Returns edges sorted by confidence (highest first).
        """
        if depth <= 0:
            return []

        if depth == 1:
            edges = self._forward.get(symbol, [])
            filtered = [e for e in edges if e.confidence >= min_confidence]
            return sorted(filtered, key=lambda e: -e.confidence)[:self.MAX_FANOUT]

        # BFS for transitive callees
        result: list[CallEdge] = []
        visited: set[str] = {symbol}
        queue: deque[tuple[str, int]] = deque([(symbol, 0)])

        while queue and len(result) < self.MAX_FANOUT * depth:
            current, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            edges = self._forward.get(current, [])
            for edge in edges:
                if edge.confidence < min_confidence:
                    continue
                result.append(edge)
                if edge.callee not in visited:
                    visited.add(edge.callee)
                    queue.append((edge.callee, current_depth + 1))

        return sorted(result, key=lambda e: -e.confidence)

    def callers_of(
        self,
        symbol: str,
        *,
        depth: int = 1,
        min_confidence: float = 0.0,
    ) -> list[CallEdge]:
        """Get direct (depth=1) or transitive callers of a symbol.

        Returns edges sorted by confidence (highest first).
        """
        if depth <= 0:
            return []

        if depth == 1:
            edges = self._reverse.get(symbol, [])
            filtered = [e for e in edges if e.confidence >= min_confidence]
            return sorted(filtered, key=lambda e: -e.confidence)[:self.MAX_FANOUT]

        # BFS for transitive callers
        result: list[CallEdge] = []
        visited: set[str] = {symbol}
        queue: deque[tuple[str, int]] = deque([(symbol, 0)])

        while queue and len(result) < self.MAX_FANOUT * depth:
            current, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            edges = self._reverse.get(current, [])
            for edge in edges:
                if edge.confidence < min_confidence:
                    continue
                result.append(edge)
                if edge.caller not in visited:
                    visited.add(edge.caller)
                    queue.append((edge.caller, current_depth + 1))

        return sorted(result, key=lambda e: -e.confidence)

    def paths_between(
        self,
        source: str,
        sink: str,
        *,
        max_depth: int = 5,
        min_confidence: float = 0.0,
    ) -> list[CallPath]:
        """Find all paths from source to sink within max_depth hops.

        Returns paths sorted by confidence (highest first), limited to MAX_PATHS.
        Uses DFS with pruning.
        """
        if source == sink:
            return []

        paths: list[CallPath] = []
        self._dfs_paths(source, sink, [], set(), max_depth, min_confidence, paths)
        paths.sort(key=lambda p: -p.confidence)
        return paths[:self.MAX_PATHS]

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path_so_far: list[CallEdge],
        visited: set[str],
        remaining_depth: int,
        min_confidence: float,
        results: list[CallPath],
    ) -> None:
        """DFS helper for path finding."""
        if remaining_depth <= 0 or len(results) >= self.MAX_PATHS:
            return

        visited.add(current)
        edges = self._forward.get(current, [])

        for edge in edges[:self.MAX_FANOUT]:
            if edge.confidence < min_confidence:
                continue

            new_path = path_so_far + [edge]

            if edge.callee == target:
                results.append(CallPath(edges=new_path))
                if len(results) >= self.MAX_PATHS:
                    break
                continue

            if edge.callee not in visited:
                self._dfs_paths(
                    edge.callee, target, new_path, visited,
                    remaining_depth - 1, min_confidence, results,
                )

        visited.discard(current)

    def reachable_from(
        self,
        symbol: str,
        *,
        max_depth: int = 3,
        min_confidence: float = 0.0,
        direction: str = "forward",
    ) -> set[str]:
        """Get all symbols reachable from a given symbol (BFS).

        direction: "forward" follows callees, "reverse" follows callers.
        """
        graph = self._forward if direction == "forward" else self._reverse
        get_next = (lambda e: e.callee) if direction == "forward" else (lambda e: e.caller)

        visited: set[str] = {symbol}
        queue: deque[tuple[str, int]] = deque([(symbol, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            edges = graph.get(current, [])
            for edge in edges[:self.MAX_FANOUT]:
                if edge.confidence < min_confidence:
                    continue
                next_sym = get_next(edge)
                if next_sym not in visited:
                    visited.add(next_sym)
                    queue.append((next_sym, depth + 1))

        visited.discard(symbol)  # Don't include the starting node
        return visited

    def entry_points(self) -> list[str]:
        """Get nodes with no incoming edges (or only low-confidence incoming).

        These are likely entry points: main(), HTTP handlers, test functions, etc.
        """
        if self._entry_points is not None:
            return self._entry_points

        # Nodes with no callers at confidence >= 0.5
        entry = []
        for node in self._nodes:
            callers = self._reverse.get(node, [])
            if not any(e.confidence >= 0.5 for e in callers):
                entry.append(node)

        self._entry_points = entry
        return entry

    def has_node(self, symbol: str) -> bool:
        """Check if a symbol is in the graph."""
        return symbol in self._nodes

    def direct_callees(self, symbol: str) -> list[str]:
        """Get callee names only (no edge metadata). Convenience method."""
        return [e.callee for e in self._forward.get(symbol, [])]

    def direct_callers(self, symbol: str) -> list[str]:
        """Get caller names only (no edge metadata). Convenience method."""
        return [e.caller for e in self._reverse.get(symbol, [])]

    def to_debug_dict(self) -> dict:
        """Serialise the call graph to a plain dict for JSON debug export.

        Not used in the scan hot path — intended for troubleshooting PCI
        resolution (see PCIResult.export_debug_json).
        """
        edges = [
            {
                "caller": e.caller,
                "callee": e.callee,
                "line": e.call_site_line,
                "file": e.call_site_file,
                "form": e.call_form.value,
                "confidence": round(e.confidence, 3),
            }
            for edge_list in self._forward.values()
            for e in edge_list
        ]
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": sorted(self._nodes),
            "call_edges": edges,
        }
