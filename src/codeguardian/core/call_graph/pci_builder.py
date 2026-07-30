"""PCIBuilder — orchestrates full Project Call Graph Index construction.

Builds SymbolTable + CallGraph + FunctionSummaries from project source,
then attaches them to ScanContext for use by detection engines.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING

from codeguardian.core.call_graph.call_extractor import (
    RawCallSite,
    extract_call_sites_from_source,
)
from codeguardian.core.call_graph.function_summary import (
    FunctionSummary,
    compute_local_summary,
)
from codeguardian.core.call_graph.graph import CallEdge, CallForm, CallGraph
from codeguardian.core.call_graph.import_resolver import (
    ResolvedImport,
    get_resolver,
)
from codeguardian.core.call_graph.symbol_table import (
    Symbol,
    SymbolKind,
    SymbolTable,
    build_symbol_table_from_parsed,
)

if TYPE_CHECKING:
    from codeguardian.core.context import ScanContext

logger = logging.getLogger(__name__)

# Supported languages for PCI (Phase 1: Python/Java/Go)
PCI_LANGUAGES = {"python", "java", "go", "javascript", "typescript", "cpp", "csharp"}

# Max files to process for PCI construction
DEFAULT_MAX_FILES = 5000


class PCIBuilder:
    """Builds the Project Call Graph Index from project source files.

    Pipeline:
    1. Parse all files → extract structure (reuses tree-sitter)
    2. Build symbol table
    3. Resolve imports
    4. Extract call sites
    5. Resolve call targets → build CallGraph
    6. Compute function summaries
    """

    def __init__(
        self,
        max_files: int = DEFAULT_MAX_FILES,
        min_confidence: float = 0.5,
        max_depth: int = 3,
        use_cache: bool = True,
    ) -> None:
        self.max_files = max_files
        self.min_confidence = min_confidence
        self.max_depth = max_depth
        self.use_cache = use_cache

    def build(self, ctx: ScanContext) -> PCIResult:
        """Build the full PCI for the given scan context.

        Returns PCIResult containing symbol_table, call_graph, and summaries.
        Uses file-content-hash cache when available to skip unchanged files.
        """
        from codeguardian.core.call_graph.pci_cache import PCICache, compute_file_hash

        start_time = time.monotonic()
        project_root = Path(ctx.project_root)

        # Initialize cache
        cache = PCICache(project_root, enabled=self.use_cache)
        cache.load()

        # Step 1: Collect and parse files (with cache awareness)
        file_structures, language_map, file_lines = self._parse_project_files(
            ctx, project_root, cache,
        )
        parse_time = time.monotonic() - start_time

        if not file_structures:
            logger.warning("PCI: No parseable files found")
            return PCIResult.empty()

        # Step 2: Build symbol table
        symbol_table = build_symbol_table_from_parsed(file_structures, project_root, language_map)
        symbol_time = time.monotonic() - start_time - parse_time

        # Step 3: Resolve imports per file
        file_imports = self._resolve_all_imports(
            file_lines, language_map, project_root,
        )
        import_time = time.monotonic() - start_time - parse_time - symbol_time

        # Step 4: Extract call sites from all functions
        raw_call_sites = self._extract_all_call_sites(
            symbol_table, file_lines, language_map,
        )

        # Step 5: Resolve call targets → build graph
        call_graph = self._resolve_and_build_graph(
            raw_call_sites, symbol_table, file_imports, language_map,
        )
        graph_time = time.monotonic() - start_time - parse_time - symbol_time - import_time

        # Step 6: Compute function summaries
        summaries = self._compute_summaries(
            symbol_table, file_lines, language_map,
        )

        # Step 7: Propagate summaries along call edges
        self._propagate_summaries(summaries, call_graph)

        total_time = time.monotonic() - start_time

        logger.info(
            "PCI built: %d symbols, %d edges, %d summaries in %.2fs "
            "(parse=%.2fs, symbols=%.2fs, imports=%.2fs, graph=%.2fs)",
            symbol_table.size,
            call_graph.edge_count,
            len(summaries),
            total_time,
            parse_time,
            symbol_time,
            import_time,
            graph_time,
        )

        # Save cache for next run
        self._save_cache(cache, file_lines, language_map, symbol_table, summaries)

        result = PCIResult(
            symbol_table=symbol_table,
            call_graph=call_graph,
            function_summaries=summaries,
            file_lines=file_lines,
            build_time_seconds=total_time,
            file_count=len(file_structures),
        )

        # Opt-in debug dump: set CODEGUARDIAN_PCI_DUMP=<path> to write graph.json.
        # Off by default — no effect on the scan hot path.
        dump_path = os.environ.get("CODEGUARDIAN_PCI_DUMP")
        if dump_path:
            try:
                result.export_debug_json(dump_path)
                logger.info("PCI debug graph written to %s", dump_path)
            except OSError as e:
                logger.warning("PCI debug dump failed (%s): %s", dump_path, e)

        return result

    def _parse_project_files(
        self,
        ctx: ScanContext,
        project_root: Path,
        cache: object | None = None,
    ) -> tuple[dict[str, object], dict[str, str], dict[str, list[str]]]:
        """Parse all relevant source files, returning structures and source lines.

        Uses cache to skip unchanged files when available.
        """
        from codeguardian.core.call_graph.pci_cache import PCICache, compute_file_hash
        from codeguardian.languages import EXTENSION_LANGUAGE_MAP, language_from_path
        from codeguardian.parsers.factory import get_parser

        suffixes = set(EXTENSION_LANGUAGE_MAP.keys())
        # Always parse the FULL project (ignore_incremental_scope=True) so the
        # call graph is complete even in incremental mode; cross-function analysis
        # on a truncated graph would miss callers/callees outside the diff.
        candidate_files = ctx.collect_candidate_files(
            project_root, suffixes=suffixes, ignore_incremental_scope=True,
        )

        # Limit file count
        if len(candidate_files) > self.max_files:
            logger.warning(
                "PCI: %d files exceed max_files=%d, sampling",
                len(candidate_files), self.max_files,
            )
            candidate_files = candidate_files[:self.max_files]

        file_structures: dict[str, object] = {}
        language_map: dict[str, str] = {}
        file_lines: dict[str, list[str]] = {}

        # Compute hashes for cache check
        file_hashes: dict[str, str] = {}
        stale_files: set[str] = set()

        for path in candidate_files:
            language = language_from_path(path)
            if language is None or language not in PCI_LANGUAGES:
                continue

            try:
                rel_path = str(path.relative_to(project_root)).replace("\\", "/")
            except ValueError:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            content_hash = compute_file_hash(content)
            file_hashes[rel_path] = content_hash
            language_map[rel_path] = language
            file_lines[rel_path] = content.splitlines()

            # Check if cached and unchanged
            if isinstance(cache, PCICache) and cache.is_enabled:
                entry = cache.get_entry(rel_path)
                if entry and entry.get("content_hash") == content_hash:
                    # Cache hit — skip parsing, will use cached symbols later
                    continue

            # Need to parse this file
            parser = get_parser(language)
            if parser is None:
                continue

            try:
                structure = parser.parse_file(path, project_root)
                file_structures[rel_path] = structure
            except Exception as e:
                logger.debug("PCI: Failed to parse %s: %s", rel_path, e)
                continue

        # Prune deleted files from cache
        if isinstance(cache, PCICache) and cache.is_enabled:
            for cached_path in list(cache._entries.keys()):
                if cached_path not in file_hashes:
                    cache.remove_entry(cached_path)

        # For cached files that weren't parsed, we still need their structures
        # for symbol table building. Re-parse them (they're fast since content
        # is already in memory). Alternative: store parsed structure in cache
        # (too large for JSON). Instead, re-parse cached files too — the main
        # savings comes from allowing incremental graph updates in future.
        if isinstance(cache, PCICache) and cache.is_enabled:
            for rel_path in list(language_map.keys()):
                if rel_path not in file_structures and rel_path in file_lines:
                    language = language_map[rel_path]
                    parser = get_parser(language)
                    if parser is None:
                        continue
                    path = project_root / rel_path
                    try:
                        structure = parser.parse_file(path, project_root)
                        file_structures[rel_path] = structure
                    except Exception:
                        continue

        # Update cache with current hashes
        if isinstance(cache, PCICache) and cache.is_enabled:
            for rel_path, content_hash in file_hashes.items():
                cache.set_entry(rel_path, {"content_hash": content_hash})

        return file_structures, language_map, file_lines

    def _save_cache(
        self,
        cache: object,
        file_lines: dict[str, list[str]],
        language_map: dict[str, str],
        symbol_table: SymbolTable,
        summaries: dict[str, FunctionSummary],
    ) -> None:
        """Save cache to disk after successful build."""
        from codeguardian.core.call_graph.pci_cache import PCICache

        if not isinstance(cache, PCICache) or not cache.is_enabled:
            return
        try:
            cache.save()
        except Exception as e:
            logger.debug("PCI cache save failed: %s", e)

    def _resolve_all_imports(
        self,
        file_lines: dict[str, list[str]],
        language_map: dict[str, str],
        project_root: Path,
    ) -> dict[str, list[ResolvedImport]]:
        """Resolve imports for all files."""
        # Build project_files mapping for resolvers
        project_files: dict[str, str] = {}
        for rel_path, lang in language_map.items():
            from codeguardian.core.call_graph.symbol_table import _file_to_module_path
            project_files[rel_path] = _file_to_module_path(rel_path, lang)

        file_imports: dict[str, list[ResolvedImport]] = {}

        for rel_path, lines in file_lines.items():
            language = language_map.get(rel_path, "")
            resolver = get_resolver(language, project_root)
            if resolver is None:
                continue

            try:
                imports = resolver.resolve_imports(rel_path, lines, project_files)
                file_imports[rel_path] = imports
            except Exception as e:
                logger.debug("PCI: Import resolution failed for %s: %s", rel_path, e)

        return file_imports

    def _extract_all_call_sites(
        self,
        symbol_table: SymbolTable,
        file_lines: dict[str, list[str]],
        language_map: dict[str, str],
    ) -> list[RawCallSite]:
        """Extract call sites from all function bodies."""
        all_sites: list[RawCallSite] = []

        for symbol in symbol_table.all_functions():
            language = language_map.get(symbol.file_path, "")
            lines = file_lines.get(symbol.file_path, [])

            if not lines or symbol.start_line <= 0 or symbol.end_line <= 0:
                continue

            # Get function body lines (0-indexed)
            body_start = symbol.start_line - 1
            body_end = min(symbol.end_line, len(lines))
            body_lines = lines[body_start:body_end]

            if not body_lines:
                continue

            sites = extract_call_sites_from_source(
                body_lines, language,
                caller_qualified_name=symbol.qualified_name,
                caller_file=symbol.file_path,
                start_line=symbol.start_line,
            )
            all_sites.extend(sites)

        return all_sites

    def _resolve_and_build_graph(
        self,
        raw_sites: list[RawCallSite],
        symbol_table: SymbolTable,
        file_imports: dict[str, list[ResolvedImport]],
        language_map: dict[str, str],
    ) -> CallGraph:
        """Resolve raw call sites to qualified targets and build the call graph."""
        graph = CallGraph()

        for site in raw_sites:
            targets = self._resolve_call_target(site, symbol_table, file_imports, language_map)
            for target_qname, confidence in targets:
                if confidence < self.min_confidence:
                    continue
                edge = CallEdge(
                    caller=site.caller_qualified_name,
                    callee=target_qname,
                    call_site_line=site.line,
                    call_site_file=site.caller_file,
                    call_form=site.form,
                    confidence=confidence,
                )
                graph.add_edge(edge)

        return graph

    def _resolve_call_target(
        self,
        site: RawCallSite,
        symbol_table: SymbolTable,
        file_imports: dict[str, list[ResolvedImport]],
        language_map: dict[str, str],
    ) -> list[tuple[str, float]]:
        """Resolve a raw call site to qualified target name(s) with confidence.

        Resolution priority:
        1. Same-file symbol → 0.95
        2. Import-resolved symbol → 0.85
        3. Method call with known receiver type → 0.80
        4. Global unique match → 0.60
        5. Global ambiguous match → 0.50
        """
        results: list[tuple[str, float]] = []
        callee_name = site.callee_name

        # Strategy depends on call form
        if site.form == CallForm.METHOD and site.receiver:
            results = self._resolve_method_call(site, symbol_table, file_imports)
        elif site.form == CallForm.CONSTRUCTOR:
            results = self._resolve_constructor_call(site, symbol_table, file_imports)
        elif site.form == CallForm.STATIC and site.receiver:
            results = self._resolve_static_call(site, symbol_table, file_imports)
        elif site.form == CallForm.SUPER:
            results = self._resolve_super_call(site, symbol_table)
        else:
            # Free function call
            results = self._resolve_free_call(site, symbol_table, file_imports)

        return results

    def _resolve_free_call(
        self,
        site: RawCallSite,
        symbol_table: SymbolTable,
        file_imports: dict[str, list[ResolvedImport]],
    ) -> list[tuple[str, float]]:
        """Resolve a free function call: func(...)."""
        callee_name = site.callee_name

        # 1. Same-file lookup
        same_file_symbols = symbol_table.lookup_in_file(site.caller_file)
        for sym in same_file_symbols:
            if sym.name == callee_name and sym.kind in (SymbolKind.FUNCTION, SymbolKind.METHOD):
                return [(sym.qualified_name, 0.95)]

        # 2. Import-resolved
        imports = file_imports.get(site.caller_file, [])
        for imp in imports:
            if imp.local_name == callee_name:
                # Check if the qualified name exists in symbol table
                target = symbol_table.lookup(imp.qualified_name)
                if target:
                    return [(target.qualified_name, imp.confidence)]
                # Even if not in our symbol table, trust the import
                return [(imp.qualified_name, imp.confidence * 0.9)]

        # 3. Same-class method (for unqualified calls within a class)
        caller_sym = symbol_table.lookup(site.caller_qualified_name)
        if caller_sym and caller_sym.class_name:
            class_qname = f"{caller_sym.module_path}.{caller_sym.class_name}" if caller_sym.module_path else caller_sym.class_name
            methods = symbol_table.lookup_methods(class_qname)
            for m in methods:
                if m.name == callee_name:
                    return [(m.qualified_name, 0.90)]

        # 4. Global lookup
        global_matches = symbol_table.lookup_by_name(
            callee_name,
            context_file=site.caller_file,
        )
        func_matches = [
            s for s in global_matches
            if s.kind in (SymbolKind.FUNCTION, SymbolKind.METHOD)
        ]

        if len(func_matches) == 1:
            return [(func_matches[0].qualified_name, 0.60)]
        elif len(func_matches) > 1:
            # Ambiguous — return all with low confidence
            return [(s.qualified_name, 0.50) for s in func_matches[:3]]

        return []

    def _resolve_method_call(
        self,
        site: RawCallSite,
        symbol_table: SymbolTable,
        file_imports: dict[str, list[ResolvedImport]],
    ) -> list[tuple[str, float]]:
        """Resolve receiver.method() calls."""
        callee_name = site.callee_name
        receiver = site.receiver or ""

        # If receiver is 'self' or 'this', look in same class
        if receiver in ("self", "this") or site.receiver_type == "__self__":
            caller_sym = symbol_table.lookup(site.caller_qualified_name)
            if caller_sym and caller_sym.class_name:
                class_qname = (
                    f"{caller_sym.module_path}.{caller_sym.class_name}"
                    if caller_sym.module_path else caller_sym.class_name
                )
                methods = symbol_table.lookup_methods(class_qname)
                for m in methods:
                    if m.name == callee_name:
                        return [(m.qualified_name, 0.95)]

                # Check parent classes
                hierarchy = symbol_table.get_class_hierarchy(class_qname)
                for parent in hierarchy[1:]:
                    parent_methods = symbol_table.lookup_methods(parent)
                    for m in parent_methods:
                        if m.name == callee_name:
                            return [(m.qualified_name, 0.85)]

        # Field-type resolution: receiver matches a declared field of the
        # caller's class (e.g. ``accountDao.deduct()`` where the class declares
        # ``private final AccountDao accountDao;``). The declared field type is
        # authoritative — more reliable than the name heuristic below — so this
        # runs before the ``receiver_type`` branch and yields higher confidence.
        field_type = self._field_type_of_receiver(site, symbol_table)
        if field_type:
            resolved = self._resolve_typed_receiver(
                field_type, callee_name, site, symbol_table, file_imports,
                found_confidence=0.85, declared_confidence=0.80, global_confidence=0.80,
            )
            if resolved:
                return resolved

        # If receiver type is known (from import or uppercase heuristic)
        if site.receiver_type and site.receiver_type != "__self__":
            resolved = self._resolve_typed_receiver(
                site.receiver_type, callee_name, site, symbol_table, file_imports,
                found_confidence=0.80, declared_confidence=0.70, global_confidence=0.75,
            )
            if resolved:
                return resolved

        # Fallback: look for any method with this name
        # Check if receiver matches a known import (e.g., `dao.findUser()`)
        imports = file_imports.get(site.caller_file, [])
        for imp in imports:
            if imp.local_name == receiver:
                # receiver is an imported module/package
                method_qname = f"{imp.qualified_name}.{callee_name}"
                target = symbol_table.lookup(method_qname)
                if target:
                    return [(target.qualified_name, imp.confidence)]

        # Global method name search (low confidence)
        all_matches = symbol_table.lookup_by_name(callee_name)
        method_matches = [s for s in all_matches if s.kind == SymbolKind.METHOD]
        if len(method_matches) == 1:
            return [(method_matches[0].qualified_name, 0.50)]

        return []

    def _field_type_of_receiver(
        self,
        site: RawCallSite,
        symbol_table: SymbolTable,
    ) -> str | None:
        """Return the declared type of ``site.receiver`` when it is a field of the
        caller's class (handles both ``field`` and ``this.field`` receivers).

        Walks the caller's class hierarchy so inherited fields resolve too.
        Returns ``None`` when the receiver is not a known field.
        """
        receiver = site.receiver or ""
        if not receiver:
            return None
        # Normalise `this.accountDao` -> `accountDao`
        field_name = receiver.split(".", 1)[1] if receiver.startswith("this.") else receiver
        if "." in field_name:
            # Chained access (a.b.c) — not a simple field reference.
            return None

        caller_sym = symbol_table.lookup(site.caller_qualified_name)
        if not caller_sym or not caller_sym.class_name:
            return None
        class_qname = (
            f"{caller_sym.module_path}.{caller_sym.class_name}"
            if caller_sym.module_path else caller_sym.class_name
        )

        # Own class first, then inherited fields up the hierarchy.
        for cls_qname in [class_qname, *symbol_table.get_class_hierarchy(class_qname)[1:]]:
            cls_sym = symbol_table.lookup(cls_qname)
            if cls_sym and field_name in cls_sym.field_types:
                return cls_sym.field_types[field_name]
        return None

    def _resolve_typed_receiver(
        self,
        type_name: str,
        callee_name: str,
        site: RawCallSite,
        symbol_table: SymbolTable,
        file_imports: dict[str, list[ResolvedImport]],
        *,
        found_confidence: float,
        declared_confidence: float,
        global_confidence: float,
    ) -> list[tuple[str, float]]:
        """Resolve ``receiver.method()`` given the receiver's (declared) type name.

        Shared by the field-type branch and the ``receiver_type`` heuristic branch;
        the confidence levels differ because a declared field type is more
        authoritative than a name heuristic.
        """
        # Check imports for the type
        imports = file_imports.get(site.caller_file, [])
        for imp in imports:
            if imp.local_name == type_name:
                method_qname = f"{imp.qualified_name}.{callee_name}"
                target = symbol_table.lookup(method_qname)
                if target:
                    return [(target.qualified_name, found_confidence)]
                return [(method_qname, declared_confidence)]

        # Global type lookup
        type_matches = symbol_table.lookup_by_name(type_name)
        class_matches = [s for s in type_matches if s.kind in (SymbolKind.CLASS, SymbolKind.INTERFACE)]
        if class_matches:
            for cls in class_matches[:2]:
                methods = symbol_table.lookup_methods(cls.qualified_name)
                for m in methods:
                    if m.name == callee_name:
                        return [(m.qualified_name, global_confidence)]

        return []

    def _resolve_constructor_call(
        self,
        site: RawCallSite,
        symbol_table: SymbolTable,
        file_imports: dict[str, list[ResolvedImport]],
    ) -> list[tuple[str, float]]:
        """Resolve Class() / new Class() constructor calls."""
        class_name = site.callee_name

        # Check imports
        imports = file_imports.get(site.caller_file, [])
        for imp in imports:
            if imp.local_name == class_name:
                # Look for __init__ or constructor
                init_qname = f"{imp.qualified_name}.__init__"
                target = symbol_table.lookup(init_qname)
                if target:
                    return [(target.qualified_name, imp.confidence)]
                # Return the class itself
                return [(imp.qualified_name, imp.confidence)]

        # Same-file class
        same_file = symbol_table.lookup_in_file(site.caller_file)
        for sym in same_file:
            if sym.name == class_name and sym.kind in (SymbolKind.CLASS, SymbolKind.INTERFACE):
                init_qname = f"{sym.qualified_name}.__init__"
                target = symbol_table.lookup(init_qname)
                if target:
                    return [(target.qualified_name, 0.95)]
                return [(sym.qualified_name, 0.90)]

        # Global lookup
        global_matches = symbol_table.lookup_by_name(class_name)
        class_matches = [s for s in global_matches if s.kind == SymbolKind.CLASS]
        if len(class_matches) == 1:
            return [(class_matches[0].qualified_name, 0.60)]

        return []

    def _resolve_static_call(
        self,
        site: RawCallSite,
        symbol_table: SymbolTable,
        file_imports: dict[str, list[ResolvedImport]],
    ) -> list[tuple[str, float]]:
        """Resolve ClassName.staticMethod() calls."""
        class_name = site.receiver or ""
        method_name = site.callee_name

        # Check imports for the class
        imports = file_imports.get(site.caller_file, [])
        for imp in imports:
            if imp.local_name == class_name:
                method_qname = f"{imp.qualified_name}.{method_name}"
                target = symbol_table.lookup(method_qname)
                if target:
                    return [(target.qualified_name, imp.confidence)]
                return [(method_qname, 0.70)]

        # Same-file class
        same_file = symbol_table.lookup_in_file(site.caller_file)
        for sym in same_file:
            if sym.name == class_name and sym.kind == SymbolKind.CLASS:
                method_qname = f"{sym.qualified_name}.{method_name}"
                target = symbol_table.lookup(method_qname)
                if target:
                    return [(target.qualified_name, 0.90)]

        return []

    def _resolve_super_call(
        self,
        site: RawCallSite,
        symbol_table: SymbolTable,
    ) -> list[tuple[str, float]]:
        """Resolve super.method() calls."""
        caller_sym = symbol_table.lookup(site.caller_qualified_name)
        if not caller_sym or not caller_sym.class_name:
            return []

        class_qname = (
            f"{caller_sym.module_path}.{caller_sym.class_name}"
            if caller_sym.module_path else caller_sym.class_name
        )
        hierarchy = symbol_table.get_class_hierarchy(class_qname)

        # Look for method in parent classes (skip self)
        for parent in hierarchy[1:]:
            parent_methods = symbol_table.lookup_methods(parent)
            for m in parent_methods:
                if m.name == site.callee_name:
                    return [(m.qualified_name, 0.85)]

        return []

    def _compute_summaries(
        self,
        symbol_table: SymbolTable,
        file_lines: dict[str, list[str]],
        language_map: dict[str, str],
    ) -> dict[str, FunctionSummary]:
        """Compute local function summaries for all functions."""
        summaries: dict[str, FunctionSummary] = {}

        for symbol in symbol_table.all_functions():
            lines = file_lines.get(symbol.file_path, [])
            language = language_map.get(symbol.file_path, "")

            if not lines or symbol.start_line <= 0 or symbol.end_line <= 0:
                continue

            body_start = symbol.start_line - 1
            body_end = min(symbol.end_line, len(lines))
            body_lines = lines[body_start:body_end]

            if not body_lines:
                continue

            summary = compute_local_summary(
                qualified_name=symbol.qualified_name,
                file_path=symbol.file_path,
                source_lines=body_lines,
                start_line=symbol.start_line,
                end_line=symbol.end_line,
                language=language,
                return_type=symbol.return_type,
            )
            summaries[symbol.qualified_name] = summary

        return summaries

    def _propagate_summaries(
        self,
        summaries: dict[str, FunctionSummary],
        call_graph: CallGraph,
    ) -> None:
        """Propagate summaries along call edges (bounded fixpoint, max 3 passes).

        Propagation rules:
        - If callee may_return_null and caller uses its result → caller may_return_null
        - If callee may_throw(X) and caller doesn't catch X → caller may_throw(X)
        - If callee acquires resource → caller transitively acquires
        """
        MAX_PASSES = 3
        changed = True
        pass_count = 0

        while changed and pass_count < MAX_PASSES:
            changed = False
            pass_count += 1

            for qname, summary in summaries.items():
                # Get callees
                callee_edges = call_graph.callees_of(qname, depth=1, min_confidence=0.7)

                for edge in callee_edges:
                    callee_summary = summaries.get(edge.callee)
                    if callee_summary is None:
                        continue

                    # Propagate may_throw
                    uncaught = callee_summary.may_throw - summary.catches
                    new_throws = uncaught - summary.transitive_may_throw
                    if new_throws:
                        summary.transitive_may_throw.update(new_throws)
                        changed = True

                    # Propagate may_return_null (transitive)
                    if callee_summary.may_return_null and not summary.transitive_may_return_null:
                        # Only propagate if caller returns the callee's result
                        # (Heuristic: if callee is in a return statement)
                        summary.transitive_may_return_null = True
                        changed = True

                    # Propagate resource acquisition
                    if (callee_summary.acquires or callee_summary.transitive_acquires_resource) and not summary.transitive_acquires_resource:
                        summary.transitive_acquires_resource = True
                        changed = True

        if pass_count >= MAX_PASSES:
            logger.debug("PCI: Summary propagation hit max passes (%d)", MAX_PASSES)


class PCIResult:
    """Result of PCI construction."""

    def __init__(
        self,
        symbol_table: SymbolTable | None = None,
        call_graph: CallGraph | None = None,
        function_summaries: dict[str, FunctionSummary] | None = None,
        file_lines: dict[str, list[str]] | None = None,
        build_time_seconds: float = 0.0,
        file_count: int = 0,
    ) -> None:
        self.symbol_table = symbol_table or SymbolTable()
        self.call_graph = call_graph or CallGraph()
        self.function_summaries = function_summaries or {}
        self.file_lines = file_lines or {}
        self.build_time_seconds = build_time_seconds
        self.file_count = file_count

    @classmethod
    def empty(cls) -> PCIResult:
        return cls()

    @property
    def is_empty(self) -> bool:
        return self.symbol_table.size == 0

    def to_debug_dict(self) -> dict:
        """Serialise the PCI (call edges + inheritance edges) for debugging."""
        graph_dict = self.call_graph.to_debug_dict()

        type_edges: list[dict] = []
        for cls in self.symbol_table.all_classes():
            for parent in cls.parent_classes:
                type_edges.append(
                    {"type": "inherits", "source": cls.qualified_name, "target": parent},
                )
            for iface in cls.interfaces:
                type_edges.append(
                    {"type": "implements", "source": cls.qualified_name, "target": iface},
                )

        return {
            "file_count": self.file_count,
            "build_time_seconds": round(self.build_time_seconds, 3),
            **graph_dict,
            "type_edges": type_edges,
        }

    def export_debug_json(self, path: str | Path) -> None:
        """Write the debug dict to ``path`` as pretty-printed JSON."""
        import json

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.to_debug_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
