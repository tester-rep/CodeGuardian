"""DependencyEngine — module-level dependency analysis and architecture metrics.

COMBINED.md §维度7: Dependency & Coupling Analyzer
Extracts import statements via tree-sitter, builds a module dependency graph,
detects circular dependencies, computes Fan-in/Fan-out, and calculates
Martin's Instability/Abstractness/Distance metrics.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from codeguardian.core.context import ScanContext
from codeguardian.engines.rule_helpers import RuleHit, RuleSpec, build_finding
from codeguardian.engines.rule_registry import filter_rule_hits, register_rules
from codeguardian.languages import EXTENSION_LANGUAGE_MAP, is_language_enabled, sort_paths_by_language_priority
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.metric import Metric
from codeguardian.models.relation import Relation
from codeguardian.models.scan import EngineResult
from codeguardian.parsers.tree_sitter_support import get_tree_sitter_document
from codeguardian.utils.ignore import should_ignore


# ══════════════════════════════════════════════════════════════
# Rule Definitions
# ══════════════════════════════════════════════════════════════

CIRCULAR_DEPENDENCY = RuleSpec(
    rule_id="CIRCULAR-DEPENDENCY",
    title="模块间存在循环依赖 (Circular dependency detected between modules)",
    category="architecture",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="提取共享接口到独立模块，或使用依赖反转（Dependency Inversion）打破循环。",
    risk_priority="should-fix",
    tags=("architecture", "dependency", "circular"),
    description_zh="循环依赖使模块无法独立编译/测试/部署，增加修改连锁影响面和构建复杂度。",
)

HIGH_FAN_OUT = RuleSpec(
    rule_id="HIGH-FAN-OUT",
    title="模块出向依赖过多 (High Fan-out: module depends on too many others)",
    category="architecture",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="拆分大模块或引入 Facade/Mediator 模式封装下游依赖。",
    risk_priority="should-fix",
    tags=("architecture", "dependency", "coupling", "fan-out"),
    description_zh="出向依赖过多说明模块职责不集中，下游任一变更都可能波及本模块。",
)

UNSTABLE_DEPENDENCY = RuleSpec(
    rule_id="UNSTABLE-DEPENDENCY",
    title="稳定模块依赖了不稳定模块 (Stable module depends on unstable one — SDP violation)",
    category="architecture",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="稳定模块应仅依赖同等或更稳定的模块。引入抽象接口使依赖方向反转。",
    risk_priority="should-fix",
    tags=("architecture", "dependency", "stability", "sdp"),
    description_zh="违反稳定依赖原则(SDP)：稳定模块被不稳定模块的变化所影响，架构腐化风险。",
)

DEPENDENCY_RULES = register_rules(
    "dependency",
    (CIRCULAR_DEPENDENCY, HIGH_FAN_OUT, UNSTABLE_DEPENDENCY),
)

# ══════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════

DEP_LANGUAGES = {"java", "python", "typescript", "javascript", "go", "cpp", "csharp"}
DEP_EXTENSIONS = {ext for ext, lang in EXTENSION_LANGUAGE_MAP.items() if lang in DEP_LANGUAGES}

FAN_OUT_THRESHOLD = 15
INSTABILITY_THRESHOLD = 0.8  # Modules with I > this are "unstable"
STABILITY_THRESHOLD = 0.3    # Modules with I < this are "stable"

# Import node types by language
_IMPORT_NODE_TYPES = {
    "python": {"import_statement", "import_from_statement"},
    "java": {"import_declaration"},
    "typescript": {"import_statement"},
    "javascript": {"import_statement"},
    "go": {"import_declaration", "import_spec"},
    "cpp": {"preproc_include"},
    "csharp": {"using_directive"},
}

# Regex for extracting module path from import text
_PYTHON_FROM_IMPORT_RE = re.compile(r"from\s+([\w.]+)\s+import")
_PYTHON_IMPORT_RE = re.compile(r"import\s+([\w.]+)")
_JAVA_IMPORT_RE = re.compile(r"import\s+(?:static\s+)?([\w.]+)")
_GO_IMPORT_RE = re.compile(r'"([^"]+)"')
_CPP_INCLUDE_RE = re.compile(r'#include\s*[<"]([^>"]+)[>"]')


# ══════════════════════════════════════════════════════════════
# Engine Implementation
# ══════════════════════════════════════════════════════════════

class DependencyEngine:
    """Analyzes module-level dependencies and architectural metrics."""

    name = "dependency"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root).resolve()
        start = time.monotonic()

        # Phase 1: Extract imports from all files
        file_imports: dict[str, set[str]] = {}  # rel_path -> set of imported module paths
        candidates = ctx.collect_candidate_files(root, suffixes=DEP_EXTENSIONS)
        sorted_files = sort_paths_by_language_priority(candidates)

        for file_path in sorted_files:
            if should_ignore(file_path):
                continue
            suffix = file_path.suffix.lower()
            language = EXTENSION_LANGUAGE_MAP.get(suffix)
            if not language or language not in DEP_LANGUAGES:
                continue
            if not is_language_enabled(language, ctx.languages):
                continue

            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
            imports = self._extract_imports(file_path, root, language)
            if imports:
                file_imports[rel_path] = imports

        # Phase 2: Aggregate into module-level dependency graph
        module_graph, file_to_module = self._build_module_graph(file_imports)

        # Phase 3: Compute metrics per module
        modules = set(module_graph.keys())
        for targets in module_graph.values():
            modules.update(targets)

        fan_in: dict[str, int] = defaultdict(int)
        fan_out: dict[str, int] = {}
        for source, targets in module_graph.items():
            fan_out[source] = len(targets)
            for target in targets:
                fan_in[target] += 1

        # Instability I = Ce / (Ca + Ce) where Ce=fan_out, Ca=fan_in
        instability: dict[str, float] = {}
        for module in modules:
            ca = fan_in.get(module, 0)
            ce = fan_out.get(module, 0)
            instability[module] = ce / (ca + ce) if (ca + ce) > 0 else 0.5

        # Phase 4: Detect issues
        hits: list[RuleHit] = []
        metrics: list[Metric] = []
        relations: list[Relation] = []

        # Circular dependency detection (DFS)
        cycles = self._detect_cycles(module_graph)
        for cycle in cycles[:10]:  # Limit to first 10 cycles
            cycle_str = " → ".join(cycle)
            # Use first module in cycle for location
            first_module = cycle[0]
            first_file = self._find_representative_file(first_module, file_to_module)
            hits.append(RuleHit(
                rule=CIRCULAR_DEPENDENCY,
                file_path=first_file or first_module,
                line_start=1,
                line_end=1,
                message=f"Circular dependency: {cycle_str}",
            ))

        # High fan-out
        for module, count in fan_out.items():
            if count > FAN_OUT_THRESHOLD:
                rep_file = self._find_representative_file(module, file_to_module)
                hits.append(RuleHit(
                    rule=HIGH_FAN_OUT,
                    file_path=rep_file or module,
                    line_start=1,
                    line_end=1,
                    message=f"Module '{module}' has fan-out={count} (threshold: {FAN_OUT_THRESHOLD})",
                ))

        # SDP violation: stable module depends on unstable module
        for source, targets in module_graph.items():
            source_i = instability.get(source, 0.5)
            if source_i >= STABILITY_THRESHOLD:  # Source not stable enough to be relevant
                continue
            for target in targets:
                target_i = instability.get(target, 0.5)
                if target_i > INSTABILITY_THRESHOLD:
                    rep_file = self._find_representative_file(source, file_to_module)
                    hits.append(RuleHit(
                        rule=UNSTABLE_DEPENDENCY,
                        file_path=rep_file or source,
                        line_start=1,
                        line_end=1,
                        message=(
                            f"Stable module '{source}' (I={source_i:.2f}) depends on "
                            f"unstable module '{target}' (I={target_i:.2f})"
                        ),
                    ))

        # Emit metrics
        for module in modules:
            metrics.append(Metric(
                target_id=module,
                target_type="module",
                metric_name="fan_in",
                value=float(fan_in.get(module, 0)),
                unit="modules",
                source_engine=self.name,
            ))
            metrics.append(Metric(
                target_id=module,
                target_type="module",
                metric_name="fan_out",
                value=float(fan_out.get(module, 0)),
                unit="modules",
                source_engine=self.name,
            ))
            metrics.append(Metric(
                target_id=module,
                target_type="module",
                metric_name="instability",
                value=round(instability.get(module, 0.5), 3),
                unit="ratio",
                source_engine=self.name,
            ))

        # Emit relations
        for source, targets in module_graph.items():
            for target in targets:
                relations.append(Relation(
                    source_id=source,
                    target_id=target,
                    relation_type="depends_on",
                    weight=1.0,
                ))

        # Apply rule filters and build findings
        filtered_hits = filter_rule_hits(hits, ctx.config.rules)
        findings = []
        for idx, hit in enumerate(filtered_hits, start=1):
            try:
                lines = (root / hit.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
            findings.append(build_finding(hit, lines, f"DEP-{idx:03d}", self.name))

        elapsed = (time.monotonic() - start) * 1000
        return EngineResult(
            engine_name=self.name,
            findings=findings,
            metrics=metrics,
            duration_ms=elapsed,
        )

    def _extract_imports(self, file_path: Path, root: Path, language: str) -> set[str]:
        """Extract imported module paths from a source file."""
        imports: set[str] = set()

        # Use tree-sitter for structured extraction
        doc = get_tree_sitter_document(file_path, root, language)
        if doc is None:
            # Fallback: regex on raw text
            return self._regex_extract_imports(file_path, language)

        import_types = _IMPORT_NODE_TYPES.get(language, set())
        if not import_types:
            return imports

        def walk(node: Any) -> None:
            if node.type in import_types:
                text = node.text.decode("utf-8") if node.text else ""
                module_path = self._parse_import_text(text, language)
                if module_path:
                    imports.add(module_path)
            for child in node.children:
                walk(child)

        walk(doc.tree.root_node)
        return imports

    def _regex_extract_imports(self, file_path: Path, language: str) -> set[str]:
        """Fallback regex import extraction."""
        imports: set[str] = set()
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        if language == "python":
            for match in _PYTHON_FROM_IMPORT_RE.finditer(content):
                imports.add(match.group(1))
            for match in _PYTHON_IMPORT_RE.finditer(content):
                imports.add(match.group(1))
        elif language == "java":
            for match in _JAVA_IMPORT_RE.finditer(content):
                imports.add(match.group(1))
        elif language in {"typescript", "javascript"}:
            # from 'module' or require('module')
            for match in re.finditer(r"""(?:from|require)\s*\(\s*['"]([^'"]+)['"]""", content):
                imports.add(match.group(1))
            for match in re.finditer(r"""from\s+['"]([^'"]+)['"]""", content):
                imports.add(match.group(1))
        elif language == "go":
            for match in _GO_IMPORT_RE.finditer(content):
                imports.add(match.group(1))
        elif language == "cpp":
            for match in _CPP_INCLUDE_RE.finditer(content):
                imports.add(match.group(1))

        return imports

    def _parse_import_text(self, text: str, language: str) -> str | None:
        """Parse import statement text into a module path."""
        if language == "python":
            match = _PYTHON_FROM_IMPORT_RE.search(text)
            if match:
                return match.group(1)
            match = _PYTHON_IMPORT_RE.search(text)
            if match:
                return match.group(1)
        elif language == "java":
            match = _JAVA_IMPORT_RE.search(text)
            if match:
                # Return package (drop class name)
                parts = match.group(1).rsplit(".", 1)
                return parts[0] if len(parts) > 1 else match.group(1)
        elif language in {"typescript", "javascript"}:
            # Extract from path string
            match = re.search(r"""['"]([^'"]+)['"]""", text)
            if match:
                return match.group(1)
        elif language == "go":
            match = _GO_IMPORT_RE.search(text)
            if match:
                return match.group(1)
        elif language == "cpp":
            match = _CPP_INCLUDE_RE.search(text)
            if match:
                return match.group(1)
        elif language == "csharp":
            match = re.search(r"using\s+([\w.]+)", text)
            if match:
                return match.group(1)
        return None

    def _build_module_graph(
        self,
        file_imports: dict[str, set[str]],
    ) -> tuple[dict[str, set[str]], dict[str, str]]:
        """Aggregate file-level imports into module-level dependency graph.

        Module = top-level directory of the file path.
        """
        module_deps: dict[str, set[str]] = defaultdict(set)
        file_to_module: dict[str, str] = {}

        for file_path in file_imports:
            module = self._file_to_module(file_path)
            file_to_module[file_path] = module

        for file_path, imports in file_imports.items():
            source_module = file_to_module[file_path]
            for imp in imports:
                # Resolve import to a module name
                target_module = self._import_to_module(imp)
                if target_module and target_module != source_module:
                    module_deps[source_module].add(target_module)

        return dict(module_deps), file_to_module

    @staticmethod
    def _file_to_module(file_path: str) -> str:
        """Map a file path to its module (top-level directory)."""
        parts = PurePosixPath(file_path).parts
        if len(parts) > 1:
            return parts[0]
        return "."

    @staticmethod
    def _import_to_module(import_path: str) -> str | None:
        """Map an import path to a module name."""
        # Skip stdlib/external imports (heuristic: starts with common std names or has no dots)
        if import_path.startswith(("java.", "javax.", "org.junit", "org.springframework")):
            return None
        if import_path.startswith(("os", "sys", "io", "re", "math", "json", "typing", "collections")):
            return None
        if import_path.startswith("@") or import_path.startswith("node_modules"):
            return None
        if "/" not in import_path and "." not in import_path:
            return None  # Likely a single-word stdlib import

        # Use first segment as module
        for sep in ("/", "."):
            if sep in import_path:
                first = import_path.split(sep)[0]
                if first and first not in {".", "..", "src", "lib", "pkg"}:
                    return first
        return import_path

    def _detect_cycles(self, graph: dict[str, set[str]]) -> list[list[str]]:
        """Detect all cycles in the dependency graph using DFS."""
        cycles: list[list[str]] = []
        visited: set[str] = set()
        in_stack: set[str] = set()
        stack: list[str] = []

        def dfs(node: str) -> None:
            if len(cycles) >= 10:  # Limit
                return
            visited.add(node)
            in_stack.add(node)
            stack.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor in in_stack:
                    # Found cycle
                    cycle_start = stack.index(neighbor)
                    cycle = stack[cycle_start:] + [neighbor]
                    cycles.append(cycle)
                elif neighbor not in visited:
                    dfs(neighbor)

            stack.pop()
            in_stack.discard(node)

        for node in graph:
            if node not in visited:
                dfs(node)

        return cycles

    @staticmethod
    def _find_representative_file(module: str, file_to_module: dict[str, str]) -> str | None:
        """Find a representative file for a module (for location reporting)."""
        for file_path, mod in file_to_module.items():
            if mod == module:
                return file_path
        return None
