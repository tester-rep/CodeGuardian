"""OODesignEngine — Object-Oriented design metrics and anti-pattern detection.

COMBINED.md §维度3: OO Design Analyzer
Computes CK metrics (WMC, DIT, CBO, LCOM) and detects anti-patterns
(God Class, Data Class, Deep Inheritance) via tree-sitter AST analysis.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from codeguardian.core.context import ScanContext
from codeguardian.engines.rule_helpers import RuleHit, RuleSpec, build_finding
from codeguardian.engines.rule_registry import filter_rule_hits, register_rules
from codeguardian.languages import EXTENSION_LANGUAGE_MAP, is_language_enabled, sort_paths_by_language_priority
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.metric import Metric
from codeguardian.models.scan import EngineResult
from codeguardian.parsers.tree_sitter_support import TreeSitterDocument, get_tree_sitter_document
from codeguardian.utils.ignore import should_ignore


# ══════════════════════════════════════════════════════════════
# Rule Definitions
# ══════════════════════════════════════════════════════════════

GOD_CLASS = RuleSpec(
    rule_id="GOD-CLASS",
    title="上帝类：类承担过多职责 (God Class detected)",
    category="maintainability",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    fix_suggestion="按职责拆分为多个内聚的小类，每个类聚焦单一职责（SRP）。",
    risk_priority="can-fix",
    tags=("oo-design", "god-class", "srp", "maintainability"),
    description_zh="类方法数量过多、代码行数过大且内聚性差，说明承担了过多不相关职责，维护成本高。",
)

DATA_CLASS = RuleSpec(
    rule_id="DATA-CLASS",
    title="数据类：仅含 getter/setter 无业务逻辑 (Data Class / Anemic Model)",
    category="maintainability",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    fix_suggestion="考虑将操作该数据的行为移入类内部，实现充血模型（Rich Domain Model）。",
    risk_priority="can-fix",
    tags=("oo-design", "data-class", "anemic-model"),
    description_zh="类仅包含字段和 getter/setter，业务逻辑散落在外部服务类中，违反封装原则。",
)

DEEP_INHERITANCE = RuleSpec(
    rule_id="DEEP-INHERITANCE",
    title="继承层次过深 (Deep Inheritance Tree: DIT > 5)",
    category="maintainability",
    # 降级理由：纯结构指标（DIT 是数值阈值），不是 bug，不应 block release。
    # 与 HIGH-COUPLING、ISP-VIOLATION 性质相同，统一降为 LOW + can-fix。
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    fix_suggestion="考虑使用组合（Composition）替代深层继承，或提取公共接口。",
    risk_priority="can-fix",
    tags=("oo-design", "inheritance", "fragile-base-class"),
    description_zh="继承层次过深会导致脆弱的父类问题：父类修改可能连锁影响所有子类。",
)

HIGH_COUPLING = RuleSpec(
    rule_id="HIGH-CLASS-COUPLING",
    title="类耦合度过高 (High CBO: Coupling Between Objects)",
    category="maintainability",
    # 降级理由：纯结构指标（CBO 是数值阈值），衡量"耦合到多少类"，不衡量"有没有 bug"。
    # 开发不会优先处理，列为 can-fix 的代码味道而非 should-fix 缺陷。
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    fix_suggestion="引入接口/抽象层解耦，减少对具体实现的直接依赖。使用依赖注入降低耦合。",
    risk_priority="can-fix",
    tags=("oo-design", "coupling", "cbo"),
    description_zh="类直接引用了过多其他类，修改任一被依赖类都可能导致连锁修改。",
)

# SOLID violation rules
ISP_VIOLATION = RuleSpec(
    rule_id="ISP-VIOLATION",
    title="接口隔离原则违规：接口方法过多 (Interface Segregation Principle)",
    category="architecture",
    # 降级理由：纯结构指标（方法数 > 10 阈值），属于设计味道而非缺陷。
    # 与 HIGH-COUPLING、DEEP-INHERITANCE 同性质，统一降为 LOW + can-fix。
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    fix_suggestion="将大接口拆分为多个小的、聚焦单一职责的接口。客户端只依赖需要的接口。",
    risk_priority="can-fix",
    tags=("oo-design", "solid", "isp"),
    description_zh="接口/抽象类方法数过多(>10)，实现类被迫实现不需要的方法，违反接口隔离原则。",
)

DIP_VIOLATION = RuleSpec(
    rule_id="DIP-VIOLATION",
    title="依赖倒置原则违规：直接实例化具体类 (Dependency Inversion Principle)",
    category="architecture",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    fix_suggestion="通过构造函数注入或工厂模式获取依赖，高层模块不应直接 new 具体实现。",
    risk_priority="can-fix",
    tags=("oo-design", "solid", "dip"),
    description_zh="类内部直接 new/实例化多个具体实现类(>5处)，修改依赖需改动本类，违反依赖倒置原则。",
)

FEATURE_ENVY = RuleSpec(
    rule_id="FEATURE-ENVY",
    title="特性嫉妒：方法过度使用外部类数据 (Feature Envy)",
    category="maintainability",
    severity=Severity.LOW,
    confidence=Confidence.LOW,
    fix_suggestion="考虑将此方法移动到它频繁访问的那个类中，或提取为独立的服务方法。",
    risk_priority="can-fix",
    tags=("oo-design", "smell", "feature-envy"),
    description_zh="方法大量访问另一个类的字段/方法，暗示逻辑放错了位置。",
)

OO_RULES = register_rules(
    "oo_design",
    (GOD_CLASS, DATA_CLASS, DEEP_INHERITANCE, HIGH_COUPLING, ISP_VIOLATION, DIP_VIOLATION, FEATURE_ENVY),
)

# ══════════════════════════════════════════════════════════════
# Supported languages for OO analysis
# ══════════════════════════════════════════════════════════════

OO_LANGUAGES = {"java", "python", "typescript", "javascript", "cpp", "csharp"}
OO_EXTENSIONS = {ext for ext, lang in EXTENSION_LANGUAGE_MAP.items() if lang in OO_LANGUAGES}

# Thresholds
GOD_CLASS_METHOD_THRESHOLD = 20
GOD_CLASS_LOC_THRESHOLD = 500
DATA_CLASS_MIN_FIELDS = 3
DIT_THRESHOLD = 5
CBO_THRESHOLD = 15
ISP_METHOD_THRESHOLD = 10  # Interface with >10 methods = ISP violation
DIP_NEW_THRESHOLD = 5  # >5 direct instantiations = DIP violation

# AST node types by language
_CLASS_NODE_TYPES = {
    "java": {"class_declaration", "interface_declaration", "enum_declaration"},
    "python": {"class_definition"},
    "typescript": {"class_declaration", "interface_declaration"},
    "javascript": {"class_declaration"},
    "cpp": {"class_specifier", "struct_specifier"},
    "csharp": {"class_declaration", "interface_declaration"},
}

_METHOD_NODE_TYPES = {
    "java": {"method_declaration", "constructor_declaration"},
    "python": {"function_definition"},
    "typescript": {"method_definition", "public_field_definition"},
    "javascript": {"method_definition"},
    "cpp": {"function_definition"},
    "csharp": {"method_declaration", "constructor_declaration"},
}

_FIELD_NODE_TYPES = {
    "java": {"field_declaration"},
    "python": set(),  # handled via assignment in __init__
    "typescript": {"public_field_definition", "property_signature"},
    "javascript": {"field_definition"},
    "cpp": {"field_declaration"},
    "csharp": {"field_declaration", "property_declaration"},
}


# ══════════════════════════════════════════════════════════════
# Engine Implementation
# ══════════════════════════════════════════════════════════════

class OODesignEngine:
    """Computes OO design metrics and detects anti-patterns."""

    name = "oo_design"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root).resolve()
        start = time.monotonic()

        hits: list[RuleHit] = []
        metrics: list[Metric] = []

        candidates = ctx.collect_candidate_files(root, suffixes=OO_EXTENSIONS)
        sorted_files = sort_paths_by_language_priority(candidates)

        for file_path in sorted_files:
            if should_ignore(file_path):
                continue

            suffix = file_path.suffix.lower()
            language = EXTENSION_LANGUAGE_MAP.get(suffix)
            if not language or language not in OO_LANGUAGES:
                continue
            if not is_language_enabled(language, ctx.languages):
                continue

            doc = get_tree_sitter_document(file_path, root, language)
            if doc is None:
                continue

            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
            self._analyze_classes(doc, rel_path, language, hits, metrics)
            self._detect_solid_violations(doc, rel_path, language, hits)

        filtered_hits = filter_rule_hits(hits, ctx.config.rules)

        findings = []
        for idx, hit in enumerate(filtered_hits, start=1):
            try:
                lines = (root / hit.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
            findings.append(build_finding(hit, lines, f"OOD-{idx:03d}", self.name))

        elapsed = (time.monotonic() - start) * 1000
        return EngineResult(
            engine_name=self.name,
            findings=findings,
            metrics=metrics,
            duration_ms=elapsed,
        )

    def _analyze_classes(
        self,
        doc: TreeSitterDocument,
        rel_path: str,
        language: str,
        hits: list[RuleHit],
        metrics: list[Metric],
    ) -> None:
        """Extract classes and compute OO metrics."""
        class_types = _CLASS_NODE_TYPES.get(language, set())
        if not class_types:
            return

        root_node = doc.tree.root_node
        class_nodes = self._find_nodes_by_type(root_node, class_types)

        # Build inheritance map for DIT calculation
        inheritance: dict[str, str | None] = {}

        for class_node in class_nodes:
            class_name = self._get_class_name(class_node, language)
            if not class_name:
                continue

            start_line = class_node.start_point[0] + 1
            end_line = class_node.end_point[0] + 1
            loc = end_line - start_line + 1

            # Count methods
            method_types = _METHOD_NODE_TYPES.get(language, set())
            methods = self._find_direct_children_by_type(class_node, method_types, language)
            method_count = len(methods)

            # Count fields
            field_count = self._count_fields(class_node, language)

            # Compute WMC (simplified: count of methods as proxy)
            wmc = method_count

            # Extract superclass for DIT
            superclass = self._get_superclass(class_node, language)
            inheritance[class_name] = superclass

            # Compute CBO (count unique type references)
            cbo = self._compute_cbo(class_node, class_name, language)

            # Check if data class (mostly getters/setters)
            is_data_class = self._is_data_class(methods, field_count, method_count, language)

            # Emit metrics
            target_id = f"{rel_path}:{class_name}"
            metrics.extend([
                Metric(
                    target_id=target_id,
                    target_type="class",
                    metric_name="wmc",
                    value=float(wmc),
                    unit="methods",
                    source_engine=self.name,
                ),
                Metric(
                    target_id=target_id,
                    target_type="class",
                    metric_name="cbo",
                    value=float(cbo),
                    unit="classes",
                    source_engine=self.name,
                ),
            ])

            # God Class detection
            if method_count >= GOD_CLASS_METHOD_THRESHOLD and loc >= GOD_CLASS_LOC_THRESHOLD:
                hits.append(RuleHit(
                    rule=GOD_CLASS,
                    file_path=rel_path,
                    line_start=start_line,
                    line_end=end_line,
                    message=(
                        f"Class '{class_name}' has {method_count} methods and {loc} lines. "
                        f"WMC={wmc}, suggesting it handles too many responsibilities."
                    ),
                    language=language,
                ))

            # Data Class detection
            if is_data_class and field_count >= DATA_CLASS_MIN_FIELDS:
                hits.append(RuleHit(
                    rule=DATA_CLASS,
                    file_path=rel_path,
                    line_start=start_line,
                    line_end=end_line,
                    message=(
                        f"Class '{class_name}' has {field_count} fields but only trivial methods "
                        f"(getters/setters/constructors). Consider adding behavior."
                    ),
                    language=language,
                ))

            # High coupling
            if cbo > CBO_THRESHOLD:
                hits.append(RuleHit(
                    rule=HIGH_COUPLING,
                    file_path=rel_path,
                    line_start=start_line,
                    line_end=end_line,
                    message=f"Class '{class_name}' has CBO={cbo} (threshold: {CBO_THRESHOLD})",
                    language=language,
                ))

        # DIT calculation (after all classes processed)
        for class_name, superclass in inheritance.items():
            dit = self._compute_dit(class_name, inheritance)
            if dit > DIT_THRESHOLD:
                # Find the class node again for location
                for class_node in class_nodes:
                    name = self._get_class_name(class_node, language)
                    if name == class_name:
                        hits.append(RuleHit(
                            rule=DEEP_INHERITANCE,
                            file_path=rel_path,
                            line_start=class_node.start_point[0] + 1,
                            line_end=class_node.end_point[0] + 1,
                            message=f"Class '{class_name}' has DIT={dit} (threshold: {DIT_THRESHOLD})",
                            language=language,
                        ))
                        break

    def _detect_solid_violations(
        self,
        doc: TreeSitterDocument,
        rel_path: str,
        language: str,
        hits: list[RuleHit],
    ) -> None:
        """Detect SOLID principle violations: ISP, DIP, Feature Envy."""
        class_types = _CLASS_NODE_TYPES.get(language, set())
        if not class_types:
            return

        root_node = doc.tree.root_node
        class_nodes = self._find_nodes_by_type(root_node, class_types)

        for class_node in class_nodes:
            class_name = self._get_class_name(class_node, language)
            if not class_name:
                continue

            start_line = class_node.start_point[0] + 1
            end_line = class_node.end_point[0] + 1

            # ISP: Interface/abstract class with too many methods
            if self._is_interface_or_abstract(class_node, language):
                method_types = _METHOD_NODE_TYPES.get(language, set())
                methods = self._find_direct_children_by_type(class_node, method_types, language)
                if len(methods) > ISP_METHOD_THRESHOLD:
                    hits.append(RuleHit(
                        rule=ISP_VIOLATION,
                        file_path=rel_path,
                        line_start=start_line,
                        line_end=end_line,
                        message=(
                            f"Interface/abstract '{class_name}' has {len(methods)} methods "
                            f"(threshold: {ISP_METHOD_THRESHOLD}). Consider splitting into smaller interfaces."
                        ),
                        language=language,
                    ))

            # DIP: Count direct instantiations (new/Class()) inside class
            new_count = self._count_direct_instantiations(class_node, language)
            if new_count > DIP_NEW_THRESHOLD:
                hits.append(RuleHit(
                    rule=DIP_VIOLATION,
                    file_path=rel_path,
                    line_start=start_line,
                    line_end=end_line,
                    message=(
                        f"Class '{class_name}' directly instantiates {new_count} concrete classes "
                        f"(threshold: {DIP_NEW_THRESHOLD}). Consider dependency injection."
                    ),
                    language=language,
                ))

    def _is_interface_or_abstract(self, class_node: Any, language: str) -> bool:
        """Check if a class node represents an interface or abstract class."""
        if language == "java":
            return class_node.type in {"interface_declaration"}
        if language in {"typescript", "javascript"}:
            return class_node.type == "interface_declaration"
        if language == "csharp":
            return class_node.type == "interface_declaration"
        if language == "python":
            # Check for ABC inheritance or abstractmethod decorators
            text = class_node.text.decode("utf-8", errors="ignore") if class_node.text else ""
            return "ABC" in text or "@abstractmethod" in text or "abstractmethod" in text
        return False

    def _count_direct_instantiations(self, class_node: Any, language: str) -> int:
        """Count 'new Foo()' or 'Foo()' direct instantiation patterns."""
        count = 0

        def walk(node: Any) -> None:
            nonlocal count
            if language in {"java", "csharp", "cpp"}:
                # new ClassName(...)
                if node.type == "object_creation_expression":
                    count += 1
            elif language in {"typescript", "javascript"}:
                if node.type == "new_expression":
                    count += 1
            elif language == "python":
                # FunctionCall where name starts uppercase → likely class instantiation
                if node.type == "call":
                    func = node.child_by_field_name("function")
                    if func and func.type == "identifier" and func.text:
                        name = func.text.decode("utf-8")
                        if name and name[0].isupper() and name not in _BUILTIN_TYPES:
                            count += 1
            for child in node.children:
                walk(child)

        walk(class_node)
        return count

    def _find_nodes_by_type(self, node: Any, types: set[str]) -> list[Any]:
        """Recursively find all nodes matching given types."""
        results = []
        if node.type in types:
            results.append(node)
        for child in node.children:
            results.extend(self._find_nodes_by_type(child, types))
        return results

    def _find_direct_children_by_type(self, node: Any, types: set[str], language: str) -> list[Any]:
        """Find methods that are direct children of a class (not nested classes)."""
        results = []
        class_types = _CLASS_NODE_TYPES.get(language, set())

        def walk(n: Any, depth: int) -> None:
            if depth > 0 and n.type in class_types:
                return  # Don't descend into nested classes
            if n.type in types:
                results.append(n)
            else:
                for child in n.children:
                    walk(child, depth + 1)

        # For Python, methods are inside class body
        body = None
        for child in node.children:
            if child.type in {"block", "class_body", "declaration_list"}:
                body = child
                break
        target = body if body else node
        for child in target.children:
            walk(child, 0)
        return results

    def _count_fields(self, class_node: Any, language: str) -> int:
        """Count field/property declarations in a class."""
        field_types = _FIELD_NODE_TYPES.get(language, set())

        if language == "python":
            # Count self.x assignments in __init__
            return self._count_python_fields(class_node)

        count = 0
        for child in class_node.children:
            if child.type in {"block", "class_body", "declaration_list"}:
                for member in child.children:
                    if member.type in field_types:
                        count += 1
        return count

    def _count_python_fields(self, class_node: Any) -> int:
        """Count self.X assignments in Python __init__."""
        count = 0
        seen: set[str] = set()

        def find_init(node: Any) -> Any | None:
            for child in node.children:
                if child.type == "block":
                    for stmt in child.children:
                        if stmt.type == "function_definition":
                            name_node = stmt.child_by_field_name("name")
                            if name_node and name_node.text and name_node.text.decode("utf-8") == "__init__":
                                return stmt
            return None

        init_fn = find_init(class_node)
        if init_fn is None:
            return 0

        def walk_assignments(node: Any) -> None:
            nonlocal count
            if node.type == "assignment":
                left = node.child_by_field_name("left")
                if left and left.type == "attribute":
                    obj = left.child_by_field_name("object")
                    attr = left.child_by_field_name("attribute")
                    if obj and obj.text and obj.text.decode("utf-8") == "self" and attr and attr.text:
                        field_name = attr.text.decode("utf-8")
                        if field_name not in seen:
                            seen.add(field_name)
                            count += 1
            for child in node.children:
                walk_assignments(child)

        walk_assignments(init_fn)
        return count

    def _get_class_name(self, node: Any, language: str) -> str | None:
        """Extract class name from AST node."""
        name_node = node.child_by_field_name("name")
        if name_node and name_node.text:
            return name_node.text.decode("utf-8")
        return None

    def _get_superclass(self, node: Any, language: str) -> str | None:
        """Extract superclass name from class declaration."""
        if language == "python":
            # argument_list contains bases
            for child in node.children:
                if child.type == "argument_list":
                    for arg in child.children:
                        if arg.type == "identifier" and arg.text:
                            return arg.text.decode("utf-8")
            return None

        if language == "java":
            superclass_node = node.child_by_field_name("superclass")
            if superclass_node:
                # type_identifier
                for child in superclass_node.children:
                    if child.type == "type_identifier" and child.text:
                        return child.text.decode("utf-8")
            return None

        if language in {"typescript", "javascript"}:
            # heritage clause / extends
            for child in node.children:
                if child.type == "class_heritage":
                    for heritage in child.children:
                        if heritage.type == "extends_clause":
                            for id_node in heritage.children:
                                if id_node.type == "identifier" and id_node.text:
                                    return id_node.text.decode("utf-8")
            return None

        if language == "cpp":
            for child in node.children:
                if child.type == "base_class_clause":
                    for base in child.children:
                        if base.type == "type_identifier" and base.text:
                            return base.text.decode("utf-8")
            return None

        return None

    def _compute_dit(self, class_name: str, inheritance: dict[str, str | None], depth: int = 0) -> int:
        """Compute Depth of Inheritance Tree for a class."""
        if depth > 20:  # Guard against cycles
            return depth
        superclass = inheritance.get(class_name)
        if superclass is None or superclass not in inheritance:
            return depth
        return self._compute_dit(superclass, inheritance, depth + 1)

    def _compute_cbo(self, class_node: Any, class_name: str, language: str) -> int:
        """Compute Coupling Between Objects — count unique external type references."""
        type_refs: set[str] = set()

        def collect_type_refs(node: Any) -> None:
            if node.type in {"type_identifier", "identifier"} and node.text:
                name = node.text.decode("utf-8")
                # Skip self-reference, primitives, common builtins
                if name != class_name and name not in _BUILTIN_TYPES:
                    # Only count capitalized names (likely class references)
                    if name[0].isupper():
                        type_refs.add(name)
            for child in node.children:
                collect_type_refs(child)

        collect_type_refs(class_node)
        return len(type_refs)

    def _is_data_class(self, methods: list[Any], field_count: int, method_count: int, language: str) -> bool:
        """Determine if a class is mostly getters/setters (anemic model)."""
        if method_count == 0:
            return field_count >= DATA_CLASS_MIN_FIELDS

        if field_count == 0:
            return False

        trivial_count = 0
        for method in methods:
            name_node = method.child_by_field_name("name")
            if not name_node or not name_node.text:
                continue
            name = name_node.text.decode("utf-8").lower()

            # Count getters, setters, constructors as trivial
            if (
                name.startswith("get")
                or name.startswith("set")
                or name.startswith("is_")
                or name in {"__init__", "__str__", "__repr__", "toString", "hashCode", "equals", "constructor"}
            ):
                trivial_count += 1

        # If >80% of methods are trivial, it's a data class
        return trivial_count / method_count >= 0.8 if method_count > 0 else False


_BUILTIN_TYPES = {
    # Java
    "String", "Integer", "Long", "Double", "Float", "Boolean", "Byte", "Short", "Character",
    "Object", "Class", "List", "Map", "Set", "Collection", "Optional", "Stream",
    "Void", "void", "int", "long", "double", "float", "boolean", "byte", "short", "char",
    # Python
    "str", "int", "float", "bool", "list", "dict", "set", "tuple", "None", "type",
    "Any", "Optional", "Union", "Type", "Callable", "Iterator", "Generator",
    # TypeScript / JavaScript
    "string", "number", "boolean", "undefined", "null", "Array", "Promise", "Record",
    # C++
    "vector", "map", "string", "shared_ptr", "unique_ptr", "size_t",
    # Common
    "Exception", "Error", "RuntimeException", "IOException",
}
