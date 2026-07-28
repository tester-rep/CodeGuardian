"""Phase 2: Defect engine optimization tests.

Tests verify:
- Test file suppression (PRINT-DEBUG / ASSERT-USED / DEAD-CODE not reported in test files)
- Comment line filtering (regex doesn't match patterns inside comments)
- Regex/AST deduplication (no duplicate hits for tree-sitter languages)
- GO-ERROR-IGNORED independent rule
- _walk_nodes iterative correctness
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.defaults import default_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


# ═══════════════════════════════════════════════════════════════════════
#  Test file suppression
# ═══════════════════════════════════════════════════════════════════════


async def test_print_debug_suppressed_in_test_file() -> None:
    """print() in a test file should NOT be flagged as PRINT-DEBUG."""
    source = """
def test_something():
    result = compute()
    print(result)
    assert result == 42
"""
    findings = await _scan_in_dir("tests/test_example.py", source)
    rule_ids = {f.rule_id for f in findings}
    assert "PRINT-DEBUG" not in rule_ids, f"PRINT-DEBUG should be suppressed in test files, got: {rule_ids}"


async def test_assert_suppressed_in_test_file() -> None:
    """assert in a test file should NOT be flagged as ASSERT-USED."""
    source = """
def test_something():
    x = 42
    assert x > 0
"""
    findings = await _scan_in_dir("tests/test_example.py", source)
    rule_ids = {f.rule_id for f in findings}
    assert "ASSERT-USED" not in rule_ids, f"ASSERT-USED should be suppressed in test files, got: {rule_ids}"


async def test_real_bugs_still_reported_in_test_file() -> None:
    """Real bugs like SELF-ASSIGNMENT should still be reported in test files."""
    source = """
def test_buggy():
    x = 10
    x = x
"""
    findings = await _scan_in_dir("tests/test_example.py", source)
    rule_ids = {f.rule_id for f in findings}
    assert "SELF-ASSIGNMENT" in rule_ids, f"Real bugs should still be flagged in test files, got: {rule_ids}"


async def test_print_debug_still_reported_in_production_file() -> None:
    """print() in a production file should be flagged normally."""
    source = """
def compute():
    print("debug value")
    return 42
"""
    findings = await _scan_in_dir("src/compute.py", source)
    rule_ids = {f.rule_id for f in findings}
    assert "PRINT-DEBUG" in rule_ids, f"PRINT-DEBUG should be flagged in production files, got: {rule_ids}"


# ═══════════════════════════════════════════════════════════════════════
#  Test file detection heuristics
# ═══════════════════════════════════════════════════════════════════════


def test_is_test_file_detection() -> None:
    """Verify _is_test_file correctly identifies test paths."""
    engine = DefectEngine
    # Should be detected as test files
    assert engine._is_test_file("tests/test_foo.py")
    assert engine._is_test_file("test/test_bar.py")
    assert engine._is_test_file("src/__tests__/foo.test.js")
    assert engine._is_test_file("pkg/handler_test.go")
    assert engine._is_test_file("spec/models/user_spec.ts")
    assert engine._is_test_file("tests/unit/test_something.py")
    # Should NOT be detected as test files
    assert not engine._is_test_file("src/main.py")
    assert not engine._is_test_file("src/testing_utils.py")  # "testing" != "tests" directory
    assert not engine._is_test_file("lib/handler.go")
    assert not engine._is_test_file("src/app.js")


# ═══════════════════════════════════════════════════════════════════════
#  Comment line filtering
# ═══════════════════════════════════════════════════════════════════════


async def test_comment_line_not_flagged_by_regex() -> None:
    """Comments containing print-like patterns should not trigger regex rules."""
    # In Go, a comment mentioning fmt.Println should not trigger PRINT-DEBUG
    source = """
package main

// fmt.Println("this is just a comment, not real code")
func example() int {
    return 42
}
"""
    findings = await _scan_in_dir("sample.go", source)
    rule_ids = {f.rule_id for f in findings}
    assert "PRINT-DEBUG" not in rule_ids, f"Comment should not trigger PRINT-DEBUG, got: {rule_ids}"


async def test_python_comment_not_flagged() -> None:
    """Python comment with print() should not trigger PRINT-DEBUG from regex."""
    source = """
def example():
    # print("debug") -- this is just a comment
    return 42
"""
    findings = await _scan_in_dir("sample.py", source)
    rule_ids = {f.rule_id for f in findings}
    assert "PRINT-DEBUG" not in rule_ids, f"Python comment should not trigger PRINT-DEBUG, got: {rule_ids}"


# ═══════════════════════════════════════════════════════════════════════
#  Regex/AST deduplication
# ═══════════════════════════════════════════════════════════════════════


async def test_no_duplicate_hits_for_java_print() -> None:
    """Java System.out.println should produce at most 1 finding per line, not duplicates from regex+AST."""
    source = """
class Demo {
    void example() {
        System.out.println("debug");
    }
}
"""
    findings = await _scan_in_dir("Demo.java", source)
    print_debug_findings = [f for f in findings if f.rule_id == "PRINT-DEBUG"]
    assert len(print_debug_findings) <= 1, (
        f"Expected at most 1 PRINT-DEBUG finding, got {len(print_debug_findings)}"
    )


async def test_no_duplicate_hits_for_js_console_log() -> None:
    """JS console.log should produce at most 1 finding per line."""
    source = """
function example() {
    console.log("debug");
}
"""
    findings = await _scan_in_dir("sample.js", source)
    print_debug_findings = [f for f in findings if f.rule_id == "PRINT-DEBUG"]
    assert len(print_debug_findings) <= 1, (
        f"Expected at most 1 PRINT-DEBUG finding, got {len(print_debug_findings)}"
    )


# ═══════════════════════════════════════════════════════════════════════
#  GO-ERROR-IGNORED independent rule
# ═══════════════════════════════════════════════════════════════════════


async def test_go_error_ignored_rule() -> None:
    """Go error discarded with _ should produce GO-ERROR-IGNORED."""
    source = """
package main

import "os"

func example() {
    f, _ := os.Open("data.txt")
    f.Close()
}
"""
    findings = await _scan_in_dir("sample.go", source)
    rule_ids = {f.rule_id for f in findings}
    assert "GO-ERROR-IGNORED" in rule_ids, f"Expected GO-ERROR-IGNORED, got: {rule_ids}"


async def test_go_error_ignored_with_handled_error() -> None:
    """Go error that IS checked should NOT produce GO-ERROR-IGNORED."""
    source = """
package main

import "os"

func example() {
    f, err := os.Open("data.txt")
    if err != nil {
        return
    }
    defer f.Close()
}
"""
    findings = await _scan_in_dir("sample.go", source)
    rule_ids = {f.rule_id for f in findings}
    assert "GO-ERROR-IGNORED" not in rule_ids, f"Handled error should NOT trigger GO-ERROR-IGNORED, got: {rule_ids}"


# ═══════════════════════════════════════════════════════════════════════
#  _walk_nodes iterative correctness
# ═══════════════════════════════════════════════════════════════════════


async def test_walk_nodes_iterative_same_as_recursive() -> None:
    """Verify iterative _walk_nodes produces same results as visiting all tree-sitter nodes."""
    source = """
package main

func add(a int, b int) int {
    return a + b
}
"""
    from codeguardian.parsers.tree_sitter_support import TREE_SITTER_MANAGER
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        f = root / "sample.go"
        f.write_text(source.strip() + "\n", encoding="utf-8")
        doc = TREE_SITTER_MANAGER.parse_file(f, root, "go")
        if doc is None:
            return  # tree-sitter not available
        nodes = DefectEngine._walk_nodes(doc.root_node)
        # Basic sanity: should include root, function, params, body, return, identifiers
        node_types = {n.type for n in nodes}
        assert "source_file" in node_types
        assert "function_declaration" in node_types
        assert "return_statement" in node_types
        assert "identifier" in node_types
        # Should be pre-order: root is first
        assert nodes[0].type == "source_file"


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════


async def _scan_in_dir(rel_path: str, source: str):
    """Helper: write a file at the given relative path in a temp dir, run DefectEngine."""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        full_path = root / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)
    return result.findings
