"""Phase 1: Deep tree-sitter defect detection tests for C++, Go, Lua, Java, JS/TS.

Tests verify that detection rules previously only available for Python
now also fire correctly for priority languages via tree-sitter analysis.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.schema import AppConfig
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


# ═══════════════════════════════════════════════════════════════════════
#  C++ deep detection tests
# ═══════════════════════════════════════════════════════════════════════


async def test_cpp_unreachable_code() -> None:
    source = """
void example() {
    return;
    int x = 42;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "UNREACHABLE-CODE")


async def test_cpp_self_assignment() -> None:
    source = """
void example() {
    int x = 10;
    x = x;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "SELF-ASSIGNMENT")


async def test_cpp_infinite_recursion() -> None:
    source = """
void broken() {
    broken();
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "INFINITE-RECURSION-RISK")


async def test_cpp_resource_leak() -> None:
    source = """
#include <cstdio>
void leak() {
    FILE* f = fopen("data.txt", "r");
    int x = 1;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "RESOURCE-LEAK")


async def test_cpp_null_deref() -> None:
    source = """
#include <cstdlib>
void unsafe() {
    int* p = (int*)malloc(sizeof(int));
    *p = 42;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF")


async def test_cpp_empty_catch() -> None:
    source = """
void example() {
    try {
        work();
    } catch (...) {
    }
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    # Should detect either EMPTY-EXCEPT or BARE-EXCEPT for catch(...)
    rule_ids = {f.rule_id for f in findings}
    assert "EMPTY-EXCEPT" in rule_ids or "BARE-EXCEPT" in rule_ids


async def test_cpp_print_debug() -> None:
    source = """
#include <cstdio>
void example() {
    printf("debug value %d", x);
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "PRINT-DEBUG")


# ═══════════════════════════════════════════════════════════════════════
#  Go deep detection tests
# ═══════════════════════════════════════════════════════════════════════


async def test_go_unreachable_code() -> None:
    source = """
package main

func example() int {
    return 42
    x := 10
    return x
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "UNREACHABLE-CODE")


async def test_go_self_assignment() -> None:
    source = """
package main

func example() {
    x := 10
    x = x
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "SELF-ASSIGNMENT")


async def test_go_error_ignored() -> None:
    """Go error discarded with _ should be detected by GO-ERROR-IGNORED rule."""
    source = """
package main

import "os"

func example() {
    f, _ := os.Open("data.txt")
    f.Close()
}
"""
    findings = await _scan_single_file("sample.go", source)
    rule_ids = {f.rule_id for f in findings}
    assert "GO-ERROR-IGNORED" in rule_ids, f"Expected GO-ERROR-IGNORED, got: {rule_ids}"


async def test_go_resource_leak() -> None:
    source = """
package main

import "os"

func example() {
    f, err := os.Open("data.txt")
    if err != nil {
        return
    }
    _ = f
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "RESOURCE-LEAK")


async def test_go_print_debug() -> None:
    source = """
package main

import "fmt"

func example() {
    fmt.Println("debug")
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "PRINT-DEBUG")


# ═══════════════════════════════════════════════════════════════════════
#  Lua deep detection tests
# ═══════════════════════════════════════════════════════════════════════


async def test_lua_print_debug() -> None:
    source = """
local function example()
    print("debug")
end
"""
    findings = await _scan_single_file("sample.lua", source)
    assert _has_rule(findings, "PRINT-DEBUG")


async def test_lua_assert_used() -> None:
    source = """
local function example(x)
    assert(x > 0)
end
"""
    findings = await _scan_single_file("sample.lua", source)
    assert _has_rule(findings, "ASSERT-USED")


async def test_lua_self_assignment() -> None:
    source = """
local function example()
    local x = 10
    x = x
end
"""
    findings = await _scan_single_file("sample.lua", source)
    assert _has_rule(findings, "SELF-ASSIGNMENT")


# ═══════════════════════════════════════════════════════════════════════
#  Enhanced Java deep detection tests
# ═══════════════════════════════════════════════════════════════════════


async def test_java_unreachable_code() -> None:
    source = """
class Demo {
    void example() {
        return;
        int x = 42;
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "UNREACHABLE-CODE")


async def test_java_self_assignment() -> None:
    source = """
class Demo {
    void example() {
        int x = 10;
        x = x;
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "SELF-ASSIGNMENT")


async def test_java_resource_leak() -> None:
    source = """
import java.io.*;

class Demo {
    void example() throws Exception {
        FileInputStream fis = new FileInputStream("data.txt");
        int x = fis.read();
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "RESOURCE-LEAK")


async def test_java_null_deref_method_chain() -> None:
    source = """
import java.util.*;

class Demo {
    void example() {
        Map<String, String> map = new HashMap<>();
        String result = map.get("key").toUpperCase();
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF")


async def test_java_infinite_recursion() -> None:
    source = """
class Demo {
    void broken() {
        broken();
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "INFINITE-RECURSION-RISK")


# ═══════════════════════════════════════════════════════════════════════
#  Enhanced JavaScript/TypeScript deep detection tests
# ═══════════════════════════════════════════════════════════════════════


async def test_js_unreachable_code() -> None:
    source = """
function example() {
    return 42;
    let x = 10;
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "UNREACHABLE-CODE")


async def test_js_self_assignment() -> None:
    source = """
function example() {
    let x = 10;
    x = x;
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "SELF-ASSIGNMENT")


async def test_js_infinite_recursion() -> None:
    source = """
function broken() {
    broken();
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "INFINITE-RECURSION-RISK")


async def test_ts_unreachable_code() -> None:
    source = """
function example(): number {
    return 42;
    const x: number = 10;
}
"""
    findings = await _scan_single_file("sample.ts", source)
    assert _has_rule(findings, "UNREACHABLE-CODE")


# ═══════════════════════════════════════════════════════════════════════
#  Cross-language comprehensive test
# ═══════════════════════════════════════════════════════════════════════


async def test_multi_language_deep_detection() -> None:
    """Verify that deep detection works across all priority languages in a single project."""
    cpp_source = """
void buggy() {
    return;
    int dead_code = 1;
}
"""
    go_source = """
package main

import "fmt"

func buggy() int {
    return 42
    x := 10
    return x
}
"""
    java_source = """
class Buggy {
    void broken() {
        return;
        int x = 42;
    }
}
"""
    js_source = """
function buggy() {
    return 42;
    let x = 10;
}
"""
    lua_source = """
local function buggy()
    local x = 10
    x = x
end
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.cpp").write_text(cpp_source.strip() + "\n", encoding="utf-8")
        (root / "sample.go").write_text(go_source.strip() + "\n", encoding="utf-8")
        (root / "Buggy.java").write_text(java_source.strip() + "\n", encoding="utf-8")
        (root / "sample.js").write_text(js_source.strip() + "\n", encoding="utf-8")
        (root / "sample.lua").write_text(lua_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=AppConfig())
        result = await DefectEngine().analyze(ctx)

    # Group findings by file
    findings_by_file: dict[str, set[str]] = {}
    for f in result.findings:
        findings_by_file.setdefault(f.location.file_path, set()).add(f.rule_id)

    # Every language should have detected UNREACHABLE-CODE or SELF-ASSIGNMENT
    assert "UNREACHABLE-CODE" in findings_by_file.get("sample.cpp", set()), "C++ unreachable not detected"
    assert "UNREACHABLE-CODE" in findings_by_file.get("sample.go", set()), "Go unreachable not detected"
    assert "UNREACHABLE-CODE" in findings_by_file.get("Buggy.java", set()), "Java unreachable not detected"
    assert "UNREACHABLE-CODE" in findings_by_file.get("sample.js", set()), "JS unreachable not detected"
    assert "SELF-ASSIGNMENT" in findings_by_file.get("sample.lua", set()), "Lua self-assignment not detected"


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════


async def _scan_single_file(filename: str, source: str):
    """Helper: write a single file to a temp dir, run DefectEngine, return findings."""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / filename).write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=AppConfig())
        result = await DefectEngine().analyze(ctx)
    return result.findings


def _has_rule(findings, rule_id: str) -> bool:
    """Check if any finding matches the given rule_id."""
    return any(f.rule_id == rule_id for f in findings)
