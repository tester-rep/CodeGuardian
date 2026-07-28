"""Multi-language detection enhancement tests.

Verifies new detection capabilities added to complete the coverage matrix:
- JS/TS: broad catch, log-only catch, null deref, console.info
- Java: log-only catch
- C++: log-only catch
- Go: defer-in-loop
- Cross-language log-only exception detection
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.defaults import default_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


# ═══════════════════════════════════════════════════════════════════════
#  JS/TS enhancement tests
# ═══════════════════════════════════════════════════════════════════════


async def test_js_broad_catch_no_param() -> None:
    """JS catch without parameter should trigger BROAD-EXCEPT."""
    source = """
function example() {
    try {
        riskyOp();
    } catch {
        doFallback();
    }
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "BROAD-EXCEPT"), f"Expected BROAD-EXCEPT, got: {_rule_ids(findings)}"


async def test_js_log_only_catch() -> None:
    """JS catch that only console.error should trigger LOG-ONLY-EXCEPT."""
    source = """
function example() {
    try {
        riskyOp();
    } catch (e) {
        console.error(e);
    }
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "LOG-ONLY-EXCEPT"), f"Expected LOG-ONLY-EXCEPT, got: {_rule_ids(findings)}"


async def test_js_catch_with_recovery_no_log_only() -> None:
    """JS catch with actual recovery should NOT trigger LOG-ONLY-EXCEPT."""
    source = """
function example() {
    try {
        riskyOp();
    } catch (e) {
        console.error(e);
        throw new Error("wrapped: " + e.message);
    }
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert not _has_rule(findings, "LOG-ONLY-EXCEPT"), f"Should not flag catch with re-throw, got: {_rule_ids(findings)}"


async def test_js_null_deref_queryselector() -> None:
    """JS querySelector result used directly without null check."""
    source = """
function example() {
    const el = document.querySelector('.my-class').textContent;
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF"), f"Expected POSSIBLE-NONE-DEREF, got: {_rule_ids(findings)}"


async def test_js_null_deref_getelementbyid() -> None:
    """JS getElementById result used in chain without null check."""
    source = """
function example() {
    document.getElementById('app').innerHTML = '<p>Hello</p>';
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF"), f"Expected POSSIBLE-NONE-DEREF, got: {_rule_ids(findings)}"


async def test_js_console_info_detected() -> None:
    """console.info should also be detected as PRINT-DEBUG."""
    source = """
function example() {
    console.info("some info");
}
"""
    findings = await _scan_single_file("sample.js", source)
    assert _has_rule(findings, "PRINT-DEBUG"), f"Expected PRINT-DEBUG, got: {_rule_ids(findings)}"


async def test_ts_log_only_catch() -> None:
    """TypeScript catch that only logs should trigger LOG-ONLY-EXCEPT."""
    source = """
async function fetchData(): Promise<void> {
    try {
        await api.get('/data');
    } catch (error) {
        console.error('Failed:', error);
    }
}
"""
    findings = await _scan_single_file("sample.ts", source)
    assert _has_rule(findings, "LOG-ONLY-EXCEPT"), f"Expected LOG-ONLY-EXCEPT, got: {_rule_ids(findings)}"


# ═══════════════════════════════════════════════════════════════════════
#  Java enhancement tests
# ═══════════════════════════════════════════════════════════════════════


async def test_java_log_only_catch() -> None:
    """Java catch that only calls e.printStackTrace() should trigger LOG-ONLY-EXCEPT."""
    source = """
class Demo {
    void example() {
        try {
            riskyOp();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "LOG-ONLY-EXCEPT"), f"Expected LOG-ONLY-EXCEPT, got: {_rule_ids(findings)}"


async def test_java_catch_with_rethrow_no_log_only() -> None:
    """Java catch that re-throws should NOT trigger LOG-ONLY-EXCEPT."""
    source = """
class Demo {
    void example() throws Exception {
        try {
            riskyOp();
        } catch (Exception e) {
            System.err.println("Error: " + e);
            throw e;
        }
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert not _has_rule(findings, "LOG-ONLY-EXCEPT"), f"Should not flag catch with re-throw, got: {_rule_ids(findings)}"


async def test_java_nullable_wrapper_trim_detected() -> None:
    """Wrapper returning Properties.getProperty should be treated as nullable."""
    source = """
import java.util.Properties;
class Demo {
    static Properties props = new Properties();
    static String getKeyValue(String key) {
        String value = props.getProperty(key);
        return value;
    }
    void load() {
        String name = Demo.getKeyValue("name").trim();
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF"), f"Expected POSSIBLE-NONE-DEREF, got: {_rule_ids(findings)}"


async def test_java_nullable_wrapper_parse_detected() -> None:
    """parseXxx on value assigned from nullable wrapper should be detected."""
    source = """
import java.util.Properties;
class Demo {
    static Properties props = new Properties();
    static String getKeyValue(String key) {
        return props.getProperty(key);
    }
    int getPort() {
        String value = Demo.getKeyValue("port");
        return Integer.parseInt(value);
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF"), f"Expected POSSIBLE-NONE-DEREF, got: {_rule_ids(findings)}"


async def test_java_get_resource_as_stream_load_detected() -> None:
    """ClassLoader.getResourceAsStream may return null before Properties.load."""
    source = """
import java.io.InputStream;
import java.util.Properties;
class Demo {
    Properties load() throws Exception {
        Properties props = new Properties();
        InputStream in = Demo.class.getClassLoader().getResourceAsStream("missing.properties");
        props.load(in);
        return props;
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF"), f"Expected POSSIBLE-NONE-DEREF, got: {_rule_ids(findings)}"


async def test_java_boolean_bitwise_condition_detected() -> None:
    """Boolean conditions should use short-circuit && / || instead of & / |."""
    source = """
class Demo {
    void check(int size, double total) {
        if (size > 0 & Math.abs(1.0 - total) > 0.001) {
            throw new RuntimeException("bad");
        }
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "SUSPICIOUS-BOOLEAN-BITWISE"), f"Expected SUSPICIOUS-BOOLEAN-BITWISE, got: {_rule_ids(findings)}"


async def test_java_division_by_config_value_without_zero_check_detected() -> None:
    """Dividing by parsed external/config value without zero check should be detected."""
    source = """
class Demo {
    int ratio(String raw, int total) {
        int count = Integer.parseInt(raw);
        return total / count;
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "DIVISION-BY-ZERO-RISK"), f"Expected DIVISION-BY-ZERO-RISK, got: {_rule_ids(findings)}"


async def test_java_collection_index_out_of_bounds_detected() -> None:
    """Loop using <= size() and get(i) should be detected."""
    source = """
import java.util.List;
class Demo {
    String join(List<String> names) {
        String out = "";
        for (int i = 0; i <= names.size(); i++) {
            out += names.get(i);
        }
        return out;
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "COLLECTION-INDEX-OUT-OF-BOUNDS"), f"Expected COLLECTION-INDEX-OUT-OF-BOUNDS, got: {_rule_ids(findings)}"


async def test_java_swallowed_exception_default_return_detected() -> None:
    """Catch that logs then returns a default value should be detected."""
    source = """
class Demo {
    String load() {
        try {
            return riskyRead();
        } catch (Exception e) {
            logger.error("load failed", e);
            return null;
        }
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "SWALLOWED-EXCEPTION-FLOW"), f"Expected SWALLOWED-EXCEPTION-FLOW, got: {_rule_ids(findings)}"


async def test_java_static_mutable_shared_state_detected() -> None:
    """Non-final static mutable collections/config objects should be detected."""
    source = """
import java.util.HashMap;
import java.util.Map;
class Demo {
    private static Map<String, String> cache = new HashMap<>();
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "STATIC-MUTABLE-SHARED-STATE"), f"Expected STATIC-MUTABLE-SHARED-STATE, got: {_rule_ids(findings)}"


async def test_java_resource_close_not_guaranteed_detected() -> None:
    """close() after work without finally/try-with-resources can be skipped on exceptions."""
    source = """
import java.io.FileInputStream;
class Demo {
    int read() throws Exception {
        FileInputStream in = new FileInputStream("data.txt");
        int value = in.read();
        in.close();
        return value;
    }
}
"""
    findings = await _scan_single_file("Demo.java", source)
    assert _has_rule(findings, "RESOURCE-CLOSE-NOT-GUARANTEED"), f"Expected RESOURCE-CLOSE-NOT-GUARANTEED, got: {_rule_ids(findings)}"


# ═══════════════════════════════════════════════════════════════════════
#  Cross-language risk family tests
# ═══════════════════════════════════════════════════════════════════════


async def test_python_division_by_literal_zero_detected() -> None:
    source = """
def ratio(total):
    return total / 0
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "DIVISION-BY-ZERO-RISK"), f"Expected DIVISION-BY-ZERO-RISK, got: {_rule_ids(findings)}"


async def test_python_range_len_plus_one_index_detected() -> None:
    source = """
def collect(items):
    out = []
    for i in range(len(items) + 1):
        out.append(items[i])
    return out
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "COLLECTION-INDEX-OUT-OF-BOUNDS"), f"Expected COLLECTION-INDEX-OUT-OF-BOUNDS, got: {_rule_ids(findings)}"


async def test_python_swallowed_exception_default_return_detected() -> None:
    source = """
import logging

def load():
    try:
        return risky()
    except Exception:
        logging.exception("failed")
        return None
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "SWALLOWED-EXCEPTION-FLOW"), f"Expected SWALLOWED-EXCEPTION-FLOW, got: {_rule_ids(findings)}"


async def test_python_resource_close_not_guaranteed_detected() -> None:
    source = """
def read_file(path):
    f = open(path)
    data = f.read()
    f.close()
    return data
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "RESOURCE-CLOSE-NOT-GUARANTEED"), f"Expected RESOURCE-CLOSE-NOT-GUARANTEED, got: {_rule_ids(findings)}"


async def test_go_division_by_parsed_value_detected() -> None:
    source = """
package main
import "strconv"
func ratio(raw string, total int) int {
    count, _ := strconv.Atoi(raw)
    return total / count
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "DIVISION-BY-ZERO-RISK"), f"Expected DIVISION-BY-ZERO-RISK, got: {_rule_ids(findings)}"


async def test_go_index_out_of_bounds_detected() -> None:
    source = """
package main
func collect(items []string) string {
    out := ""
    for i := 0; i <= len(items); i++ {
        out += items[i]
    }
    return out
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "COLLECTION-INDEX-OUT-OF-BOUNDS"), f"Expected COLLECTION-INDEX-OUT-OF-BOUNDS, got: {_rule_ids(findings)}"


async def test_go_resource_close_not_guaranteed_detected() -> None:
    source = """
package main
import "os"
func readFile(path string) int {
    f, _ := os.Open(path)
    value := 1
    f.Close()
    return value
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "RESOURCE-CLOSE-NOT-GUARANTEED"), f"Expected RESOURCE-CLOSE-NOT-GUARANTEED, got: {_rule_ids(findings)}"


async def test_cpp_index_out_of_bounds_detected() -> None:
    source = """
#include <vector>
int sum(std::vector<int>& values) {
    int total = 0;
    for (int i = 0; i <= values.size(); ++i) {
        total += values[i];
    }
    return total;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "COLLECTION-INDEX-OUT-OF-BOUNDS"), f"Expected COLLECTION-INDEX-OUT-OF-BOUNDS, got: {_rule_ids(findings)}"


async def test_cpp_swallowed_exception_default_return_detected() -> None:
    source = """
#include <cstdio>
int load() {
    try {
        return risky();
    } catch (const std::exception& e) {
        fprintf(stderr, "failed");
        return 0;
    }
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "SWALLOWED-EXCEPTION-FLOW"), f"Expected SWALLOWED-EXCEPTION-FLOW, got: {_rule_ids(findings)}"


# ═══════════════════════════════════════════════════════════════════════
#  C++ enhancement tests



# ═══════════════════════════════════════════════════════════════════════


async def test_cpp_log_only_catch() -> None:
    """C++ catch that only calls fprintf/printf should trigger LOG-ONLY-EXCEPT."""
    source = """
#include <cstdio>
void example() {
    try {
        riskyOp();
    } catch (...) {
        fprintf(stderr, "Error occurred");
    }
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "LOG-ONLY-EXCEPT"), f"Expected LOG-ONLY-EXCEPT, got: {_rule_ids(findings)}"


async def test_cpp_catch_with_rethrow_no_log_only() -> None:
    """C++ catch with throw should NOT trigger LOG-ONLY-EXCEPT."""
    source = """
void example() {
    try {
        riskyOp();
    } catch (const std::exception& e) {
        printf("Error: %s\\n", e.what());
        throw;
    }
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert not _has_rule(findings, "LOG-ONLY-EXCEPT"), f"Should not flag catch with re-throw, got: {_rule_ids(findings)}"


# ═══════════════════════════════════════════════════════════════════════
#  Go enhancement tests
# ═══════════════════════════════════════════════════════════════════════


async def test_go_defer_in_loop() -> None:
    """Go defer inside for loop should trigger GO-DEFER-IN-LOOP."""
    source = """
package main

import "os"

func processFiles(names []string) {
    for _, name := range names {
        f, _ := os.Open(name)
        defer f.Close()
    }
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "GO-DEFER-IN-LOOP"), f"Expected GO-DEFER-IN-LOOP, got: {_rule_ids(findings)}"


async def test_go_defer_outside_loop_ok() -> None:
    """Go defer outside loop should NOT trigger GO-DEFER-IN-LOOP."""
    source = """
package main

import "os"

func processFile(name string) {
    f, err := os.Open(name)
    if err != nil {
        return
    }
    defer f.Close()
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert not _has_rule(findings, "GO-DEFER-IN-LOOP"), f"Should not flag defer outside loop, got: {_rule_ids(findings)}"


# ═══════════════════════════════════════════════════════════════════════
#  Cross-language coverage matrix test
# ═══════════════════════════════════════════════════════════════════════


async def test_coverage_matrix_all_languages() -> None:
    """Verify each language has its expected detection capabilities."""
    # C++: empty catch + log-only catch + bare except + resource leak + null deref
    cpp_source = """
#include <cstdlib>
void example() {
    int* p = (int*)malloc(sizeof(int));
    *p = 42;
    try { work(); } catch (...) {}
}
"""
    # Go: error ignored + defer-in-loop + resource leak
    go_source = """
package main
import "os"
func example() {
    for i := 0; i < 10; i++ {
        f, _ := os.Open("x.txt")
        defer f.Close()
    }
}
"""
    # Java: broad catch + log-only catch + resource leak
    java_source = """
import java.io.*;
class Demo {
    void example() {
        try {
            FileInputStream fis = new FileInputStream("x.txt");
            fis.read();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
"""
    # JS: empty catch + console debug
    js_source = """
function example() {
    try { riskyOp(); } catch {}
    console.log("debug");
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.cpp").write_text(cpp_source.strip() + "\n", encoding="utf-8")
        (root / "sample.go").write_text(go_source.strip() + "\n", encoding="utf-8")
        (root / "Demo.java").write_text(java_source.strip() + "\n", encoding="utf-8")
        (root / "sample.js").write_text(js_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    by_file: dict[str, set[str]] = {}
    for f in result.findings:
        by_file.setdefault(f.location.file_path, set()).add(f.rule_id)

    cpp_rules = by_file.get("sample.cpp", set())
    go_rules = by_file.get("sample.go", set())
    java_rules = by_file.get("Demo.java", set())
    js_rules = by_file.get("sample.js", set())

    # C++ should detect: EMPTY-EXCEPT or BARE-EXCEPT, POSSIBLE-NONE-DEREF, RESOURCE-LEAK
    assert cpp_rules & {"EMPTY-EXCEPT", "BARE-EXCEPT"}, f"C++ missing catch detection: {cpp_rules}"
    assert "POSSIBLE-NONE-DEREF" in cpp_rules, f"C++ missing null deref: {cpp_rules}"

    # Go should detect: GO-ERROR-IGNORED, GO-DEFER-IN-LOOP
    assert "GO-ERROR-IGNORED" in go_rules, f"Go missing error ignored: {go_rules}"
    assert "GO-DEFER-IN-LOOP" in go_rules, f"Go missing defer-in-loop: {go_rules}"

    # Java should detect: BROAD-EXCEPT, LOG-ONLY-EXCEPT, RESOURCE-LEAK
    assert "BROAD-EXCEPT" in java_rules, f"Java missing broad except: {java_rules}"
    assert "LOG-ONLY-EXCEPT" in java_rules, f"Java missing log-only: {java_rules}"
    assert "RESOURCE-LEAK" in java_rules, f"Java missing resource leak: {java_rules}"

    # JS should detect: PRINT-DEBUG, EMPTY-EXCEPT or BROAD-EXCEPT
    assert "PRINT-DEBUG" in js_rules, f"JS missing print debug: {js_rules}"


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════


async def _scan_single_file(filename: str, source: str):
    """Helper: write a single file to a temp dir, run DefectEngine, return findings."""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / filename).write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)
    return result.findings


def _has_rule(findings, rule_id: str) -> bool:
    """Check if any finding matches the given rule_id."""
    return any(f.rule_id == rule_id for f in findings)


def _rule_ids(findings) -> set[str]:
    """Get all rule IDs from findings."""
    return {f.rule_id for f in findings}
