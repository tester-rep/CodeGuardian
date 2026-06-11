"""P0 high-value bug rules — cross-language detection tests.

Covers 8 newly added rules:
- DICT-ITERATE-MUTATE          (Python)
- DUPLICATE-DICT-KEY           (Python)
- JAVA-STRING-EQ-OPERATOR      (Java)
- FOREACH-COLLECTION-MUTATE    (Java + C#)
- GO-RANGE-LOOP-VAR-ADDR       (Go)
- GO-CHANNEL-SEND-AFTER-CLOSE  (Go)
- CPP-USE-AFTER-FREE           (C++)
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


async def _scan_single_file(filename: str, source: str):
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / filename).write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)
    return result.findings


def _has_rule(findings, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ── DICT-ITERATE-MUTATE ──────────────────────────────────────────────


async def test_dict_iterate_del_detected() -> None:
    source = """
def cleanup(cache):
    for key in cache:
        if cache[key] == 0:
            del cache[key]
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "DICT-ITERATE-MUTATE"), _rule_ids(findings)


async def test_dict_iterate_pop_method_detected() -> None:
    source = """
def cleanup(cache):
    for key in cache.keys():
        cache.pop(key)
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "DICT-ITERATE-MUTATE"), _rule_ids(findings)


async def test_list_iterate_remove_detected() -> None:
    source = """
def filter_done(tasks):
    for task in tasks:
        if task == "done":
            tasks.remove(task)
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "DICT-ITERATE-MUTATE"), _rule_ids(findings)


async def test_dict_iterate_with_snapshot_not_flagged() -> None:
    """list(d) snapshot should NOT trigger."""
    source = """
def cleanup(cache):
    for key in list(cache):
        del cache[key]
"""
    findings = await _scan_single_file("sample.py", source)
    assert not _has_rule(findings, "DICT-ITERATE-MUTATE"), _rule_ids(findings)


async def test_dict_iterate_copy_not_flagged() -> None:
    source = """
def cleanup(cache):
    for key in cache.copy():
        del cache[key]
"""
    findings = await _scan_single_file("sample.py", source)
    assert not _has_rule(findings, "DICT-ITERATE-MUTATE"), _rule_ids(findings)


async def test_dict_assign_new_key_during_iteration_detected() -> None:
    source = """
def merge(defaults, user):
    for k in defaults:
        defaults[k + "_x"] = user.get(k)
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "DICT-ITERATE-MUTATE"), _rule_ids(findings)


# ── DUPLICATE-DICT-KEY ───────────────────────────────────────────────


async def test_duplicate_string_key_detected() -> None:
    source = """
config = {
    "host": "localhost",
    "port": 80,
    "host": "127.0.0.1",
}
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "DUPLICATE-DICT-KEY"), _rule_ids(findings)


async def test_duplicate_int_float_hash_equal_detected() -> None:
    """1 and 1.0 hash-equal in Python — runtime overwrites silently."""
    source = """
m = {1: "int", 1.0: "float"}
"""
    findings = await _scan_single_file("sample.py", source)
    assert _has_rule(findings, "DUPLICATE-DICT-KEY"), _rule_ids(findings)


async def test_unique_keys_not_flagged() -> None:
    source = """
config = {"host": "localhost", "port": 80, "name": "x"}
"""
    findings = await _scan_single_file("sample.py", source)
    assert not _has_rule(findings, "DUPLICATE-DICT-KEY"), _rule_ids(findings)


# ── JAVA-STRING-EQ-OPERATOR ──────────────────────────────────────────


async def test_java_string_literal_eq_detected() -> None:
    source = """
public class A {
    public boolean check(String s) {
        if (s == "hello") {
            return true;
        }
        return false;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "JAVA-STRING-EQ-OPERATOR"), _rule_ids(findings)


async def test_java_string_var_eq_detected() -> None:
    source = """
public class A {
    public boolean check(String a, String b) {
        return a != b;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "JAVA-STRING-EQ-OPERATOR"), _rule_ids(findings)


async def test_java_eq_null_not_flagged() -> None:
    """`s == null` is the legitimate null check — must not trigger."""
    source = """
public class A {
    public boolean isEmpty(String s) {
        return s == null;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert not _has_rule(findings, "JAVA-STRING-EQ-OPERATOR"), _rule_ids(findings)


async def test_java_int_eq_not_flagged() -> None:
    source = """
public class A {
    public boolean check(int a, int b) {
        return a == b;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert not _has_rule(findings, "JAVA-STRING-EQ-OPERATOR"), _rule_ids(findings)


# ── FOREACH-COLLECTION-MUTATE (Java) ─────────────────────────────────


async def test_java_foreach_remove_detected() -> None:
    source = """
import java.util.List;
public class A {
    public void clean(List<String> items) {
        for (String x : items) {
            if (x.isEmpty()) {
                items.remove(x);
            }
        }
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "FOREACH-COLLECTION-MUTATE"), _rule_ids(findings)


async def test_java_foreach_other_collection_not_flagged() -> None:
    """Mutating a DIFFERENT collection in the loop body is allowed."""
    source = """
import java.util.List;
public class A {
    public void copy(List<String> src, List<String> dst) {
        for (String x : src) {
            dst.add(x);
        }
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert not _has_rule(findings, "FOREACH-COLLECTION-MUTATE"), _rule_ids(findings)


# ── FOREACH-COLLECTION-MUTATE (C#) ───────────────────────────────────


async def test_csharp_foreach_remove_detected() -> None:
    source = """
using System.Collections.Generic;
public class A {
    public void Clean(List<string> items) {
        foreach (var x in items) {
            if (x == "") {
                items.Remove(x);
            }
        }
    }
}
"""
    findings = await _scan_single_file("A.cs", source)
    assert _has_rule(findings, "FOREACH-COLLECTION-MUTATE"), _rule_ids(findings)


# ── GO-RANGE-LOOP-VAR-ADDR ───────────────────────────────────────────


async def test_go_range_addr_detected() -> None:
    source = """
package main

type Item struct{ Name string }

func collect(xs []Item) []*Item {
    var out []*Item
    for _, v := range xs {
        out = append(out, &v)
    }
    return out
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "GO-RANGE-LOOP-VAR-ADDR"), _rule_ids(findings)


async def test_go_range_with_local_copy_not_flagged() -> None:
    """`v := v` local rebinding is the standard fix — must not trigger."""
    source = """
package main

type Item struct{ Name string }

func collect(xs []Item) []*Item {
    var out []*Item
    for _, v := range xs {
        v := v
        out = append(out, &v)
    }
    return out
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert not _has_rule(findings, "GO-RANGE-LOOP-VAR-ADDR"), _rule_ids(findings)


# ── GO-CHANNEL-SEND-AFTER-CLOSE ──────────────────────────────────────


async def test_go_channel_send_after_close_detected() -> None:
    source = """
package main

func produce(ch chan int) {
    ch <- 1
    close(ch)
    ch <- 2
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "GO-CHANNEL-SEND-AFTER-CLOSE"), _rule_ids(findings)


async def test_go_send_before_close_not_flagged() -> None:
    source = """
package main

func produce(ch chan int) {
    ch <- 1
    ch <- 2
    close(ch)
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert not _has_rule(findings, "GO-CHANNEL-SEND-AFTER-CLOSE"), _rule_ids(findings)


# ── CPP-USE-AFTER-FREE ───────────────────────────────────────────────


async def test_cpp_use_after_delete_detected() -> None:
    source = """
struct Node { int v; Node* next; };

void leak() {
    Node* p = new Node();
    delete p;
    p->v = 1;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "CPP-USE-AFTER-FREE"), _rule_ids(findings)


async def test_cpp_free_then_use_detected() -> None:
    source = """
#include <stdlib.h>

void leak() {
    int* p = (int*)malloc(sizeof(int));
    free(p);
    *p = 5;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "CPP-USE-AFTER-FREE"), _rule_ids(findings)


async def test_cpp_delete_then_nullptr_not_flagged() -> None:
    """Reassigning to nullptr after delete is the canonical fix — must not trigger."""
    source = """
struct Node { int v; };

void safe() {
    Node* p = new Node();
    delete p;
    p = nullptr;
    if (p) { p->v = 0; }
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert not _has_rule(findings, "CPP-USE-AFTER-FREE"), _rule_ids(findings)


# ── CPP-DOUBLE-FREE ──────────────────────────────────────────────────


async def test_cpp_double_delete_detected() -> None:
    source = """
void bad() {
    int* p = new int(1);
    delete p;
    delete p;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "CPP-DOUBLE-FREE"), _rule_ids(findings)


async def test_cpp_double_free_detected() -> None:
    source = """
#include <cstdlib>
void bad() {
    int* p = (int*)malloc(4);
    free(p);
    free(p);
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "CPP-DOUBLE-FREE"), _rule_ids(findings)


async def test_cpp_double_free_with_reassign_not_flagged() -> None:
    """Reassigning between frees avoids double-free."""
    source = """
void ok() {
    int* p = new int(1);
    delete p;
    p = new int(2);
    delete p;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert not _has_rule(findings, "CPP-DOUBLE-FREE"), _rule_ids(findings)


# ── CPP-DELETE-MISMATCH ──────────────────────────────────────────────


async def test_cpp_array_new_scalar_delete_detected() -> None:
    source = """
void bad() {
    int* arr;
    arr = new int[10];
    delete arr;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "CPP-DELETE-MISMATCH"), _rule_ids(findings)


async def test_cpp_scalar_new_array_delete_detected() -> None:
    source = """
void bad() {
    int* p;
    p = new int(5);
    delete[] p;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert _has_rule(findings, "CPP-DELETE-MISMATCH"), _rule_ids(findings)


async def test_cpp_matched_new_delete_not_flagged() -> None:
    source = """
void ok1() {
    int* a;
    a = new int[10];
    delete[] a;
}
void ok2() {
    int* b;
    b = new int(1);
    delete b;
}
"""
    findings = await _scan_single_file("sample.cpp", source)
    assert not _has_rule(findings, "CPP-DELETE-MISMATCH"), _rule_ids(findings)


# ── JAVA-HASHCODE-EQUALS-MISMATCH ────────────────────────────────────


async def test_java_only_equals_overridden_detected() -> None:
    source = """
public class Point {
    int x, y;
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Point)) return false;
        Point p = (Point) o;
        return x == p.x && y == p.y;
    }
}
"""
    findings = await _scan_single_file("Point.java", source)
    assert _has_rule(findings, "JAVA-HASHCODE-EQUALS-MISMATCH"), _rule_ids(findings)


async def test_java_only_hashcode_overridden_detected() -> None:
    source = """
public class Box {
    int v;
    @Override
    public int hashCode() {
        return v;
    }
}
"""
    findings = await _scan_single_file("Box.java", source)
    assert _has_rule(findings, "JAVA-HASHCODE-EQUALS-MISMATCH"), _rule_ids(findings)


async def test_java_both_overridden_not_flagged() -> None:
    source = """
public class Good {
    int v;
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Good)) return false;
        return ((Good) o).v == v;
    }
    @Override
    public int hashCode() { return v; }
}
"""
    findings = await _scan_single_file("Good.java", source)
    assert not _has_rule(findings, "JAVA-HASHCODE-EQUALS-MISMATCH"), _rule_ids(findings)


async def test_java_neither_overridden_not_flagged() -> None:
    source = """
public class Plain {
    int v;
    public int getV() { return v; }
}
"""
    findings = await _scan_single_file("Plain.java", source)
    assert not _has_rule(findings, "JAVA-HASHCODE-EQUALS-MISMATCH"), _rule_ids(findings)


# ── JAVA-EQUALS-ON-ARRAY ─────────────────────────────────────────────


async def test_java_equals_on_int_array_detected() -> None:
    source = """
public class A {
    public boolean same(int[] a, int[] b) {
        return a.equals(b);
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "JAVA-EQUALS-ON-ARRAY"), _rule_ids(findings)


async def test_java_equals_on_string_array_detected() -> None:
    source = """
public class A {
    public boolean check(String[] xs) {
        String[] ys = new String[]{"a"};
        return xs.equals(ys);
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "JAVA-EQUALS-ON-ARRAY"), _rule_ids(findings)


async def test_java_equals_on_string_not_flagged() -> None:
    """String.equals is correct content-comparison — must not trigger."""
    source = """
public class A {
    public boolean check(String x, String y) {
        return x.equals(y);
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert not _has_rule(findings, "JAVA-EQUALS-ON-ARRAY"), _rule_ids(findings)


# ── JAVA-INTEGER-BOXING-EQ ───────────────────────────────────────────


async def test_java_integer_boxing_eq_detected() -> None:
    source = """
public class A {
    public boolean same(Integer x, Integer y) {
        return x == y;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "JAVA-INTEGER-BOXING-EQ"), _rule_ids(findings)


async def test_java_long_boxing_neq_detected() -> None:
    source = """
public class A {
    public boolean diff(Long a, Long b) {
        return a != b;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "JAVA-INTEGER-BOXING-EQ"), _rule_ids(findings)


async def test_java_boxed_vs_null_not_flagged() -> None:
    """== null on boxed type is the canonical null-check — must not trigger."""
    source = """
public class A {
    public boolean isNull(Integer x) {
        return x == null;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert not _has_rule(findings, "JAVA-INTEGER-BOXING-EQ"), _rule_ids(findings)


async def test_java_primitive_int_eq_not_flagged() -> None:
    """Primitive int == int is value comparison — must not trigger."""
    source = """
public class A {
    public boolean same(int x, int y) {
        return x == y;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert not _has_rule(findings, "JAVA-INTEGER-BOXING-EQ"), _rule_ids(findings)


# ── GO-NIL-MAP-WRITE ─────────────────────────────────────────────────


async def test_go_nil_map_write_detected() -> None:
    source = """
package main

func Bad() {
    var m map[string]int
    m["x"] = 1
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert _has_rule(findings, "GO-NIL-MAP-WRITE"), _rule_ids(findings)


async def test_go_make_map_not_flagged() -> None:
    """make(map[...]...) initializes before write — must not trigger."""
    source = """
package main

func Ok() {
    m := make(map[string]int)
    m["x"] = 1
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert not _has_rule(findings, "GO-NIL-MAP-WRITE"), _rule_ids(findings)


async def test_go_map_literal_not_flagged() -> None:
    """var m = map[K]V{} is initialized — must not trigger."""
    source = """
package main

func Ok() {
    var m = map[string]int{}
    m["x"] = 1
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert not _has_rule(findings, "GO-NIL-MAP-WRITE"), _rule_ids(findings)


async def test_go_map_make_after_var_not_flagged() -> None:
    """Declared as var then initialized with make before write — must not trigger."""
    source = """
package main

func Ok() {
    var m map[string]int
    m = make(map[string]int)
    m["x"] = 1
}
"""
    findings = await _scan_single_file("sample.go", source)
    assert not _has_rule(findings, "GO-NIL-MAP-WRITE"), _rule_ids(findings)


# ── JAVA-INTEGER-BOXING-EQ regression: relaxed identifier constraint ──


async def test_java_boxing_eq_method_call_vs_var_detected() -> None:
    """Common real-world pattern: cache.get(...) == knownBoxedVar is a boxing bug.

    Previously the rule required both sides to be plain identifiers, so this
    very pattern (~70% of real-world cases per design analysis) was missed.
    """
    source = """
import java.util.Map;
public class A {
    public boolean check(Map<String, Integer> cache, Integer expected) {
        return cache.get("k") == expected;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert _has_rule(findings, "JAVA-INTEGER-BOXING-EQ"), _rule_ids(findings)


async def test_java_boxing_eq_no_boxed_context_not_flagged() -> None:
    """Without any known boxed local variable, do not flag generic `a == b`.

    This guards against the relaxation regressing into noise.
    """
    source = """
public class A {
    public boolean check(int a, int b) {
        return a == b;
    }
}
"""
    findings = await _scan_single_file("A.java", source)
    assert not _has_rule(findings, "JAVA-INTEGER-BOXING-EQ"), _rule_ids(findings)


# ── GO-RANGE-LOOP-VAR-ADDR: go.mod version awareness ─────────────────


async def _scan_with_go_mod(filename: str, source: str, go_directive: str):
    """Scan a single Go file alongside a go.mod containing the given directive."""
    from codeguardian.engines.defect_engine import _go_module_version

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / filename).write_text(source.strip() + "\n", encoding="utf-8")
        (root / "go.mod").write_text(
            f"module example.com/test\n\n{go_directive}\n", encoding="utf-8"
        )
        # Bust the lru_cache so each test's go.mod is read freshly.
        _go_module_version.cache_clear()
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)
        _go_module_version.cache_clear()
    return result.findings


async def test_go_range_addr_suppressed_on_go_122() -> None:
    """Go 1.22+ fixes range-variable scoping at the language level — rule must be silent."""
    source = """
package main

type Item struct{ Name string }

func collect(xs []Item) []*Item {
    var out []*Item
    for _, v := range xs {
        out = append(out, &v)
    }
    return out
}
"""
    findings = await _scan_with_go_mod("sample.go", source, "go 1.22")
    assert not _has_rule(findings, "GO-RANGE-LOOP-VAR-ADDR"), _rule_ids(findings)


async def test_go_range_addr_still_flagged_on_go_121() -> None:
    """Go 1.21 still has the bug — rule must remain active."""
    source = """
package main

type Item struct{ Name string }

func collect(xs []Item) []*Item {
    var out []*Item
    for _, v := range xs {
        out = append(out, &v)
    }
    return out
}
"""
    findings = await _scan_with_go_mod("sample.go", source, "go 1.21")
    assert _has_rule(findings, "GO-RANGE-LOOP-VAR-ADDR"), _rule_ids(findings)

