"""Focused tests for upgraded defect rules."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.schema import AppConfig
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


async def test_defect_engine_detects_python_and_catch_based_defects() -> None:
    python_source = """
def noisy(value):
    print(value)
    assert(value)
    try:
        risky()
    except:
        pass

    try:
        risky()
    except Exception:
        pass

# TODO remove dead unused path
"""
    js_source = """
try {
  work();
} catch (error) {
}
console.log("debug");
"""
    java_source = """
class Demo {
    void run() {
        try {
            work();
        } catch (Exception e) {
        }
        System.out.println("debug");
        assert ready;
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(python_source.strip() + "\n", encoding="utf-8")
        (root / "sample.js").write_text(js_source.strip() + "\n", encoding="utf-8")
        (root / "Demo.java").write_text(java_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=AppConfig())
        result = await DefectEngine().analyze(ctx)

        rule_ids = {finding.rule_id for finding in result.findings}
        assert {
            "DEAD-CODE",
            "EMPTY-EXCEPT",
            "PRINT-DEBUG",
            "ASSERT-USED",
            "BROAD-EXCEPT",
            "BARE-EXCEPT",
        }.issubset(rule_ids)


async def test_defect_engine_detects_priority_language_regex_rules() -> None:
    cpp_source = """
#include <cassert>
#include <iostream>
void run(bool ok) {
  std::cout << "debug";
  assert(ok);
  try { work(); } catch (...) {}
}
// TODO remove dead unused path
"""
    go_source = """
package main
import "fmt"
func run() {
  fmt.Println("debug")
}
// TODO remove dead unused path
"""
    csharp_source = """
using System;
using System.Diagnostics;
class Demo {
  void Run(bool ok) {
    Console.WriteLine("debug");
    Debug.Assert(ok);
    try { Work(); } catch (Exception ex) {}
  }
}
// TODO remove dead unused path
"""
    lua_source = """
local function run(ok)
  print("debug")
  assert(ok)
end
-- TODO remove dead unused path
"""
    rust_source = """
fn run(ok: bool) {
  println!("debug");
  assert!(ok);
}
// TODO remove dead unused path
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.cpp").write_text(cpp_source.strip() + "\n", encoding="utf-8")
        (root / "sample.go").write_text(go_source.strip() + "\n", encoding="utf-8")
        (root / "Sample.cs").write_text(csharp_source.strip() + "\n", encoding="utf-8")
        (root / "sample.lua").write_text(lua_source.strip() + "\n", encoding="utf-8")
        (root / "sample.rs").write_text(rust_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=AppConfig())
        result = await DefectEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    file_paths = {finding.location.file_path for finding in result.findings}

    assert {
        "DEAD-CODE",
        "PRINT-DEBUG",
        "ASSERT-USED",
        "EMPTY-EXCEPT",
        "BROAD-EXCEPT",
        "BARE-EXCEPT",
    }.issubset(rule_ids)
    assert {"sample.cpp", "sample.go", "Sample.cs", "sample.lua", "sample.rs"}.issubset(file_paths)


async def test_defect_engine_reports_syntax_errors_and_log_only_handlers() -> None:
    source = """
import logging

logger = logging.getLogger(__name__)


def noisy():
    try:
        risky()
    except ValueError:
        logger.exception("ignored")
"""
    broken_source = """
def broken(:
    pass
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        (root / "broken.py").write_text(broken_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=AppConfig())
        result = await DefectEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "LOG-ONLY-EXCEPT" in rule_ids
    assert "SYNTAX-ERROR" in rule_ids


async def test_defect_engine_does_not_treat_console_print_as_debug_print() -> None:
    source = """
from rich.console import Console

console = Console()
console.print("hello")
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=AppConfig())
        result = await DefectEngine().analyze(ctx)

    print_debug_findings = [finding for finding in result.findings if finding.rule_id == "PRINT-DEBUG"]
    assert print_debug_findings == []


async def test_defect_engine_detects_python_resource_leaks_with_low_noise() -> None:

    source = """
import sqlite3


def leak_file(path):
    handle = open(path)
    return handle.read()


def leak_db():
    conn = sqlite3.connect("demo.db")
    return 1


def safe_with(path):
    with open(path) as handle:
        return handle.read()


def safe_finally(path):
    handle = open(path)
    try:
        return handle.read()
    finally:
        handle.close()


def transfer(path):
    handle = open(path)
    return handle
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=AppConfig())
        result = await DefectEngine().analyze(ctx)

    resource_findings = [finding for finding in result.findings if finding.rule_id == "RESOURCE-LEAK"]
    assert len(resource_findings) == 2
    assert {finding.location.line_start for finding in resource_findings} == {5, 10}


