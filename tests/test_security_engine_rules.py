"""Focused tests for upgraded security rules."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.security_engine import SecurityEngine
from codeguardian.models.enums import Severity



async def test_security_engine_detects_python_risks() -> None:
    source = """
import hashlib
import pickle
import random
import subprocess

password = "secret123"


def run(user_id, command, path, payload):
    cursor.execute(f"select * from users where id = {user_id}")
    subprocess.run(command, shell=True)
    digest = hashlib.md5(b"demo").hexdigest()
    token = random.randint(1, 9)
    data = pickle.loads(payload)
    return open(f"/tmp/{path}").read()
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

        rule_ids = {finding.rule_id for finding in result.findings}
        assert {
            "HARDCODED-PASSWORD",
            "SQL-INJECTION-RISK",
            "COMMAND-INJECTION-RISK",
            "WEAK-HASH",
            "INSECURE-RANDOM",
            "UNSAFE-DESERIALIZATION",
            "PATH-TRAVERSAL-RISK",
        }.issubset(rule_ids)


async def test_security_engine_avoids_sanitized_python_flows() -> None:
    source = """
import os
import shlex
import subprocess


def run(user_id, command, path):
    safe_path = os.path.normpath(path)
    safe_command = shlex.quote(command)
    cursor.execute("select * from users where id = %s", [user_id])
    subprocess.run(safe_command, shell=True)
    return open(safe_path).read()
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

        rule_ids = {finding.rule_id for finding in result.findings}
        assert "SQL-INJECTION-RISK" not in rule_ids
        assert "COMMAND-INJECTION-RISK" not in rule_ids
        assert "PATH-TRAVERSAL-RISK" not in rule_ids


async def test_security_engine_detects_javascript_risks() -> None:
    source = """
const token = "secret-1234";
db.query(`select * from users where id = ${userId}`);
exec(command);
crypto.createHash("md5");
Math.random();
fs.readFile(`./${name}`);
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.js").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

        rule_ids = {finding.rule_id for finding in result.findings}
        assert {
            "HARDCODED-PASSWORD",
            "SQL-INJECTION-RISK",
            "COMMAND-INJECTION-RISK",
            "WEAK-HASH",
            "INSECURE-RANDOM",
            "PATH-TRAVERSAL-RISK",
        }.issubset(rule_ids)


async def test_security_engine_detects_priority_language_regex_risks() -> None:
    cpp_source = """
#include <fstream>
#include <string>
void run(std::string user, std::string name, std::string command) {
  std::string password = "secret123";
  sqlite3_exec(db, ("SELECT * FROM users WHERE id = " + user).c_str(), 0, 0, 0);
  system(command.c_str());
  std::ifstream file("/tmp/" + name);
}
"""
    go_source = """
package main
import (
  "crypto/md5"
  "math/rand"
  "os"
  "os/exec"
)
func run(userID string, name string, command string) {
  password := "secret123"
  _ = password
  db.Query("SELECT * FROM users WHERE id = " + userID)
  exec.Command("sh", "-c", command)
  os.Open("/tmp/" + name)
  md5.New()
  rand.Intn(10)
}
"""
    csharp_source = """
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
class Demo {
  void Run(string userId, string name, string command) {
    var password = "secret123";
    var sql = "SELECT * FROM users WHERE id = " + userId;
    Process.Start(command);
    File.ReadAllText("/tmp/" + name);
    MD5.Create();
    new Random();
  }
}
"""
    lua_source = """
local password = "secret123"
local sql = "SELECT * FROM users WHERE id = " .. user_id
os.execute(command)
io.open("/tmp/" .. name)
"""
    rust_source = """
use std::process::Command;
fn run(user_id: &str, name: String, command: &str) {
  let password = "secret123";
  let _query = "SELECT * FROM users WHERE id = ".to_string() + user_id;
  Command::new("sh").arg("-c").arg(command).status();
  std::fs::read_to_string("/tmp/".to_string() + &name);
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.cpp").write_text(cpp_source.strip() + "\n", encoding="utf-8")
        (root / "sample.go").write_text(go_source.strip() + "\n", encoding="utf-8")
        (root / "Sample.cs").write_text(csharp_source.strip() + "\n", encoding="utf-8")
        (root / "sample.lua").write_text(lua_source.strip() + "\n", encoding="utf-8")
        (root / "sample.rs").write_text(rust_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    file_paths = {finding.location.file_path for finding in result.findings}

    assert {
        "HARDCODED-PASSWORD",
        "SQL-INJECTION-RISK",
        "COMMAND-INJECTION-RISK",
        "PATH-TRAVERSAL-RISK",
        "WEAK-HASH",
        "INSECURE-RANDOM",
    }.issubset(rule_ids)
    assert {"sample.cpp", "sample.go", "Sample.cs", "sample.lua", "sample.rs"}.issubset(file_paths)


async def test_security_engine_ignores_generated_protobuf_java_sources() -> None:
    generated_proto = """
// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: demo.proto

package demo;

public final class DemoProto {
  public int hashCode() {
    return getSubsystem();
  }

  public boolean getSubsystem() {
    return true;
  }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        target = root / "app" / "src" / "main" / "java" / "demo" / "pb" / "DemoProto.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(generated_proto.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    assert result.findings == []


async def test_security_engine_ignores_command_declarations_and_literal_shell_calls() -> None:
    c_source = """
int system(const char *);

void run(void) {
  system("ls -la");
}
"""
    js_source = """
const { exec } = require("child_process");
exec("ls -la");
"""
    java_source = """
class Demo {
  void run() throws Exception {
    Runtime.getRuntime().exec("ls");
  }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.cpp").write_text(c_source.strip() + "\n", encoding="utf-8")
        (root / "sample.js").write_text(js_source.strip() + "\n", encoding="utf-8")
        (root / "Demo.java").write_text(java_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    command_findings = [finding for finding in result.findings if finding.rule_id == "COMMAND-INJECTION-RISK"]
    assert command_findings == []


async def test_security_engine_marks_dynamic_shell_calls_as_blocking() -> None:
    java_source = """
class Demo {
  void run(String command) throws Exception {
    Runtime.getRuntime().exec(command);
  }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Demo.java").write_text(java_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    finding = next(finding for finding in result.findings if finding.rule_id == "COMMAND-INJECTION-RISK")
    assert finding.severity == Severity.CRITICAL
    assert finding.blocks_release is True
    assert finding.risk_priority == "must-fix"


