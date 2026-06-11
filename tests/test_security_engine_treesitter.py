"""Tests for SecurityEngine C++ and Go tree-sitter deep analysis."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.security_engine import SecurityEngine
from codeguardian.models.enums import Severity


# ═══════════════════════════════════════════════════════════════════════
# C++ tree-sitter security tests
# ═══════════════════════════════════════════════════════════════════════


async def test_cpp_treesitter_detects_hardcoded_password() -> None:
    source = """
#include <string>
void init() {
    std::string password = "super_secret_123";
    std::string api_key = "AKIAIOSFODNN7EXAMPLE";
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "auth.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    rule_ids = {f.rule_id for f in result.findings if f.location.file_path == "auth.cpp"}
    assert "HARDCODED-PASSWORD" in rule_ids


async def test_cpp_treesitter_detects_command_injection() -> None:
    source = """
#include <cstdlib>
void run(const char* userInput) {
    system(userInput);
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "exec.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    cmd_findings = [f for f in result.findings if f.rule_id == "COMMAND-INJECTION-RISK"]
    assert len(cmd_findings) >= 1


async def test_cpp_treesitter_no_command_injection_for_literal() -> None:
    """system("ls") with a literal argument should NOT trigger."""
    source = """
#include <cstdlib>
void run() {
    system("ls -la");
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "safe.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    cmd_findings = [f for f in result.findings if f.rule_id == "COMMAND-INJECTION-RISK"]
    assert cmd_findings == []


async def test_cpp_treesitter_detects_weak_hash_and_insecure_random() -> None:
    source = """
#include <cstdlib>
void crypto_ops() {
    MD5_Init(nullptr);
    int r = rand();
    srand(42);
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "crypto.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    rule_ids = {f.rule_id for f in result.findings if f.location.file_path == "crypto.cpp"}
    assert "WEAK-HASH" in rule_ids
    assert "INSECURE-RANDOM" in rule_ids


# ═══════════════════════════════════════════════════════════════════════
# Go tree-sitter security tests
# ═══════════════════════════════════════════════════════════════════════


async def test_go_treesitter_detects_hardcoded_password() -> None:
    source = """
package main

func init() {
    password := "super_secret_123"
    _ = password
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "auth.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    rule_ids = {f.rule_id for f in result.findings if f.location.file_path == "auth.go"}
    assert "HARDCODED-PASSWORD" in rule_ids


async def test_go_treesitter_detects_command_injection() -> None:
    source = """
package main

import "os/exec"

func run(userCmd string) {
    exec.Command("sh", "-c", userCmd)
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "exec.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    cmd_findings = [f for f in result.findings if f.rule_id == "COMMAND-INJECTION-RISK"]
    assert len(cmd_findings) >= 1


async def test_go_treesitter_no_command_injection_for_literal() -> None:
    """exec.Command("sh", "-c", "ls") with literal should NOT trigger."""
    source = """
package main

import "os/exec"

func run() {
    exec.Command("sh", "-c", "ls -la")
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "safe.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    cmd_findings = [f for f in result.findings if f.rule_id == "COMMAND-INJECTION-RISK"]
    assert cmd_findings == []


async def test_go_treesitter_detects_weak_hash_and_insecure_random() -> None:
    source = """
package main

import (
    "crypto/md5"
    "math/rand"
)

func crypto_ops() {
    md5.New()
    rand.Intn(100)
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "crypto.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    rule_ids = {f.rule_id for f in result.findings if f.location.file_path == "crypto.go"}
    assert "WEAK-HASH" in rule_ids
    assert "INSECURE-RANDOM" in rule_ids


async def test_go_treesitter_detects_sql_injection() -> None:
    source = """
package main

func query(db interface{ Query(string) }, userId string) {
    db.Query("SELECT * FROM users WHERE id = " + userId)
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "db.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    rule_ids = {f.rule_id for f in result.findings if f.location.file_path == "db.go"}
    assert "SQL-INJECTION-RISK" in rule_ids


async def test_go_treesitter_combined_risks() -> None:
    """Full Go file with multiple security risks — tree-sitter should detect all."""
    source = """
package main

import (
    "crypto/md5"
    "math/rand"
    "os/exec"
)

func vulnerable(userID string, cmd string) {
    password := "super_secret"
    _ = password
    md5.New()
    rand.Intn(10)
    exec.Command("sh", "-c", cmd)
    db.Query("SELECT * FROM users WHERE id = " + userID)
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "vuln.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await SecurityEngine().analyze(ctx)

    rule_ids = {f.rule_id for f in result.findings if f.location.file_path == "vuln.go"}
    assert "HARDCODED-PASSWORD" in rule_ids
    assert "WEAK-HASH" in rule_ids
    assert "INSECURE-RANDOM" in rule_ids
    assert "COMMAND-INJECTION-RISK" in rule_ids
    assert "SQL-INJECTION-RISK" in rule_ids
