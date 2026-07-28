"""False-positive suppression: placeholder secrets, test-path & inline exemptions.

Covers:
- P0-1: HARDCODED-PASSWORD ignores placeholder / env-reference values.
- P0-2: Security & performance heuristic rules are suppressed in test files.
- P2-1: Inline suppression comments (# codeguardian: ignore / # noqa).

All helpers use ``default_config()`` so the repo-root ``codeguardian.toml``
(e.g. ``min_severity = "medium"``) cannot leak in and mask LOW-severity rules.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.defaults import default_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine
from codeguardian.engines.performance_engine import PerformanceEngine
from codeguardian.engines.security_engine import SecurityEngine


def _write_project(root: Path, files: dict[str, str]) -> None:
    for name, src in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")


async def _security(files: dict[str, str]) -> list:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        _write_project(root, files)
        ctx = ScanContext(project_root=str(root), config=default_config())
        return (await SecurityEngine().analyze(ctx)).findings


async def _defect(files: dict[str, str]) -> list:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        _write_project(root, files)
        ctx = ScanContext(project_root=str(root), config=default_config())
        return (await DefectEngine().analyze(ctx)).findings


async def _performance(files: dict[str, str]) -> list:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        _write_project(root, files)
        ctx = ScanContext(project_root=str(root), config=default_config())
        return (await PerformanceEngine().analyze(ctx)).findings


def _rule_ids(findings: list, filename: str) -> set[str]:
    return {f.rule_id for f in findings if f.location.file_path == filename}


# ── P0-1: placeholder / env-reference secret values ─────────────────────


async def test_python_placeholder_password_not_flagged() -> None:
    findings = await _security({"app/config.py": 'password = "your_password_here"\n'})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "app/config.py")


async def test_python_env_reference_not_flagged() -> None:
    findings = await _security({"app/config.py": 'api_key = "${API_KEY}"\n'})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "app/config.py")


async def test_python_real_password_still_flagged() -> None:
    findings = await _security({"app/config.py": 'password = "aB3$xK9zQ1wE"\n'})
    assert "HARDCODED-PASSWORD" in _rule_ids(findings, "app/config.py")


async def test_java_placeholder_password_not_flagged() -> None:
    src = "class Config {\n    String password = \"changeme\";\n}\n"
    findings = await _security({"app/Config.java": src})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "app/Config.java")


async def test_go_placeholder_password_not_flagged() -> None:
    # Short declaration (:=) is the Go path that actually fires HARDCODED-PASSWORD.
    src = "package main\n\nfunc f() {\n\tpassword := \"your_password_here\"\n\t_ = password\n}\n"
    findings = await _security({"app/config.go": src})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "app/config.go")


async def test_go_real_password_still_flagged() -> None:
    src = "package main\n\nfunc f() {\n\tpassword := \"aB3$xK9zQ1wE\"\n\t_ = password\n}\n"
    findings = await _security({"app/config.go": src})
    assert "HARDCODED-PASSWORD" in _rule_ids(findings, "app/config.go")


async def test_go_toplevel_var_real_password_flagged() -> None:
    # Top-level `var x = "..."`: value sits in an expression_list wrapper.
    src = "package main\n\nvar password = \"aB3$xK9zQ1wE\"\n"
    findings = await _security({"app/config.go": src})
    assert "HARDCODED-PASSWORD" in _rule_ids(findings, "app/config.go")


# ── P0-2: test-path exemptions ──────────────────────────────────────────


async def test_hardcoded_secret_suppressed_in_test_file() -> None:
    findings = await _security({"tests/test_auth.py": 'password = "aB3$xK9zQ1wE"\n'})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "tests/test_auth.py")


async def test_hardcoded_secret_flagged_in_source_file() -> None:
    findings = await _security({"app/auth.py": 'password = "aB3$xK9zQ1wE"\n'})
    assert "HARDCODED-PASSWORD" in _rule_ids(findings, "app/auth.py")


async def test_sql_injection_suppressed_in_test_file() -> None:
    src = (
        "package main\n\n"
        "func query(db interface{ Query(string) }, userId string) {\n"
        "    db.Query(\"SELECT * FROM users WHERE id = \" + userId)\n"
        "}\n"
    )
    findings = await _security({"storage/db_test.go": src})
    assert "SQL-INJECTION-RISK" not in _rule_ids(findings, "storage/db_test.go")


async def test_sql_injection_flagged_in_source_file() -> None:
    src = (
        "package main\n\n"
        "func query(db interface{ Query(string) }, userId string) {\n"
        "    db.Query(\"SELECT * FROM users WHERE id = \" + userId)\n"
        "}\n"
    )
    findings = await _security({"storage/db.go": src})
    assert "SQL-INJECTION-RISK" in _rule_ids(findings, "storage/db.go")


_SQL_IN_LOOP_SRC = (
    "def load(ids, cursor):\n"
    "    for uid in ids:\n"
    "        cursor.execute(\"SELECT * FROM t WHERE id=%s\", (uid,))\n"
)


async def test_sql_in_loop_suppressed_in_test_file() -> None:
    findings = await _performance({"tests/test_repo.py": _SQL_IN_LOOP_SRC})
    assert "SQL-IN-LOOP" not in _rule_ids(findings, "tests/test_repo.py")


async def test_sql_in_loop_flagged_in_source_file() -> None:
    findings = await _performance({"app/repo.py": _SQL_IN_LOOP_SRC})
    assert "SQL-IN-LOOP" in _rule_ids(findings, "app/repo.py")


async def test_missing_pagination_suppressed_in_test_file() -> None:
    src = "def list_all(repo):\n    return repo.find_all()\n"
    findings = await _performance({"tests/test_list.py": src})
    assert "MISSING-PAGINATION" not in _rule_ids(findings, "tests/test_list.py")


# ── Phase 2.1: inline suppression comments ──────────────────────────────


async def test_inline_ignore_trailing_comment() -> None:
    src = 'password = "aB3$xK9zQ1wE"  # codeguardian: ignore HARDCODED-PASSWORD\n'
    findings = await _security({"app/c.py": src})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "app/c.py")


async def test_inline_ignore_previous_line() -> None:
    src = '# codeguardian: ignore HARDCODED-PASSWORD\npassword = "aB3$xK9zQ1wE"\n'
    findings = await _security({"app/c.py": src})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "app/c.py")


async def test_noqa_trailing_comment() -> None:
    src = 'password = "aB3$xK9zQ1wE"  # noqa: HARDCODED-PASSWORD\n'
    findings = await _security({"app/c.py": src})
    assert "HARDCODED-PASSWORD" not in _rule_ids(findings, "app/c.py")


async def test_inline_ignore_other_rule_does_not_suppress() -> None:
    src = 'password = "aB3$xK9zQ1wE"  # codeguardian: ignore SQL-INJECTION-RISK\n'
    findings = await _security({"app/c.py": src})
    assert "HARDCODED-PASSWORD" in _rule_ids(findings, "app/c.py")


async def test_inline_ignore_defect_engine() -> None:
    src = "def f():\n    print('x')  # codeguardian: ignore PRINT-DEBUG\n"
    findings = await _defect({"app/d.py": src})
    assert "PRINT-DEBUG" not in _rule_ids(findings, "app/d.py")
