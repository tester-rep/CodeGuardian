"""Tests for advanced bug-detection rules in DefectEngine.

Covers: EXCEPTION-NOT-RAISED, MUTABLE-DEFAULT-ARG, SELF-ASSIGNMENT,
        REDEFINE-IN-LOOP, EXCEPTION-LOST-CONTEXT, INFINITE-RECURSION-RISK,
        MISSING-SUPER-INIT.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.defaults import default_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


# ── EXCEPTION-NOT-RAISED ─────────────────────────────────────────────────


async def test_exception_not_raised_detected() -> None:
    source = """
def validate(x):
    if x < 0:
        ValueError("x must be positive")
    return x
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "EXCEPTION-NOT-RAISED"]
    assert len(hits) >= 1
    assert hits[0].location.line_start == 3


async def test_exception_raised_not_flagged() -> None:
    source = """
def validate(x):
    if x < 0:
        raise ValueError("x must be positive")
    return x
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "EXCEPTION-NOT-RAISED"]
    assert hits == []


async def test_custom_error_not_raised() -> None:
    source = """
class MyCustomError(Exception):
    pass

def process():
    MyCustomError("something failed")
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "EXCEPTION-NOT-RAISED"]
    assert len(hits) >= 1


# ── MUTABLE-DEFAULT-ARG ─────────────────────────────────────────────────


async def test_mutable_default_list_detected() -> None:
    source = """
def append_to(item, target=[]):
    target.append(item)
    return target
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "MUTABLE-DEFAULT-ARG"]
    assert len(hits) >= 1


async def test_mutable_default_dict_detected() -> None:
    source = """
def merge(extra, base={}):
    base.update(extra)
    return base
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "MUTABLE-DEFAULT-ARG"]
    assert len(hits) >= 1


async def test_immutable_default_not_flagged() -> None:
    source = """
def greet(name, greeting="hello"):
    return f"{greeting} {name}"
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "MUTABLE-DEFAULT-ARG"]
    assert hits == []


# ── SELF-ASSIGNMENT ──────────────────────────────────────────────────────


async def test_self_assignment_detected() -> None:
    source = """
def process(data):
    data = data
    return data
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "SELF-ASSIGNMENT"]
    assert len(hits) >= 1


async def test_self_attr_assignment_detected() -> None:
    source = """
class Foo:
    def reset(self):
        self.value = self.value
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "SELF-ASSIGNMENT"]
    assert len(hits) >= 1


async def test_normal_assignment_not_flagged() -> None:
    source = """
def process(data):
    result = data
    return result
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "SELF-ASSIGNMENT"]
    assert hits == []


# ── REDEFINE-IN-LOOP ────────────────────────────────────────────────────


async def test_function_redefined_in_loop() -> None:
    source = """
handlers = []
for i in range(5):
    def handler():
        return i
    handlers.append(handler)
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "REDEFINE-IN-LOOP"]
    assert len(hits) >= 1


async def test_function_outside_loop_not_flagged() -> None:
    source = """
def handler():
    return 42

for i in range(5):
    handler()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "REDEFINE-IN-LOOP"]
    assert hits == []


# ── EXCEPTION-LOST-CONTEXT ───────────────────────────────────────────────


async def test_exception_lost_context_detected() -> None:
    source = """
def process():
    try:
        risky()
    except ValueError:
        raise RuntimeError("failed")
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "EXCEPTION-LOST-CONTEXT"]
    assert len(hits) >= 1


async def test_exception_with_from_not_flagged() -> None:
    source = """
def process():
    try:
        risky()
    except ValueError as e:
        raise RuntimeError("failed") from e
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "EXCEPTION-LOST-CONTEXT"]
    assert hits == []


async def test_bare_reraise_not_flagged() -> None:
    source = """
def process():
    try:
        risky()
    except ValueError:
        raise
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "EXCEPTION-LOST-CONTEXT"]
    assert hits == []


# ── INFINITE-RECURSION-RISK ──────────────────────────────────────────────


async def test_infinite_recursion_detected() -> None:
    source = """
def loop():
    loop()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "INFINITE-RECURSION-RISK"]
    assert len(hits) >= 1


async def test_infinite_recursion_return() -> None:
    source = """
def loop():
    return loop()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "INFINITE-RECURSION-RISK"]
    assert len(hits) >= 1


async def test_conditional_recursion_not_flagged() -> None:
    source = """
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "INFINITE-RECURSION-RISK"]
    assert hits == []


# ── MISSING-SUPER-INIT ──────────────────────────────────────────────────


async def test_missing_super_init_detected() -> None:
    source = """
class Base:
    def __init__(self):
        self.value = 1

class Child(Base):
    def __init__(self):
        self.extra = 2
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "MISSING-SUPER-INIT"]
    assert len(hits) >= 1


async def test_super_init_called_not_flagged() -> None:
    source = """
class Base:
    def __init__(self):
        self.value = 1

class Child(Base):
    def __init__(self):
        super().__init__()
        self.extra = 2
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "MISSING-SUPER-INIT"]
    assert hits == []


async def test_no_base_class_not_flagged() -> None:
    source = """
class Standalone:
    def __init__(self):
        self.value = 1
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "MISSING-SUPER-INIT"]
    assert hits == []


async def test_exception_subclass_not_flagged() -> None:
    """Custom exceptions don't need to call super().__init__ explicitly."""
    source = """
class AppError(ValueError):
    def __init__(self, code):
        self.code = code
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "MISSING-SUPER-INIT"]
    assert hits == []


# ── EXCEPTION-SWALLOWED-NO-LOG ──────────────────────────────────────────


async def _run_defect_engine(source: str) -> list:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=default_config())
        result = await DefectEngine().analyze(ctx)
    return list(result.findings)


async def test_exception_swallowed_no_log_with_default_assign() -> None:
    """except: x = default — no log, no raise → flagged."""
    source = """
def parse(s):
    try:
        return int(s)
    except ValueError:
        result = 0
        return result
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "EXCEPTION-SWALLOWED-NO-LOG"]
    assert len(hits) == 1


async def test_exception_swallowed_no_log_with_default_return() -> None:
    """except Exception: return None — no log, no raise → flagged."""
    source = """
def fetch(url):
    try:
        return _http_get(url)
    except Exception:
        return None
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "EXCEPTION-SWALLOWED-NO-LOG"]
    assert len(hits) == 1


async def test_exception_swallowed_no_log_skips_empty_except() -> None:
    """except: pass is owned by EMPTY-EXCEPT, not by this rule."""
    source = """
def f():
    try:
        do()
    except Exception:
        pass
"""
    findings = await _run_defect_engine(source)
    swallow = [f for f in findings if f.rule_id == "EXCEPTION-SWALLOWED-NO-LOG"]
    empty = [f for f in findings if f.rule_id == "EMPTY-EXCEPT"]
    assert swallow == []
    assert len(empty) >= 1


async def test_exception_swallowed_no_log_skips_when_logged() -> None:
    """If logger.exception is called, LOG-ONLY-EXCEPT or
    SWALLOWED-EXCEPTION-FLOW take over — this rule should stay silent."""
    source = """
import logging
log = logging.getLogger(__name__)

def f():
    try:
        do()
    except Exception:
        log.exception("failed")
        return None
"""
    findings = await _run_defect_engine(source)
    swallow = [f for f in findings if f.rule_id == "EXCEPTION-SWALLOWED-NO-LOG"]
    assert swallow == []


async def test_exception_swallowed_no_log_skips_when_reraised() -> None:
    """If re-raised, the exception is not swallowed."""
    source = """
def f():
    try:
        do()
    except ValueError:
        cleanup()
        raise
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "EXCEPTION-SWALLOWED-NO-LOG"]
    assert hits == []


async def test_exception_swallowed_no_log_skips_when_reraised_new() -> None:
    """`raise NewError(...) from err` is also a re-raise."""
    source = """
def f():
    try:
        do()
    except ValueError as err:
        raise RuntimeError("bad") from err
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "EXCEPTION-SWALLOWED-NO-LOG"]
    assert hits == []


async def test_exception_swallowed_no_log_severity_is_low() -> None:
    """Severity must be LOW per design — below other meaningful defect rules."""
    source = """
def parse(s):
    try:
        return int(s)
    except ValueError:
        return -1
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "EXCEPTION-SWALLOWED-NO-LOG"]
    assert len(hits) == 1
    assert hits[0].severity.value == "low"


# ── SUBPROCESS-SHELL-TRUE ───────────────────────────────────────────────


async def test_subprocess_shell_true_run_detected() -> None:
    source = """
import subprocess

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "SUBPROCESS-SHELL-TRUE"]
    assert len(hits) == 1


async def test_subprocess_shell_true_popen_detected() -> None:
    source = """
import subprocess

def run_cmd():
    p = subprocess.Popen("ls -la", shell=True)
    return p
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "SUBPROCESS-SHELL-TRUE"]
    assert len(hits) == 1


async def test_subprocess_shell_true_check_output_detected() -> None:
    source = """
import subprocess

def get_branch():
    return subprocess.check_output("git rev-parse HEAD", shell=True)
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "SUBPROCESS-SHELL-TRUE"]
    assert len(hits) == 1


async def test_subprocess_shell_false_not_flagged() -> None:
    """Default shell=False or explicit shell=False must not be flagged."""
    source = """
import subprocess

def run_cmd():
    subprocess.run(["git", "status"])
    subprocess.run(["ls"], shell=False)
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "SUBPROCESS-SHELL-TRUE"]
    assert hits == []


async def test_subprocess_no_shell_kw_not_flagged() -> None:
    """Calls without a shell= keyword default to shell=False — silent."""
    source = """
import subprocess

def run_cmd():
    subprocess.check_output(["echo", "hello"])
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "SUBPROCESS-SHELL-TRUE"]
    assert hits == []


async def test_subprocess_shell_true_severity_is_low() -> None:
    """Severity must be LOW (security engine handles the CRITICAL path)."""
    source = """
import subprocess

def run_cmd():
    subprocess.run("ls", shell=True)
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "SUBPROCESS-SHELL-TRUE"]
    assert len(hits) == 1
    assert hits[0].severity.value == "low"


async def test_subprocess_shell_true_non_subprocess_call_ignored() -> None:
    """`some_other_lib.run(..., shell=True)` must not match — only the
    subprocess module is in scope."""
    source = """
def run_cmd(other):
    other.run("ls", shell=True)
"""
    findings = await _run_defect_engine(source)
    hits = [f for f in findings if f.rule_id == "SUBPROCESS-SHELL-TRUE"]
    assert hits == []

