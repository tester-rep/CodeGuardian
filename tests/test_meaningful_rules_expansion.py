"""Behavior-locking tests for newly added meaningful detection rules.

Covers:
- STUB-IN-PROD (defect, regex)         — stub/not-implemented in production path
- PYTHON-LOCK-NO-RELEASE (defect, AST) — lock acquired without guaranteed release
- IO-IN-LOCK (performance, AST)        — blocking I/O inside `with lock:` block
- HTTP-NO-STATUS-CHECK (defect, AST)   — requests.* response consumed without status check
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine
from codeguardian.engines.performance_engine import PerformanceEngine


# ── STUB-IN-PROD ────────────────────────────────────────────────────────


async def test_stub_in_prod_python_not_implemented() -> None:
    source = """
def get_user(uid):
    raise NotImplementedError("wire up later")
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "STUB-IN-PROD"]
    assert len(hits) == 1
    assert hits[0].location.line_start == 2


async def test_stub_in_prod_go_panic_todo() -> None:
    source = """
package main

func DoWork() {
    panic("TODO: implement before launch")
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.go").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "STUB-IN-PROD"]
    assert len(hits) == 1


async def test_stub_in_prod_csharp_not_implemented_exception() -> None:
    source = """
public class Service {
    public string GetName() {
        throw new NotImplementedException();
    }
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Service.cs").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "STUB-IN-PROD"]
    assert len(hits) == 1


async def test_stub_in_prod_skips_normal_exceptions() -> None:
    """Normal `raise ValueError(...)` must NOT be flagged as stub."""
    source = """
def parse(x):
    if not x:
        raise ValueError("empty input")
    return x.upper()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "STUB-IN-PROD"]
    assert hits == []


# ── PYTHON-LOCK-NO-RELEASE ──────────────────────────────────────────────


async def test_lock_acquire_without_release_flagged() -> None:
    source = """
import threading

class Cache:
    def __init__(self):
        self._lock = threading.Lock()
        self._data = {}

    def write(self, k, v):
        self._lock.acquire()
        self._data[k] = v
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "cache.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "PYTHON-LOCK-NO-RELEASE"]
    assert len(hits) == 1


async def test_lock_release_outside_finally_still_flagged() -> None:
    """release() at the end of try (not in finally) leaks on exception path."""
    source = """
import threading

_lock = threading.Lock()

def update():
    _lock.acquire()
    try:
        do_work()
        _lock.release()
    except Exception:
        pass
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "u.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "PYTHON-LOCK-NO-RELEASE"]
    assert len(hits) == 1


async def test_lock_with_statement_not_flagged() -> None:
    """`with lock:` is the recommended pattern — must not trigger."""
    source = """
import threading

class Cache:
    def __init__(self):
        self._lock = threading.Lock()
        self._data = {}

    def write(self, k, v):
        with self._lock:
            self._data[k] = v
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "cache.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "PYTHON-LOCK-NO-RELEASE"]
    assert hits == []


async def test_lock_release_in_finally_not_flagged() -> None:
    """try/finally with release() in finally is safe."""
    source = """
import threading

_lock = threading.Lock()

def update():
    _lock.acquire()
    try:
        do_work()
    finally:
        _lock.release()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "u.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "PYTHON-LOCK-NO-RELEASE"]
    assert hits == []


async def test_acquire_on_non_lock_receiver_not_flagged() -> None:
    """`semaphore.acquire()` shouldn't fire (only "lock"/"mutex" suffix considered)."""
    source = """
class FakeFile:
    def acquire(self): pass
    def release(self): pass

def run():
    f = FakeFile()
    f.acquire()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "ff.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "PYTHON-LOCK-NO-RELEASE"]
    assert hits == []


# ── IO-IN-LOCK ──────────────────────────────────────────────────────────


async def test_http_call_inside_lock_flagged() -> None:
    source = """
import threading
import requests

_lock = threading.Lock()

def fetch_and_store(url):
    with _lock:
        resp = requests.get(url, timeout=5)
        return resp.text
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "f.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "IO-IN-LOCK"]
    assert len(hits) == 1


async def test_time_sleep_inside_lock_flagged() -> None:
    source = """
import threading
import time

_mutex = threading.Lock()

def wait_and_release():
    with _mutex:
        time.sleep(2)
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "w.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "IO-IN-LOCK"]
    assert len(hits) == 1


async def test_db_execute_inside_lock_flagged() -> None:
    source = """
import threading

_lock = threading.Lock()

def insert(cursor, row):
    with _lock:
        cursor.execute("INSERT INTO t VALUES (?)", (row,))
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "db.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "IO-IN-LOCK"]
    assert len(hits) == 1


async def test_pure_memory_op_inside_lock_not_flagged() -> None:
    """Only memory ops in a critical section is the correct pattern."""
    source = """
import threading

_lock = threading.Lock()
_data = {}

def store(k, v):
    with _lock:
        _data[k] = v
        _data["count"] = _data.get("count", 0) + 1
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "s.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "IO-IN-LOCK"]
    assert hits == []


async def test_io_in_non_lock_with_block_not_flagged() -> None:
    """`with open(...)` is not a lock — shouldn't trigger."""
    source = """
def read_file(path):
    with open(path) as f:
        return f.read()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "rf.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "IO-IN-LOCK"]
    assert hits == []


async def test_io_in_nested_function_inside_lock_not_flagged() -> None:
    """A nested def inside `with lock:` describes deferred execution; shouldn't fire."""
    source = """
import threading
import requests

_lock = threading.Lock()

def make_handler():
    with _lock:
        def handler():
            requests.get("http://x", timeout=1)
        return handler
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "h.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "IO-IN-LOCK"]
    assert hits == []


# ── HTTP-NO-STATUS-CHECK ────────────────────────────────────────────────


async def test_http_no_status_check_consumes_json_without_check() -> None:
    source = """
import requests

def fetch_user(uid):
    resp = requests.get(f"https://api/users/{uid}")
    data = resp.json()
    return data
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "client.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "HTTP-NO-STATUS-CHECK"]
    assert len(hits) == 1


async def test_http_with_raise_for_status_not_flagged() -> None:
    source = """
import requests

def fetch_user(uid):
    resp = requests.get(f"https://api/users/{uid}")
    resp.raise_for_status()
    return resp.json()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "client.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "HTTP-NO-STATUS-CHECK"]
    assert hits == []


async def test_http_with_status_code_check_not_flagged() -> None:
    source = """
import requests

def fetch_user(uid):
    resp = requests.get(f"https://api/users/{uid}")
    if resp.status_code != 200:
        return None
    return resp.json()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "client.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "HTTP-NO-STATUS-CHECK"]
    assert hits == []


async def test_http_returned_to_caller_not_flagged() -> None:
    """response 被 return 出去交给上层处理，本函数不该报警。"""
    source = """
import requests

def fetch_raw(uid):
    resp = requests.get(f"https://api/users/{uid}")
    return resp
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "client.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "HTTP-NO-STATUS-CHECK"]
    assert hits == []


async def test_http_passed_as_argument_not_flagged() -> None:
    """response 被作为参数交给别的函数，外层可能检查，不该误报。"""
    source = """
import requests

def fetch_user(uid):
    resp = requests.get(f"https://api/users/{uid}")
    process(resp)
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "client.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "HTTP-NO-STATUS-CHECK"]
    assert hits == []


async def test_http_session_get_not_flagged() -> None:
    """保守起见，session.<verb>() 不告警（避免 session 命名歧义带来的误报）。"""
    source = """
def fetch_user(session, uid):
    resp = session.get(f"https://api/users/{uid}")
    return resp.json()
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "client.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "HTTP-NO-STATUS-CHECK"]
    assert hits == []


async def test_http_no_consumption_not_flagged() -> None:
    """fire-and-forget：未消费 .json/.text/.content，不属于这条规则的范畴。"""
    source = """
import requests

def ping():
    resp = requests.get("https://api/ping")
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "client.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)

    hits = [f for f in result.findings if f.rule_id == "HTTP-NO-STATUS-CHECK"]
    assert hits == []

