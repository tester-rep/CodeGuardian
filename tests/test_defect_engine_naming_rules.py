"""Tests for naming-related defect detection rules.

Covers:
  - IDENTIFIER-TYPO
  - BOOL-PREFIX-NO-BOOL-RETURN
  - GETTER-HAS-SIDE-EFFECT
  - SETTER-RETURNS-VALUE
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


async def _run(source: str) -> list:
    """Helper: write source to a temp .py file and run DefectEngine."""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await DefectEngine().analyze(ctx)
        return result.findings


def _ids(findings: list) -> list[str]:
    return [f.rule_id for f in findings]


# ═══════════════════════════════════════════════════════════════════════
# IDENTIFIER-TYPO
# ═══════════════════════════════════════════════════════════════════════


async def test_typo_in_variable_name():
    findings = await _run("recieve_data = 42")
    assert "IDENTIFIER-TYPO" in _ids(findings)


async def test_typo_in_function_name():
    findings = await _run("def get_reponse():\n    return None")
    assert "IDENTIFIER-TYPO" in _ids(findings)


async def test_typo_in_function_argument():
    findings = await _run("def process(calender_data):\n    pass")
    assert "IDENTIFIER-TYPO" in _ids(findings)


async def test_typo_in_class_name():
    findings = await _run("class Enviroment:\n    pass")
    assert "IDENTIFIER-TYPO" in _ids(findings)


async def test_typo_in_snake_case_compound():
    findings = await _run("my_lenght = 100")
    assert "IDENTIFIER-TYPO" in _ids(findings)


async def test_typo_multiple_different_typos():
    findings = await _run("recieve_reponse = 1\nudpate_reuslt = 2")
    typo_hits = [f for f in findings if f.rule_id == "IDENTIFIER-TYPO"]
    # Should detect at least 2 distinct typos
    assert len(typo_hits) >= 2


async def test_no_typo_on_correct_spelling():
    findings = await _run("receive_data = 42\nresponse = None\ncalendar_event = True")
    assert "IDENTIFIER-TYPO" not in _ids(findings)


async def test_no_typo_on_short_names():
    findings = await _run("x = 1\ni = 0\nok = True")
    assert "IDENTIFIER-TYPO" not in _ids(findings)


async def test_no_typo_on_dunder():
    findings = await _run("class Foo:\n    def __init__(self):\n        pass")
    typo_hits = [f for f in findings if f.rule_id == "IDENTIFIER-TYPO"]
    # __init__ should not trigger typo
    init_typos = [h for h in typo_hits if "init" in h.message.lower()]
    assert len(init_typos) == 0


# ═══════════════════════════════════════════════════════════════════════
# BOOL-PREFIX-NO-BOOL-RETURN
# ═══════════════════════════════════════════════════════════════════════


async def test_bool_prefix_returning_string():
    findings = await _run('def is_valid():\n    return "yes"')
    assert "BOOL-PREFIX-NO-BOOL-RETURN" in _ids(findings)


async def test_bool_prefix_has_returning_int():
    findings = await _run("def has_items():\n    return 42")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" in _ids(findings)


async def test_bool_prefix_can_returning_list():
    findings = await _run("def can_access():\n    return [1, 2, 3]")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" in _ids(findings)


async def test_bool_prefix_should_returning_dict():
    findings = await _run('def should_retry():\n    return {"retry": True}')
    assert "BOOL-PREFIX-NO-BOOL-RETURN" in _ids(findings)


async def test_bool_prefix_ok_returning_true_false():
    findings = await _run("def is_valid():\n    if True:\n        return True\n    return False")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" not in _ids(findings)


async def test_bool_prefix_ok_returning_comparison():
    findings = await _run("def is_positive(x):\n    return x > 0")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" not in _ids(findings)


async def test_bool_prefix_ok_returning_isinstance():
    findings = await _run("def is_str(x):\n    return isinstance(x, str)")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" not in _ids(findings)


async def test_bool_prefix_ok_returning_bool_op():
    findings = await _run("def has_data(a, b):\n    return a and b")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" not in _ids(findings)


async def test_bool_prefix_ok_returning_not():
    findings = await _run("def is_empty(lst):\n    return not lst")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" not in _ids(findings)


async def test_bool_prefix_ok_no_explicit_return():
    findings = await _run('def is_setup():\n    print("setting up")')
    assert "BOOL-PREFIX-NO-BOOL-RETURN" not in _ids(findings)


async def test_bool_prefix_ok_ternary_bool():
    findings = await _run("def is_ok(x):\n    return True if x else False")
    assert "BOOL-PREFIX-NO-BOOL-RETURN" not in _ids(findings)


# ═══════════════════════════════════════════════════════════════════════
# GETTER-HAS-SIDE-EFFECT
# ═══════════════════════════════════════════════════════════════════════


async def test_getter_with_delete():
    code = "def get_user(db):\n    user = db.find(1)\n    db.delete(user)\n    return user"
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" in _ids(findings)


async def test_getter_with_save():
    code = "def get_or_create(db, name):\n    obj = db.find(name)\n    if not obj:\n        obj = db.save(name)\n    return obj"
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" in _ids(findings)


async def test_getter_with_send():
    code = 'def get_report(client):\n    client.send("generating")\n    return client.fetch()'
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" in _ids(findings)


async def test_getter_with_append():
    code = "results = []\ndef get_value(x):\n    results.append(x)\n    return x"
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" in _ids(findings)


async def test_getter_with_commit():
    code = "def get_data(session):\n    data = session.query()\n    session.commit()\n    return data"
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" in _ids(findings)


async def test_pure_getter_no_flag():
    code = "def get_name(user):\n    return user.name"
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" not in _ids(findings)


async def test_getter_with_read_ops_no_flag():
    code = 'def get_items(db):\n    items = db.query("SELECT *")\n    filtered = [i for i in items if i.active]\n    return filtered'
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" not in _ids(findings)


async def test_non_get_function_no_flag():
    code = "def fetch_and_delete(db, id):\n    obj = db.find(id)\n    db.delete(obj)\n    return obj"
    findings = await _run(code)
    assert "GETTER-HAS-SIDE-EFFECT" not in _ids(findings)


# ═══════════════════════════════════════════════════════════════════════
# SETTER-RETURNS-VALUE
# ═══════════════════════════════════════════════════════════════════════


async def test_setter_returning_string():
    code = "def set_name(self, name):\n    self.name = name\n    return name"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" in _ids(findings)


async def test_setter_returning_int():
    code = "def set_count(count):\n    return count + 1"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" in _ids(findings)


async def test_setter_returning_old_value():
    code = "class Config:\n    def set_timeout(self, val):\n        old = self.timeout\n        self.timeout = val\n        return old"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" in _ids(findings)


async def test_setter_returning_none_no_flag():
    code = "def set_name(self, name):\n    self.name = name\n    return None"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" not in _ids(findings)


async def test_setter_returning_self_no_flag():
    code = "class Builder:\n    def set_name(self, name):\n        self.name = name\n        return self"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" not in _ids(findings)


async def test_setter_no_return_no_flag():
    code = "def set_value(self, val):\n    self.value = val"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" not in _ids(findings)


async def test_setter_bare_return_no_flag():
    code = "def set_value(self, val):\n    self.value = val\n    return"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" not in _ids(findings)


async def test_non_set_function_no_flag():
    code = "def update_name(self, name):\n    self.name = name\n    return name"
    findings = await _run(code)
    assert "SETTER-RETURNS-VALUE" not in _ids(findings)
