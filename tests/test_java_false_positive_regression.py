"""Java false-positive regression tests.

Each case reproduces a confirmed false positive found by scanning a real Java
project (spr_robot_java). These guard against re-introducing the FP after fixes.
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


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _has_rule(findings, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


# ── FP-1: guarded Map.get(k) inside `if (map.get(k) != null)` ────────────
# Real case: MainTest.java lines 69-112. The parse call is fully guarded by an
# enclosing null check on the SAME get() expression, yet was flagged.


async def test_guarded_map_get_parse_not_flagged() -> None:
    source = """
import java.util.Map;
class MainTest {
    void parse(Map<String, String> paramMap) {
        if (paramMap.get("robotNum") != null) {
            int robotnum = Integer.parseInt(paramMap.get("robotNum"));
        }
    }
}
"""
    findings = await _scan_single_file("MainTest.java", source)
    assert not _has_rule(findings, "POSSIBLE-NONE-DEREF"), (
        f"Guarded map.get() must not be flagged, got: {_rule_ids(findings)}"
    )


async def test_unguarded_map_get_parse_still_flagged() -> None:
    """Control: the SAME pattern WITHOUT a guard must still be flagged (no regression in recall)."""
    source = """
import java.util.Map;
class MainTest {
    void parse(Map<String, String> paramMap) {
        int robotnum = Integer.parseInt(paramMap.get("robotNum"));
    }
}
"""
    findings = await _scan_single_file("MainTest.java", source)
    assert _has_rule(findings, "POSSIBLE-NONE-DEREF"), (
        f"Unguarded map.get() parse must still be flagged, got: {_rule_ids(findings)}"
    )


# ── FP-2: static METHOD misclassified as static mutable FIELD ────────────
# Real case: Tools.java:31 `public static void copyMap(Map dest, Map src)`,
# Sprconfig.java:308 `public static Properties loadConfProperties()`.


async def test_static_method_with_map_param_not_flagged() -> None:
    source = """
import java.util.Map;
class Tools {
    public static void copyMap(Map dest, Map src) {
        dest.clear();
        dest.putAll(src);
    }
}
"""
    findings = await _scan_single_file("Tools.java", source)
    assert not _has_rule(findings, "STATIC-MUTABLE-SHARED-STATE"), (
        f"Static method must not be flagged as static mutable state, got: {_rule_ids(findings)}"
    )


async def test_static_method_returning_properties_not_flagged() -> None:
    source = """
import java.util.Properties;
class Sprconfig {
    public static Properties loadConfProperties() {
        Properties properties = new Properties();
        return properties;
    }
}
"""
    findings = await _scan_single_file("Sprconfig.java", source)
    assert not _has_rule(findings, "STATIC-MUTABLE-SHARED-STATE"), (
        f"Static factory method must not be flagged, got: {_rule_ids(findings)}"
    )


async def test_static_mutable_field_still_flagged() -> None:
    """Control: a genuine non-final static mutable FIELD must still be flagged."""
    source = """
import java.util.HashMap;
import java.util.Map;
class Sprconfig {
    private static Map<String, String> cache = new HashMap<>();
}
"""
    findings = await _scan_single_file("Sprconfig.java", source)
    assert _has_rule(findings, "STATIC-MUTABLE-SHARED-STATE"), (
        f"Genuine static mutable field must still be flagged, got: {_rule_ids(findings)}"
    )
