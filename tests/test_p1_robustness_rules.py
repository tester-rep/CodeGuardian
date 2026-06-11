"""Behavior-locking tests for P1 robustness rules.

Covers:
- STATIC-SIMPLEDATEFORMAT (defect, regex)   — Java shared SimpleDateFormat (thread-unsafe)
- MISSING-CHARSET         (defect, regex)   — Java String/IO ops without explicit charset
- MISSING-TIMEZONE        (defect, file)    — Java SimpleDateFormat without setTimeZone
- SWITCH-NO-DEFAULT       (defect, AST)     — Java switch without default branch
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine


async def _defect_findings(filename: str, source: str) -> list:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / filename).write_text(source, encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        return (await DefectEngine().analyze(ctx)).findings


# ── STATIC-SIMPLEDATEFORMAT ─────────────────────────────────────────────


async def test_static_sdf_private_static_final_flagged() -> None:
    source = """
import java.text.SimpleDateFormat;
public class Util {
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd");
    public static String fmt(java.util.Date d) { return SDF.format(d); }
}
"""
    findings = await _defect_findings("Util.java", source)
    hits = [f for f in findings if f.rule_id == "STATIC-SIMPLEDATEFORMAT"]
    assert len(hits) == 1


async def test_static_sdf_public_static_flagged() -> None:
    source = """
import java.text.SimpleDateFormat;
public class Util {
    public static SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd");
}
"""
    findings = await _defect_findings("Util.java", source)
    hits = [f for f in findings if f.rule_id == "STATIC-SIMPLEDATEFORMAT"]
    assert len(hits) == 1


async def test_static_sdf_local_variable_not_flagged() -> None:
    """方法内局部 SimpleDateFormat 是安全的（每次调用新建）。"""
    source = """
import java.text.SimpleDateFormat;
public class Util {
    public static String fmt(java.util.Date d) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        return sdf.format(d);
    }
}
"""
    findings = await _defect_findings("Util.java", source)
    hits = [f for f in findings if f.rule_id == "STATIC-SIMPLEDATEFORMAT"]
    assert hits == []


# ── MISSING-CHARSET ─────────────────────────────────────────────────────


async def test_missing_charset_new_string_no_charset_flagged() -> None:
    source = """
public class C {
    public static String decode(byte[] bytes) {
        return new String(bytes);
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "MISSING-CHARSET"]
    assert len(hits) == 1


async def test_missing_charset_get_bytes_no_arg_flagged() -> None:
    source = """
public class C {
    public static byte[] enc(String s) {
        return s.getBytes();
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "MISSING-CHARSET"]
    assert len(hits) == 1


async def test_missing_charset_file_reader_flagged() -> None:
    source = """
import java.io.*;
public class C {
    public static FileReader open(String path) throws Exception {
        return new FileReader(path);
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "MISSING-CHARSET"]
    assert len(hits) == 1


async def test_missing_charset_input_stream_reader_flagged() -> None:
    source = """
import java.io.*;
public class C {
    public static InputStreamReader wrap(InputStream in) {
        return new InputStreamReader(in);
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "MISSING-CHARSET"]
    assert len(hits) == 1


async def test_missing_charset_with_explicit_charset_not_flagged() -> None:
    source = """
import java.io.*;
import java.nio.charset.StandardCharsets;
public class C {
    public static String decode(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
    public static byte[] enc(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
    public static InputStreamReader wrap(InputStream in) {
        return new InputStreamReader(in, StandardCharsets.UTF_8);
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "MISSING-CHARSET"]
    assert hits == []


# ── MISSING-TIMEZONE ────────────────────────────────────────────────────


async def test_missing_timezone_sdf_without_set_flagged() -> None:
    source = """
import java.text.SimpleDateFormat;
public class Util {
    public static String fmt(java.util.Date d) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(d);
    }
}
"""
    findings = await _defect_findings("Util.java", source)
    hits = [f for f in findings if f.rule_id == "MISSING-TIMEZONE"]
    assert len(hits) == 1


async def test_missing_timezone_with_set_time_zone_not_flagged() -> None:
    source = """
import java.text.SimpleDateFormat;
import java.util.TimeZone;
public class Util {
    public static String fmt(java.util.Date d) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(d);
    }
}
"""
    findings = await _defect_findings("Util.java", source)
    hits = [f for f in findings if f.rule_id == "MISSING-TIMEZONE"]
    assert hits == []


async def test_missing_timezone_non_java_not_flagged() -> None:
    """规则只对 Java 启用，Python datetime 不应误报。"""
    source = """
from datetime import datetime
def fmt():
    return datetime.now().strftime("%Y-%m-%d")
"""
    findings = await _defect_findings("c.py", source)
    hits = [f for f in findings if f.rule_id == "MISSING-TIMEZONE"]
    assert hits == []


# ── SWITCH-NO-DEFAULT ───────────────────────────────────────────────────


async def test_switch_no_default_classic_flagged() -> None:
    source = """
public class C {
    public static int code(String s) {
        switch (s) {
            case "A": return 1;
            case "B": return 2;
        }
        return -1;
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "SWITCH-NO-DEFAULT"]
    assert len(hits) == 1


async def test_switch_with_default_not_flagged() -> None:
    source = """
public class C {
    public static int code(String s) {
        switch (s) {
            case "A": return 1;
            case "B": return 2;
            default: return -1;
        }
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "SWITCH-NO-DEFAULT"]
    assert hits == []


async def test_switch_arrow_with_default_not_flagged() -> None:
    """Java 14+ switch 表达式，default -> ... 形式。"""
    source = """
public class C {
    public static int code(String s) {
        return switch (s) {
            case "A" -> 1;
            case "B" -> 2;
            default -> -1;
        };
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "SWITCH-NO-DEFAULT"]
    assert hits == []
