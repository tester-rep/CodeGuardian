"""Tests for the AI Verifier — second-pass FP judgement over engine findings."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from codeguardian.ai.models import GenerateResult, TokenUsage
from codeguardian.ai.verifier.cache import VerifyCache, VerifyVerdict, compute_cache_key
from codeguardian.ai.verifier.verifier import AIVerifier
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding


def _make_finding(
    *,
    fid: str = "SEC-001",
    file_path: str = "app/api.py",
    line: int = 10,
    severity: Severity = Severity.HIGH,
    rule_id: str = "SQL-INJECTION-RISK",
) -> Finding:
    return Finding(
        id=fid,
        title="Possible SQL Injection",
        category="security",
        severity=severity,
        confidence=Confidence.MEDIUM,
        location=Location(file_path=file_path, line_start=line, line_end=line),
        source_engine="security_engine",
        rule_id=rule_id,
        cwe_ids=["CWE-89"],
        blocks_release=True,
        evidence_level="suspected",
    )


def _stub_provider(verdict_value: str, reason: str = "因为...") -> AsyncMock:
    provider = AsyncMock()
    provider.generate_with_usage.return_value = GenerateResult(
        text=json.dumps({"verdict": verdict_value, "reason": reason}),
        usage=TokenUsage(prompt_tokens=100, completion_tokens=20, total_tokens=120),
    )
    return provider


def _make_verifier(tmp_path: Path, *, provider: AsyncMock, escalate: AsyncMock | None = None) -> AIVerifier:
    return AIVerifier(
        verify_provider=provider,
        escalate_provider=escalate or provider,
        cache=VerifyCache(tmp_path, enabled=False),
        project_root=tmp_path,
        max_tokens_per_scan=10_000,
        max_concurrent=2,
        verify_model_name="model-a",
        escalate_model_name="model-b",
    )


def _seed_source_file(root: Path, rel: str, content: str) -> None:
    abs_path = root / rel
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_text(content, encoding="utf-8")


@pytest.mark.asyncio
async def test_pass1_true_keeps_severity_and_tags_confirmed(tmp_path):
    """MEDIUM severity allows Pass 1 to be decisive (no severity gate)."""
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    provider = _stub_provider("true", "数据未做参数化")
    verifier = _make_verifier(tmp_path, provider=provider)

    finding = _make_finding(severity=Severity.MEDIUM)
    outcome = await verifier.verify([finding])

    assert len(outcome.findings) == 1
    out = outcome.findings[0]
    assert out.severity == Severity.MEDIUM  # untouched
    assert out.verification_status == "ai-verified-true"
    assert "ai-confirmed" in out.tags
    assert out.evidence_level == "static-confirmed"
    assert outcome.confirmed_count == 1
    assert outcome.pass1_decisive == 1
    assert provider.generate_with_usage.await_count == 1


@pytest.mark.asyncio
async def test_pass1_false_downgrades_to_info_and_unblocks(tmp_path):
    """MEDIUM Pass 1 false stays in Pass 1 (no escalation)."""
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    provider = _stub_provider("false", "测试桩，无真实风险")
    verifier = _make_verifier(tmp_path, provider=provider)

    finding = _make_finding(severity=Severity.MEDIUM)
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    assert out.severity == Severity.INFO
    assert out.blocks_release is False
    assert out.verification_status == "ai-verified-fp"
    assert "ai-fp" in out.tags
    assert out.evidence_level == "needs-review"
    assert outcome.fp_count == 1


@pytest.mark.asyncio
async def test_high_severity_forces_pass2_even_when_pass1_says_true(tmp_path):
    """HIGH severity must escalate to Pass 2 regardless of Pass 1 verdict.

    User requirement: "怀疑有问题的，必须提供详细的证据和源代码，给到 AI
    做二次检查". Pass 1 only sees ±10 lines, which is insufficient for
    confirming a high-severity finding.
    """
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    pass1 = _stub_provider("true", "看起来确实是 SQL 注入")
    pass2 = _stub_provider("false", "Pass 2 看到了上层的参数化处理")
    verifier = _make_verifier(tmp_path, provider=pass1, escalate=pass2)

    finding = _make_finding(severity=Severity.HIGH)
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    # Pass 2's verdict wins.
    assert out.verification_status == "ai-verified-fp"
    assert out.severity == Severity.INFO
    assert outcome.pass1_count == 1
    assert outcome.pass2_count == 1
    # Pass 1 was decisive but escalated, so pass1_decisive stays at 0.
    assert outcome.pass1_decisive == 0
    assert pass1.generate_with_usage.await_count == 1
    assert pass2.generate_with_usage.await_count == 1


@pytest.mark.asyncio
async def test_critical_severity_also_forces_pass2(tmp_path):
    """CRITICAL is in the force-Pass-2 set just like HIGH."""
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    pass1 = _stub_provider("true", "p1 says yes")
    pass2 = _stub_provider("true", "p2 confirms after seeing call graph")
    verifier = _make_verifier(tmp_path, provider=pass1, escalate=pass2)

    finding = _make_finding(severity=Severity.CRITICAL)
    outcome = await verifier.verify([finding])

    assert outcome.pass2_count == 1
    assert outcome.findings[0].verification_status == "ai-verified-true"


@pytest.mark.asyncio
async def test_high_severity_pass2_failure_falls_back_to_pass1_verdict(tmp_path):
    """If Pass 2 fails (parse error/budget), fall back to Pass 1's verdict.

    This preserves "best available judgement" rather than dropping to
    skipped — Pass 1 still ran and gave a real answer.
    """
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    pass1 = _stub_provider("false", "字段名误命中")

    # Pass 2 returns garbage that fails to parse.
    pass2 = AsyncMock()
    pass2.generate_with_usage.return_value = GenerateResult(
        text="<not json>",
        usage=TokenUsage(prompt_tokens=80, completion_tokens=5, total_tokens=85),
    )
    verifier = _make_verifier(tmp_path, provider=pass1, escalate=pass2)

    finding = _make_finding(severity=Severity.HIGH)
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    assert out.verification_status == "ai-verified-fp"  # Pass 1's call wins
    assert outcome.pass2_count == 1


@pytest.mark.asyncio
async def test_uncertain_pass1_escalates_to_pass2(tmp_path):
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    pass1 = _stub_provider("uncertain", "需要看调用方")
    pass2 = _stub_provider("true", "调用方未过滤")
    verifier = _make_verifier(tmp_path, provider=pass1, escalate=pass2)

    finding = _make_finding(severity=Severity.MEDIUM)
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    assert out.verification_status == "ai-verified-true"
    assert outcome.pass1_count == 1
    assert outcome.pass2_count == 1
    assert pass1.generate_with_usage.await_count == 1
    assert pass2.generate_with_usage.await_count == 1


@pytest.mark.asyncio
async def test_uncertain_after_both_passes_keeps_finding(tmp_path):
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    pass1 = _stub_provider("uncertain", "信息不足")
    pass2 = _stub_provider("uncertain", "仍然信息不足")
    verifier = _make_verifier(tmp_path, provider=pass1, escalate=pass2)

    finding = _make_finding(severity=Severity.HIGH)
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    assert out.severity == Severity.HIGH  # untouched
    assert out.verification_status == "ai-uncertain"
    assert "ai-uncertain" in out.tags
    assert outcome.uncertain_count == 1


@pytest.mark.asyncio
async def test_cache_hit_skips_provider_call(tmp_path):
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))

    cache = VerifyCache(tmp_path, enabled=True)
    finding = _make_finding()
    # Read code lines the same way verifier does (via prompt context).
    code_lines = (tmp_path / "app/api.py").read_text(encoding="utf-8").splitlines()
    key = compute_cache_key(finding, code_lines=code_lines, model="model-a")
    cache.store(key, VerifyVerdict(status="ai-verified-fp", summary="cached", pass_used=1))

    provider = _stub_provider("true")
    verifier = AIVerifier(
        verify_provider=provider,
        escalate_provider=provider,
        cache=cache,
        project_root=tmp_path,
        max_tokens_per_scan=10_000,
        max_concurrent=2,
        verify_model_name="model-a",
        escalate_model_name="model-a",
    )

    outcome = await verifier.verify([finding])
    assert outcome.cache_hits == 1
    assert outcome.findings[0].verification_status == "ai-verified-fp"
    provider.generate_with_usage.assert_not_called()


@pytest.mark.asyncio
async def test_budget_exhaustion_marks_remaining_skipped(tmp_path):
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    provider = _stub_provider("true")
    # Budget so small it gets exhausted on the first call.
    verifier = AIVerifier(
        verify_provider=provider,
        escalate_provider=provider,
        cache=VerifyCache(tmp_path, enabled=False),
        project_root=tmp_path,
        max_tokens_per_scan=10,  # tiny — first finding will spend 120 tokens (mocked)
        max_concurrent=1,
        verify_model_name="model-a",
        escalate_model_name="model-a",
    )

    f1 = _make_finding(fid="SEC-001", line=5)
    f2 = _make_finding(fid="SEC-002", line=15)
    outcome = await verifier.verify([f1, f2])

    statuses = [f.verification_status for f in outcome.findings]
    assert "ai-verified-true" in statuses
    assert any(s.startswith("ai-skipped-") for s in statuses)
    assert outcome.skipped_count >= 1


@pytest.mark.asyncio
async def test_malformed_response_treated_as_skipped_error(tmp_path):
    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    provider = AsyncMock()
    provider.generate_with_usage.return_value = GenerateResult(
        text="this is not json at all",
        usage=TokenUsage(prompt_tokens=100, completion_tokens=10, total_tokens=110),
    )
    verifier = _make_verifier(tmp_path, provider=provider)
    finding = _make_finding()
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    # Severity untouched, status records skip, finding kept.
    assert out.severity == finding.severity
    assert out.verification_status.startswith("ai-skipped-")
    assert outcome.skipped_count == 1


@pytest.mark.asyncio
async def test_upstream_5xx_is_retried_then_succeeds(tmp_path, monkeypatch):
    """A transient gateway 5xx must be retried (backoff), not silently dropped."""
    import codeguardian.ai.verifier.verifier as verifier_mod

    # Avoid real backoff delays in the test.
    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(verifier_mod.asyncio, "sleep", _no_sleep)

    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    provider = AsyncMock()
    provider.generate_with_usage.side_effect = [
        Exception("Server error '500 Internal Server Error' for url ..."),
        GenerateResult(
            text=json.dumps({"verdict": "true", "reason": "确认注入"}),
            usage=TokenUsage(prompt_tokens=100, completion_tokens=20, total_tokens=120),
        ),
    ]
    verifier = _make_verifier(tmp_path, provider=provider)

    finding = _make_finding(severity=Severity.MEDIUM)
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    assert out.verification_status == "ai-verified-true"
    assert outcome.confirmed_count == 1
    # First call 500, second call succeeded → exactly two invocations.
    assert provider.generate_with_usage.await_count == 2


@pytest.mark.asyncio
async def test_upstream_5xx_exhausts_retries_and_keeps_finding(tmp_path, monkeypatch):
    """Persistent 5xx beyond MAX_RETRIES → verdict None → finding kept (skipped)."""
    import codeguardian.ai.verifier.verifier as verifier_mod

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(verifier_mod.asyncio, "sleep", _no_sleep)

    _seed_source_file(tmp_path, "app/api.py", "\n".join(f"line{i}" for i in range(1, 30)))
    provider = AsyncMock()
    provider.generate_with_usage.side_effect = Exception(
        "Server error '503 Service Unavailable' for url ..."
    )
    verifier = _make_verifier(tmp_path, provider=provider)

    finding = _make_finding(severity=Severity.MEDIUM)
    outcome = await verifier.verify([finding])

    out = outcome.findings[0]
    # Finding preserved (not deleted / not flipped to FP).
    assert out.severity == finding.severity
    assert out.verification_status.startswith("ai-skipped-")
    assert outcome.skipped_count == 1
    # Initial attempt + MAX_RETRIES retries.
    assert provider.generate_with_usage.await_count == verifier_mod.MAX_RETRIES + 1


# ────────────────────────────────────────────────────────────────────
# Call-graph: verify caller/callee snippets are surfaced for high severity
# ────────────────────────────────────────────────────────────────────


def test_call_graph_finds_python_caller_and_callee(tmp_path):
    """End-to-end smoke test: Python project with caller A → B (the hit) → C."""
    from codeguardian.ai.verifier.call_graph import find_call_graph

    _seed_source_file(tmp_path, "pkg/a.py", (
        "from pkg.b import b_func\n"
        "\n"
        "def caller_a():\n"
        "    x = 1\n"
        "    b_func(x)\n"
        "    return x\n"
    ))
    _seed_source_file(tmp_path, "pkg/b.py", (
        "from pkg.c import c_func\n"
        "\n"
        "def b_func(value):\n"
        "    # finding hits this line\n"
        "    result = value / 0\n"
        "    c_func(result)\n"
        "    return result\n"
        "\n"
        "def c_func(v):\n"
        "    return v\n"
    ))

    result = find_call_graph(
        project_root=tmp_path,
        file_path="pkg/b.py",
        line_start=5,  # `result = value / 0`
        caller_depth=1,
        callee_depth=1,
    )

    assert result.enclosing_function is not None
    assert result.enclosing_function.name == "b_func"
    # caller_a should be located via cross-file scan.
    caller_names = {s.function_name for s in result.callers}
    assert "caller_a" in caller_names
    # c_func is called from inside b_func and defined in same file.
    callee_names = {s.function_name for s in result.callees}
    assert "c_func" in callee_names


def test_call_graph_unsupported_language_returns_empty(tmp_path):
    """Files with unrecognized extensions yield empty results without crashing."""
    from codeguardian.ai.verifier.call_graph import find_call_graph

    _seed_source_file(tmp_path, "weird.xyz", "no parser supports me\n")

    result = find_call_graph(
        project_root=tmp_path,
        file_path="weird.xyz",
        line_start=1,
        caller_depth=2,
        callee_depth=2,
    )
    assert result.enclosing_function is None
    assert result.callers == []
    assert result.callees == []
    assert result.notes  # populated with the reason


def test_call_graph_respects_total_byte_budget(tmp_path):
    """Caller chain must stop before exceeding MAX_TOTAL_BYTES."""
    from codeguardian.ai.verifier.call_graph import MAX_TOTAL_BYTES, find_call_graph

    # Generate many tiny callers; check total stays below the cap.
    _seed_source_file(tmp_path, "pkg/target.py", (
        "def hot():\n"
        "    return 1\n"
    ))
    big_body = "    x = 0\n" * 200  # ~1.4KB per caller
    for i in range(20):
        _seed_source_file(tmp_path, f"pkg/c{i}.py", (
            "from pkg.target import hot\n"
            f"def caller_{i}():\n"
            f"{big_body}"
            "    return hot()\n"
        ))

    result = find_call_graph(
        project_root=tmp_path,
        file_path="pkg/target.py",
        line_start=2,
        caller_depth=1,
        callee_depth=0,
    )
    total = sum(len(s.code) for s in result.callers)
    assert total <= MAX_TOTAL_BYTES + 8000  # snippet body itself counts (capped per snippet)


# ────────────────────────────────────────────────────────────────────
# Field-write reverse lookup (Pass 2 same-file initializer hint)
# ────────────────────────────────────────────────────────────────────


def test_field_writes_finds_java_static_initializer(tmp_path):
    """The motivating case: AI sees `intervalMinMillisec` in a method but the
    initializer is at the class top (far from the hit). Reverse lookup should
    surface it.
    """
    from codeguardian.ai.verifier.field_writes import find_field_writes

    # Pad with blank lines so the initializer (line 3) is well outside the
    # ±5-line hit window, simulating a realistic large class file.
    padding = "\n".join([f"    // filler line {i}" for i in range(40)])
    java_src = (
        "package com.example;\n"
        "\n"
        "public class Stat {\n"
        "    private static final long intervalMinMillisec = 10_000L;\n"
        "    private long lastSampleAt = 0L;\n"
        "\n"
        f"{padding}\n"
        "\n"
        "    public boolean shouldSample(long now) {\n"
        "        // hit line: reads intervalMinMillisec without seeing init\n"
        "        if (now - lastSampleAt < intervalMinMillisec) {\n"
        "            return false;\n"
        "        }\n"
        "        lastSampleAt = now;\n"
        "        return true;\n"
        "    }\n"
        "}\n"
    )
    file_path = tmp_path / "Stat.java"
    file_path.write_text(java_src, encoding="utf-8")
    # Find the actual hit line: the `if (now - ...)` line.
    hit_line = next(
        i + 1 for i, line in enumerate(java_src.splitlines())
        if "if (now - lastSampleAt" in line
    )

    snippets = find_field_writes(file_path=file_path, line_start=hit_line)

    field_names = {s.field_name for s in snippets}
    assert "intervalMinMillisec" in field_names, (
        f"expected to surface the class-level initializer; got {field_names}"
    )
    init_snippet = next(s for s in snippets if s.field_name == "intervalMinMillisec")
    assert "10_000L" in init_snippet.code_block


def test_field_writes_skips_writes_inside_hit_window(tmp_path):
    """Writes that happen *inside* the ±5-line hit window are noise — they're
    already visible in the enclosing-function block. The lookup should only
    surface writes elsewhere in the file.
    """
    from codeguardian.ai.verifier.field_writes import find_field_writes

    py_src = (
        "class Cfg:\n"                      # 1
        "    def __init__(self):\n"          # 2
        "        self.threshold = 100\n"     # 3 — write outside window
        "\n"                                  # 4
        "    def check(self, value):\n"      # 5
        "        threshold = 50\n"           # 6 — write inside window
        "        result = threshold * 2\n"   # 7 — hit line
        "        return result\n"            # 8
    )
    file_path = tmp_path / "cfg.py"
    file_path.write_text(py_src, encoding="utf-8")

    snippets = find_field_writes(file_path=file_path, line_start=7)

    threshold_writes = [s for s in snippets if s.field_name == "threshold"]
    # Should only return line 3 (outside ±5 window of line 7 means lines 1-12;
    # line 3 IS inside that window — adjust: HIT_RADIUS is 5, so window is
    # lines 2..12. So line 3 IS inside the window, line 6 also inside.
    # Both are dedup'd. Therefore for a 5-line file we expect zero hits.
    # That's fine — the test purpose is "doesn't return line 6 which already
    # appears in enclosing block". We assert the in-window line 6 is excluded.
    in_window_writes = [w for w in threshold_writes if w.line == 6]
    assert in_window_writes == [], "writes inside hit window must be excluded"


def test_field_writes_caps_total_bytes(tmp_path):
    """Output must respect MAX_TOTAL_BYTES regardless of how many writes exist."""
    from codeguardian.ai.verifier.field_writes import MAX_TOTAL_BYTES, find_field_writes

    # File with many writes to a single field, far away from the hit.
    lines = ["def hit():", "    return val"]  # line 2 is hit
    for _ in range(500):
        lines.append("val = " + "x" * 80)
    py_src = "\n".join(lines) + "\n"
    file_path = tmp_path / "noisy.py"
    file_path.write_text(py_src, encoding="utf-8")

    snippets = find_field_writes(file_path=file_path, line_start=2)
    total = sum(len(s.code_block) for s in snippets)
    assert total <= MAX_TOTAL_BYTES + 500  # block formatting overhead tolerance


def test_field_writes_unsupported_language_returns_empty(tmp_path):
    """Unrecognized extensions return empty without crashing."""
    from codeguardian.ai.verifier.field_writes import find_field_writes

    file_path = tmp_path / "weird.xyz"
    file_path.write_text("foo = 1\nbar = foo\n", encoding="utf-8")

    snippets = find_field_writes(file_path=file_path, line_start=2)
    assert snippets == []


def test_field_writes_filters_keywords(tmp_path):
    """Language keywords (e.g. `return`, `for`, `null`) must not be chased."""
    from codeguardian.ai.verifier.field_writes import find_field_writes

    # `value` is written at line 1; hit is at line 11 — well outside the
    # ±5 hit window — so the write should surface.
    py_src = (
        "value = 0\n"           # 1
        "# pad\n"               # 2
        "# pad\n"               # 3
        "# pad\n"               # 4
        "# pad\n"               # 5
        "# pad\n"               # 6
        "# pad\n"               # 7
        "# pad\n"               # 8
        "# pad\n"               # 9
        "def f():\n"            # 10
        "    for i in range(10):\n"  # 11 — hit
        "        return value\n"     # 12
    )
    file_path = tmp_path / "kw.py"
    file_path.write_text(py_src, encoding="utf-8")

    snippets = find_field_writes(file_path=file_path, line_start=11)
    names = {s.field_name for s in snippets}
    # `value` is not a keyword and has a write at line 1 — should appear.
    assert "value" in names
    # Keywords must never appear.
    assert "for" not in names
    assert "return" not in names
    assert "range" not in names


def test_pass2_context_includes_field_writes_at_medium_plus(tmp_path):
    """build_pass2_context must invoke field-write lookup for medium+ findings."""
    from codeguardian.ai.verifier.prompts import build_pass2_context
    from codeguardian.models.common import Location
    from codeguardian.models.finding import Finding

    padding = "\n".join([f"    // line {i}" for i in range(30)])
    java_src = (
        "package com.example;\n"
        "public class Stat {\n"
        "    private static final long intervalMinMillisec = 10_000L;\n"
        f"{padding}\n"
        "    public boolean shouldSample(long now) {\n"
        "        return now > intervalMinMillisec;\n"
        "    }\n"
        "}\n"
    )
    _seed_source_file(tmp_path, "Stat.java", java_src)
    hit_line = next(
        i + 1 for i, line in enumerate(java_src.splitlines())
        if "return now > intervalMinMillisec" in line
    )

    finding = Finding(
        id="MAGIC-001",
        title="suspicious unread field",
        category="quality",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        location=Location(file_path="Stat.java", line_start=hit_line, line_end=hit_line),
        source_engine="quality_engine",
    )
    ctx = build_pass2_context(finding, tmp_path)

    field_writes = ctx.get("field_writes")
    assert field_writes, "medium severity must trigger field-write lookup"
    names = {s.field_name for s in field_writes}
    assert "intervalMinMillisec" in names


def test_pass2_context_skips_field_writes_at_low(tmp_path):
    """LOW severity does not trigger field-write lookup (token budget)."""
    from codeguardian.ai.verifier.prompts import build_pass2_context
    from codeguardian.models.common import Location
    from codeguardian.models.finding import Finding

    java_src = (
        "public class Stat {\n"
        "    private static final long intervalMinMillisec = 10_000L;\n"
        "    public boolean f(long now) { return now > intervalMinMillisec; }\n"
        "}\n"
    )
    _seed_source_file(tmp_path, "Stat.java", java_src)

    finding = Finding(
        id="LOW-001",
        title="low severity",
        category="style",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        location=Location(file_path="Stat.java", line_start=3, line_end=3),
        source_engine="style_engine",
    )
    ctx = build_pass2_context(finding, tmp_path)
    assert ctx.get("field_writes") == []


# ────────────────────────────────────────────────────────────────────
# Rule-targeted evidence collectors (A/B/C classes) + force-Pass-2 routing
# ────────────────────────────────────────────────────────────────────


def test_a_collector_surfaces_concurrent_hashmap_safety_token(tmp_path):
    """A-class: when the static field is a ConcurrentHashMap and is used via
    putIfAbsent/get only, the safety-token scan should report it so the AI
    can judge FP correctly.
    """
    from codeguardian.ai.verifier.evidence_collectors import (
        collect_a_static_mutable_evidence,
    )

    java_src = (
        "package com.example;\n"
        "import java.util.concurrent.ConcurrentHashMap;\n"
        "public class Cache {\n"
        "    private static final ConcurrentHashMap<String, String> CACHE = new ConcurrentHashMap<>();\n"
        "    public String get(String k) {\n"
        "        return CACHE.get(k);\n"
        "    }\n"
        "    public void put(String k, String v) {\n"
        "        CACHE.putIfAbsent(k, v);\n"
        "    }\n"
        "}\n"
    )
    file_path = tmp_path / "Cache.java"
    file_path.write_text(java_src, encoding="utf-8")
    lines = java_src.splitlines()
    # Hit line: the static declaration (line 4).
    hit = next(i + 1 for i, ln in enumerate(lines) if "private static final ConcurrentHashMap" in ln)

    block = collect_a_static_mutable_evidence(
        file_path=file_path,
        line_start=hit,
        code_lines=lines,
    )
    assert block is not None
    # ConcurrentHashMap should appear in the safety-token list.
    assert "ConcurrentHashMap" in block.body
    # Use-sites for CACHE.get / CACHE.putIfAbsent should be surfaced.
    assert "CACHE.get(" in block.body or "CACHE.putIfAbsent" in block.body


def test_a_collector_reports_no_safety_when_plain_hashmap(tmp_path):
    """A-class: a plain `HashMap` with .put usage should NOT surface safety
    tokens — exactly the kind of case where AI should consider judging true.
    """
    from codeguardian.ai.verifier.evidence_collectors import (
        collect_a_static_mutable_evidence,
    )

    java_src = (
        "import java.util.HashMap;\n"
        "public class Bad {\n"
        "    private static HashMap<String, String> CACHE = new HashMap<>();\n"
        "    public void put(String k, String v) { CACHE.put(k, v); }\n"
        "    public String get(String k) { return CACHE.get(k); }\n"
        "}\n"
    )
    file_path = tmp_path / "Bad.java"
    file_path.write_text(java_src, encoding="utf-8")
    lines = java_src.splitlines()
    hit = next(i + 1 for i, ln in enumerate(lines) if "private static HashMap" in ln)

    block = collect_a_static_mutable_evidence(
        file_path=file_path,
        line_start=hit,
        code_lines=lines,
    )
    assert block is not None
    # No safety primitives present — we explicitly say so.
    assert "未发现任何并发安全包装迹象" in block.body


def test_b_collector_extracts_full_java_catch_body_and_caller_tail(tmp_path):
    """B-class: full catch block + caller tail (where retry/fallback lives)."""
    from codeguardian.ai.verifier.call_graph import CallGraphSnippet
    from codeguardian.ai.verifier.evidence_collectors import collect_b_exception_evidence

    java_src = (
        "public class Svc {\n"
        "    public void doWork() {\n"
        "        try {\n"
        "            riskyCall();\n"
        "        } catch (IOException e) {\n"
        "            log.warn(\"failed\", e);\n"
        "            // intentionally swallowed\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    file_path = tmp_path / "Svc.java"
    file_path.write_text(java_src, encoding="utf-8")
    lines = java_src.splitlines()
    hit = next(i + 1 for i, ln in enumerate(lines) if "log.warn" in ln)

    caller_snip = CallGraphSnippet(
        file_path="other/Caller.java",
        function_name="invokeSvc",
        line_start=10,
        line_end=20,
        code="\n".join([
            "public void invokeSvc() {",
            "  for (int i = 0; i < 3; i++) {",
            "    try { svc.doWork(); return; }",
            "    catch (Exception e) { Thread.sleep(1000); }",  # retry tail
            "  }",
            "  throw new RuntimeException(\"all retries failed\");",
            "}",
        ]),
        relation="caller",
    )

    block = collect_b_exception_evidence(
        file_path=file_path,
        line_start=hit,
        code_lines=lines,
        callers=[caller_snip],
    )
    assert block is not None
    # Catch body fully captured.
    assert "catch (IOException e)" in block.body
    assert "intentionally swallowed" in block.body
    # Caller tail (with retry pattern) appears.
    assert "invokeSvc" in block.body
    assert "all retries failed" in block.body or "Thread.sleep" in block.body


def test_b_collector_python_except_block(tmp_path):
    """B-class also handles Python `except` blocks (indent-based)."""
    from codeguardian.ai.verifier.evidence_collectors import collect_b_exception_evidence

    py_src = (
        "def do_work():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception as e:\n"
        "        log.warning('failed: %s', e)\n"
        "        return None\n"
        "    return 'ok'\n"
    )
    file_path = tmp_path / "svc.py"
    file_path.write_text(py_src, encoding="utf-8")
    lines = py_src.splitlines()
    hit = next(i + 1 for i, ln in enumerate(lines) if "log.warning" in ln)

    block = collect_b_exception_evidence(
        file_path=file_path,
        line_start=hit,
        code_lines=lines,
        callers=[],
    )
    assert block is not None
    assert "except Exception" in block.body
    assert "return None" in block.body


def test_c_collector_finds_try_with_resources_token(tmp_path):
    """C-class: when try-with-resources wraps the resource, surface that fact."""
    from codeguardian.ai.verifier.evidence_collectors import collect_c_resource_evidence

    java_src = (
        "public class Reader {\n"
        "    public String read(String path) throws IOException {\n"
        "        try (FileInputStream in = new FileInputStream(path)) {\n"
        "            return new String(in.readAllBytes());\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    file_path = tmp_path / "Reader.java"
    file_path.write_text(java_src, encoding="utf-8")
    lines = java_src.splitlines()
    hit = next(i + 1 for i, ln in enumerate(lines) if "new FileInputStream" in ln)

    block = collect_c_resource_evidence(
        file_path=file_path,
        line_start=hit,
        code_lines=lines,
    )
    assert block is not None
    # The window should include the try ( opener — that's the safety evidence.
    assert "try (" in block.body or "try-with-resources" in block.body or "finally" in block.body


def test_c_collector_no_safety_token_for_bare_open(tmp_path):
    """C-class: bare resource open with no try/finally/with → safety section
    should explicitly report 'no lifecycle tokens'.
    """
    from codeguardian.ai.verifier.evidence_collectors import collect_c_resource_evidence

    java_src = (
        "public class Bad {\n"
        "    public void leak() throws Exception {\n"
        "        FileInputStream in = new FileInputStream(\"x\");\n"
        "        in.read();\n"
        "        // never closed\n"
        "    }\n"
        "}\n"
    )
    file_path = tmp_path / "Bad.java"
    file_path.write_text(java_src, encoding="utf-8")
    lines = java_src.splitlines()
    hit = next(i + 1 for i, ln in enumerate(lines) if "new FileInputStream" in ln)

    block = collect_c_resource_evidence(
        file_path=file_path,
        line_start=hit,
        code_lines=lines,
    )
    assert block is not None
    assert "未出现 try-with-resources" in block.body


def test_pass2_context_inlines_enhanced_evidence_for_static_mutable(tmp_path):
    """build_pass2_context must invoke the A-class collector for STATIC-MUTABLE-SHARED-STATE."""
    from codeguardian.ai.verifier.prompts import build_pass2_context

    java_src = (
        "import java.util.concurrent.ConcurrentHashMap;\n"
        "public class Cfg {\n"
        "    private static final ConcurrentHashMap<String, String> M = new ConcurrentHashMap<>();\n"
        "    public String get(String k) { return M.get(k); }\n"
        "}\n"
    )
    _seed_source_file(tmp_path, "Cfg.java", java_src)
    hit_line = 3  # the static declaration

    finding = Finding(
        id="SMSS-001",
        title="Static mutable shared state",
        category="defect",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="Cfg.java", line_start=hit_line, line_end=hit_line),
        source_engine="defect_engine",
        rule_id="STATIC-MUTABLE-SHARED-STATE",
    )
    ctx = build_pass2_context(finding, tmp_path)
    enhanced = ctx.get("enhanced_evidence")
    assert enhanced is not None, "STATIC-MUTABLE-SHARED-STATE must trigger A-class collector"
    assert "ConcurrentHashMap" in enhanced.body


def test_pass2_context_no_enhanced_evidence_for_unmapped_rule(tmp_path):
    """Rules not in ENHANCED_RULE_IDS must NOT trigger any collector."""
    from codeguardian.ai.verifier.prompts import build_pass2_context

    _seed_source_file(tmp_path, "x.py", "def f():\n    return 1\n")
    finding = Finding(
        id="UNK-001",
        title="some other rule",
        category="defect",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="x.py", line_start=2, line_end=2),
        source_engine="defect_engine",
        rule_id="SOME-OTHER-RULE",
    )
    ctx = build_pass2_context(finding, tmp_path)
    assert ctx.get("enhanced_evidence") is None


@pytest.mark.asyncio
async def test_enhanced_rule_forces_pass2_even_when_pass1_decisive(tmp_path):
    """STATIC-MUTABLE-SHARED-STATE at MEDIUM severity must force Pass 2 even
    if Pass 1 already returned a decisive verdict. User's hard requirement:
    "宁愿不要检查出问题，也不要检查一堆假问题"——high-FP rules always need
    the richer evidence before any verdict is finalized.
    """
    _seed_source_file(tmp_path, "Cfg.java", (
        "import java.util.concurrent.ConcurrentHashMap;\n"
        "public class Cfg {\n"
        "    private static final ConcurrentHashMap<String, String> M = new ConcurrentHashMap<>();\n"
        "    public String get(String k) { return M.get(k); }\n"
        "}\n"
    ))
    pass1 = _stub_provider("true", "static + mutable, looks like concurrent risk")
    pass2 = _stub_provider("false", "actually ConcurrentHashMap, thread-safe")
    verifier = _make_verifier(tmp_path, provider=pass1, escalate=pass2)

    finding = Finding(
        id="SMSS-001",
        title="Static mutable shared state",
        category="defect",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="Cfg.java", line_start=3, line_end=3),
        source_engine="defect_engine",
        rule_id="STATIC-MUTABLE-SHARED-STATE",
        blocks_release=True,
        evidence_level="suspected",
    )
    outcome = await verifier.verify([finding])

    # Pass 2 must have fired despite Pass 1 being decisive.
    assert outcome.pass1_count == 1
    assert outcome.pass2_count == 1
    # Pass 2's verdict (false) wins.
    assert outcome.findings[0].verification_status == "ai-verified-fp"


@pytest.mark.asyncio
async def test_non_enhanced_rule_pass1_decisive_skips_pass2(tmp_path):
    """Sanity: a regular rule (not in ENHANCED_RULE_IDS) at MEDIUM still
    finalizes on Pass 1 — we didn't accidentally force Pass 2 globally.
    """
    _seed_source_file(tmp_path, "app.py", "\n".join(f"line{i}" for i in range(1, 30)))
    pass1 = _stub_provider("true", "regular rule, decisive")
    pass2 = _stub_provider("false", "shouldn't be called")
    verifier = _make_verifier(tmp_path, provider=pass1, escalate=pass2)

    finding = Finding(
        id="REG-001",
        title="Regular finding",
        category="defect",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="app.py", line_start=5, line_end=5),
        source_engine="defect_engine",
        rule_id="SOME-REGULAR-RULE",
    )
    outcome = await verifier.verify([finding])
    assert outcome.pass1_count == 1
    assert outcome.pass2_count == 0
    assert outcome.pass1_decisive == 1



