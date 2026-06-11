"""Tests for the Semgrep integration (adapter, engine, orchestrator glue)."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from codeguardian.config.schema import AppConfig, RulesConfig
from codeguardian.core.context import ScanContext
from codeguardian.core.orchestrator import Orchestrator
from codeguardian.engines.semgrep_adapter import filter_hits, parse_semgrep_results
from codeguardian.engines.semgrep_engine import SemgrepEngine
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding


# ─────────────────────────── V1: adapter ───────────────────────────


def _sample_payload() -> dict:
    return {
        "results": [
            {
                "check_id": "python.lang.security.use-defused-xml.use-defused-xml",
                "path": "src/app.py",
                "start": {"line": 14, "col": 1},
                "end": {"line": 14, "col": 40},
                "extra": {
                    "message": "Use defusedxml instead of xml",
                    "severity": "WARNING",
                    "metadata": {
                        "category": "security",
                        "cwe": ["CWE-611: Improper Restriction of XML External Entity Reference"],
                        "owasp": ["A05:2017 - Broken Access Control"],
                        "technology": ["python"],
                        "references": ["https://docs.python.org/3/library/xml.html"],
                        "confidence": "HIGH",
                    },
                },
            }
        ],
        "errors": [],
    }


def test_parse_semgrep_results_basic() -> None:
    payload = _sample_payload()
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        hits = parse_semgrep_results(payload, root)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule.rule_id == "python.lang.security.use-defused-xml.use-defused-xml"
    assert hit.rule.category == "security"
    assert hit.rule.severity == Severity.MEDIUM  # WARNING → MEDIUM
    assert hit.rule.confidence == Confidence.HIGH
    assert hit.line_start == 14
    assert hit.file_path == "src/app.py"
    assert "CWE-611" in hit.rule.cwe_ids
    assert hit.language == "python"


def test_parse_semgrep_results_empty() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        assert parse_semgrep_results({"results": []}, root) == []
        assert parse_semgrep_results({}, root) == []


def test_filter_hits_respects_min_severity() -> None:
    payload = _sample_payload()
    with TemporaryDirectory() as tmpdir:
        hits = parse_semgrep_results(payload, Path(tmpdir))
    # default = keep
    assert filter_hits(hits, RulesConfig()) == hits
    # min_severity HIGH drops the MEDIUM hit
    assert filter_hits(hits, RulesConfig(min_severity=Severity.HIGH)) == []


def test_filter_hits_respects_disabled_list() -> None:
    payload = _sample_payload()
    with TemporaryDirectory() as tmpdir:
        hits = parse_semgrep_results(payload, Path(tmpdir))
    disabled_rules = RulesConfig(disabled=[hits[0].rule.rule_id])
    assert filter_hits(hits, disabled_rules) == []


# ───────────── V5: Windows UTF-8 env is forced in subprocess ─────────────


async def test_semgrep_subprocess_forces_pythonutf8(monkeypatch) -> None:
    """Engine must inject PYTHONUTF8=1 to avoid the GBK crash on Windows."""
    captured = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b'{"results": [], "errors": []}', b"")

        def kill(self) -> None:
            pass

        async def wait(self) -> int:
            return 0

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["cmd"] = list(args)
        captured["env"] = kwargs.get("env", {})
        return _FakeProc()

    cfg = AppConfig()
    cfg.semgrep.enabled = True
    with TemporaryDirectory() as tmpdir:
        ctx = ScanContext(project_root=tmpdir, config=cfg)
        with (
            patch(
                "codeguardian.engines.semgrep_engine.shutil.which",
                return_value="/fake/semgrep",
            ),
            patch(
                "codeguardian.engines.semgrep_engine.asyncio.create_subprocess_exec",
                side_effect=fake_create_subprocess_exec,
            ),
        ):
            result = await SemgrepEngine().analyze(ctx)

    assert result.findings == []
    assert captured["env"].get("PYTHONUTF8") == "1"
    assert "--json" in captured["cmd"]
    # stdout mode: no --output flag (avoids GBK file-write bug)
    assert "--output" not in captured["cmd"]


async def test_semgrep_graceful_skip_when_binary_missing() -> None:
    cfg = AppConfig()
    cfg.semgrep.enabled = True
    with TemporaryDirectory() as tmpdir:
        ctx = ScanContext(project_root=tmpdir, config=cfg)
        with patch(
            "codeguardian.engines.semgrep_engine.shutil.which",
            return_value=None,
        ):
            result = await SemgrepEngine().analyze(ctx)
    assert result.findings == []
    assert any("not found" in w.lower() for w in result.warnings)


async def test_semgrep_disabled_returns_empty_result_without_subprocess() -> None:
    cfg = AppConfig()  # semgrep.enabled defaults to False
    with TemporaryDirectory() as tmpdir:
        ctx = ScanContext(project_root=tmpdir, config=cfg)
        with patch(
            "codeguardian.engines.semgrep_engine.asyncio.create_subprocess_exec",
        ) as mock_exec:
            result = await SemgrepEngine().analyze(ctx)
            mock_exec.assert_not_called()
    assert result.findings == []
    assert result.engine_name == "semgrep"


async def test_semgrep_engine_end_to_end_with_fake_output() -> None:
    cfg = AppConfig()
    cfg.semgrep.enabled = True
    payload_bytes = json.dumps(_sample_payload()).encode("utf-8")

    class _FakeProc:
        returncode = 1  # 1 = findings reported; NOT an error

        async def communicate(self) -> tuple[bytes, bytes]:
            return payload_bytes, b""

        def kill(self) -> None:
            pass

        async def wait(self) -> int:
            return 1

    async def fake_exec(*_args, **_kwargs):
        return _FakeProc()

    with TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "src" / "app.py"
        target.parent.mkdir(parents=True)
        target.write_text("import xml.etree.ElementTree as ET\n" * 20, encoding="utf-8")

        ctx = ScanContext(project_root=tmpdir, config=cfg)
        with (
            patch(
                "codeguardian.engines.semgrep_engine.shutil.which",
                return_value="/fake/semgrep",
            ),
            patch(
                "codeguardian.engines.semgrep_engine.asyncio.create_subprocess_exec",
                side_effect=fake_exec,
            ),
        ):
            result = await SemgrepEngine().analyze(ctx)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.source_engine == "semgrep"
    assert finding.id.startswith("SGR-")
    assert finding.category == "security"
    assert "CWE-611" in finding.cwe_ids


# ───────────── V2: cross-engine de-duplication ─────────────


def _mk_finding(
    fid: str,
    *,
    engine: str,
    rule: str,
    line: int,
    cwe: list[str],
    evidence_level: str = "suspected",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=fid,
        title=f"t-{fid}",
        category="security",
        severity=severity,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="src/a.py", line_start=line, line_end=line),
        source_engine=engine,
        rule_id=rule,
        cwe_ids=cwe,
        evidence_level=evidence_level,
    )


def test_dedupe_keeps_higher_evidence_rank() -> None:
    local = _mk_finding(
        "L-1", engine="security", rule="SQL-INJECTION-RISK", line=10,
        cwe=["CWE-89"], evidence_level="likely",
    )
    semgrep = _mk_finding(
        "S-1", engine="semgrep", rule="python.lang.security.sqli", line=11,
        cwe=["CWE-89"], evidence_level="suspected",
    )
    out = Orchestrator._dedupe_overlapping_findings([local, semgrep])
    # local has higher evidence rank → kept; semgrep dropped
    assert [f.id for f in out] == ["L-1"]


def test_dedupe_swaps_when_semgrep_has_stronger_evidence() -> None:
    local = _mk_finding(
        "L-2", engine="security", rule="XXE-RISK", line=14,
        cwe=["CWE-611"], evidence_level="suspected",
    )
    semgrep = _mk_finding(
        "S-2", engine="semgrep", rule="python.lang.security.xxe", line=14,
        cwe=["CWE-611"], evidence_level="likely",
    )
    out = Orchestrator._dedupe_overlapping_findings([local, semgrep])
    assert [f.id for f in out] == ["S-2"]


def test_dedupe_keeps_distinct_cwes() -> None:
    a = _mk_finding("A", engine="security", rule="R1", line=10, cwe=["CWE-89"])
    b = _mk_finding("B", engine="semgrep", rule="R2", line=11, cwe=["CWE-78"])
    out = Orchestrator._dedupe_overlapping_findings([a, b])
    assert {f.id for f in out} == {"A", "B"}


def test_dedupe_ignores_findings_without_cwe() -> None:
    a = _mk_finding("A", engine="security", rule="R1", line=10, cwe=[])
    b = _mk_finding("B", engine="semgrep", rule="R2", line=10, cwe=[])
    out = Orchestrator._dedupe_overlapping_findings([a, b])
    assert {f.id for f in out} == {"A", "B"}


# ───────────── V6: LocalValidator downgrades likely-FP Semgrep findings ─────────────


def test_local_validator_downgrades_likely_fp_semgrep_finding() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # A flagged line preceded by a sanitizer call — LocalValidator sees FP.
        src = root / "src" / "q.py"
        src.parent.mkdir(parents=True)
        src.write_text(
            "def handle(u):\n"
            "    safe = escape(u)\n"  # sanitizer in preceding lines
            "    cursor.execute(safe)\n",
            encoding="utf-8",
        )

        finding = _mk_finding(
            "S-FP",
            engine="semgrep",
            rule="python.lang.security.sqli",
            line=3,
            cwe=["CWE-89"],
            severity=Severity.CRITICAL,
            evidence_level="suspected",
        )
        finding.location = Location(
            file_path="src/q.py", line_start=3, line_end=3,
        )
        finding.blocks_release = True

        orch = Orchestrator(AppConfig())
        out = orch._apply_local_validator_to_engine(
            [finding], engine="semgrep", project_root=root,
        )
    assert len(out) == 1
    downgraded = out[0]
    assert downgraded.severity == Severity.HIGH  # CRITICAL → HIGH
    assert downgraded.blocks_release is False
    assert "local-validator-fp" in downgraded.tags
    assert downgraded.verification_status == "static-likely-fp"


def test_local_validator_leaves_non_semgrep_findings_untouched() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        finding = _mk_finding(
            "L-1",
            engine="security",
            rule="SQL-INJECTION-RISK",
            line=3,
            cwe=["CWE-89"],
            severity=Severity.CRITICAL,
        )
        orch = Orchestrator(AppConfig())
        out = orch._apply_local_validator_to_engine(
            [finding], engine="semgrep", project_root=root,
        )
    # source_engine != "semgrep" → pass through unchanged.
    assert out[0].severity == Severity.CRITICAL
    assert "local-validator-fp" not in out[0].tags


# ───────────────────── V7: loader binds [semgrep] section ─────────────────────


def test_toml_loader_binds_semgrep_section() -> None:
    """Regression: ``[semgrep]`` in codeguardian.toml must reach AppConfig.semgrep.

    Earlier versions of ``_merge_toml_into_config`` silently dropped the
    section because it was not whitelisted, making every user-supplied knob
    (including ``enabled = true``) a no-op.
    """
    from codeguardian.config.loader import load_app_config

    with TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "codeguardian.toml"
        cfg_path.write_text(
            '[semgrep]\n'
            'enabled = true\n'
            'jobs = 4\n'
            'config = ["p/python", "p/owasp-top-ten"]\n'
            'local_validate = false\n',
            encoding="utf-8",
        )
        cfg = load_app_config(str(cfg_path))

    assert cfg.semgrep.enabled is True
    assert cfg.semgrep.jobs == 4
    assert cfg.semgrep.config == ["p/python", "p/owasp-top-ten"]
    assert cfg.semgrep.local_validate is False
