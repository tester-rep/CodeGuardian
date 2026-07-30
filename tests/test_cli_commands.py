"""CLI command validation and smoke tests."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from codeguardian.cli.app import app
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.models.profile import ProjectProfile
from codeguardian.models.scan import DiffResult, ScanResult

runner = CliRunner()


def test_analyze_rejects_unknown_dimension() -> None:
    result = runner.invoke(app, ["analyze", "observability", "."])

    assert result.exit_code == 1
    assert "Invalid dimension" in result.stdout
    assert "performance" in result.stdout



def test_analyze_supports_performance_dimension(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["dimensions"] = request.dimensions
        captured["review_mode"] = request.review_mode
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.analyze.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["analyze", "performance", str(project)])

    assert result.exit_code == 0
    assert captured == {"dimensions": ["performance"], "review_mode": "standard"}
    assert "[PERFORMANCE]" in result.stdout





def test_scan_rejects_unsupported_report_format() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(root), "--report", "json,docx"])

    assert result.exit_code == 1
    assert "Unsupported report format" in result.stdout
    assert "terminal, json, html, sarif, pdf" in result.stdout


def test_scan_rejects_unsupported_dimension() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(root), "--dimensions", "observability"])

    assert result.exit_code == 1
    assert "Unsupported dimension" in result.stdout
    assert "performance" in result.stdout



def test_scan_supports_performance_dimension(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["dimensions"] = request.dimensions
        captured["review_mode"] = request.review_mode
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.scan.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(project), "--dimensions", "performance"])

    assert result.exit_code == 0
    assert captured == {"dimensions": ["performance"], "review_mode": "standard"}





def test_analyze_supports_architecture_dimension(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["dimensions"] = request.dimensions
        captured["review_mode"] = request.review_mode
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.analyze.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["analyze", "architecture", str(project)])

    assert result.exit_code == 0
    assert captured == {"dimensions": ["architecture"], "review_mode": "standard"}
    assert "[ARCHITECTURE]" in result.stdout


def test_scan_supports_all_dimensions(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["dimensions"] = request.dimensions
        captured["review_mode"] = request.review_mode
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.scan.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(project), "--dimensions", "all"])

    assert result.exit_code == 0
    assert captured["dimensions"] == ["all"]


def test_scan_uses_project_config_defaults_when_options_omitted() -> None:


    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")
        (project / "codeguardian.toml").write_text(
            "[scan]\n"
            "review_mode = \"ai_off\"\n\n"
            "[reports]\n"
            "formats = [\"json\"]\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["scan", str(project)])

        assert result.exit_code == 0
        assert (project / "reports" / "report.json").exists()
        assert "已生成报告" in result.stdout


def test_scan_passes_verify_generate_request(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["verify_mode"] = request.verify_mode
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.scan.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(project), "--verify", "generate"])

    assert result.exit_code == 0
    assert captured == {"verify_mode": "generate"}
    assert "验证模式" in result.stdout



def test_scan_passes_verify_syntax_request(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["verify_mode"] = request.verify_mode
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.scan.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(project), "--verify", "syntax"])

    assert result.exit_code == 0
    assert captured == {"verify_mode": "syntax"}
    assert "验证模式" in result.stdout



def test_scan_passes_verify_safe_request(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["verify_mode"] = request.verify_mode
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.scan.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(project), "--verify", "safe"])

    assert result.exit_code == 0
    assert captured == {"verify_mode": "safe"}
    assert "验证模式" in result.stdout



def test_scan_rejects_unsupported_verify_mode() -> None:

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(root), "--verify", "full"])

    assert result.exit_code == 1
    assert "Unsupported verification mode" in result.stdout



def test_scan_passes_incremental_request(monkeypatch) -> None:


    captured = {}

    async def fake_run_scan(_self, request):
        captured["incremental"] = request.incremental
        captured["since"] = request.since
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.scan.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(project), "--incremental", "--since", "HEAD~2"])

    assert result.exit_code == 0
    assert captured == {"incremental": True, "since": "HEAD~2"}
    assert "增量扫描范围" in result.stdout





def test_report_command_renders_json_from_snapshot() -> None:

    with runner.isolated_filesystem():
        snapshot = _build_snapshot()
        snapshot_path = Path("snapshot.json")
        snapshot_path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")

        result = runner.invoke(app, ["report", "--format", "json", "--input", str(snapshot_path)])

        assert result.exit_code == 0
        assert Path("reports/report.json").exists()
        assert "Generated report" in result.stdout


def test_baseline_command_creates_baseline_from_latest_snapshot() -> None:
    with runner.isolated_filesystem():
        project = Path("demo-project")
        snapshot_dir = project / ".codeguardian"
        snapshot_dir.mkdir(parents=True)

        latest_snapshot = _build_snapshot(project_path=project.resolve())
        (snapshot_dir / "latest.json").write_text(latest_snapshot.model_dump_json(indent=2), encoding="utf-8")

        result = runner.invoke(app, ["baseline", str(project), "--latest"])

        baseline_path = snapshot_dir / "baseline.json"
        assert result.exit_code == 0
        assert baseline_path.exists()
        saved = ScanResult.model_validate_json(baseline_path.read_text(encoding="utf-8"))
        assert saved.project_profile.overall_score == latest_snapshot.project_profile.overall_score
        assert "Baseline saved" in result.stdout
        assert "--baseline" in result.stdout



def test_baseline_command_runs_fresh_scan(monkeypatch) -> None:
    captured = {}

    async def fake_run_scan(_self, request):
        captured["review_mode"] = request.review_mode
        captured["dimensions"] = request.dimensions
        captured["report_formats"] = request.report_formats
        return _build_snapshot(project_path=request.project_path)

    monkeypatch.setattr("codeguardian.cli.commands.baseline.Orchestrator.run_scan", fake_run_scan)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = runner.invoke(app, ["baseline", str(project), "--output", "quality-baseline.json", "--review-mode", "ai_off"])

        assert result.exit_code == 0
        assert (project / "quality-baseline.json").exists()
        assert captured == {"review_mode": "ai_off", "dimensions": None, "report_formats": []}



def test_trend_command_summarizes_recent_snapshots() -> None:
    with runner.isolated_filesystem():
        project = Path("demo-project")
        snapshot_dir = project / ".codeguardian"
        snapshot_dir.mkdir(parents=True)

        oldest = _build_snapshot(project_path=project.resolve())
        oldest.scan_id = "20260420090000"
        oldest.started_at = "2026-04-20T09:00:00+00:00"
        oldest.finished_at = "2026-04-20T09:05:00+00:00"
        oldest.project_profile.overall_score = 92.0
        oldest.findings = []

        middle = _build_snapshot(project_path=project.resolve())
        middle.scan_id = "20260420100000"
        middle.started_at = "2026-04-20T10:00:00+00:00"
        middle.finished_at = "2026-04-20T10:05:00+00:00"
        middle.project_profile.overall_score = 86.0

        latest = _build_snapshot(project_path=project.resolve())
        latest.scan_id = "20260420110000"
        latest.started_at = "2026-04-20T11:00:00+00:00"
        latest.finished_at = "2026-04-20T11:05:00+00:00"
        latest.project_profile.overall_score = 78.0
        latest.findings[0].severity = Severity.CRITICAL
        latest.findings[0].confidence = Confidence.HIGH
        latest.findings[0].blocks_release = True

        for snapshot in (oldest, middle, latest):
            (snapshot_dir / f"snapshot-{snapshot.scan_id}.json").write_text(
                snapshot.model_dump_json(indent=2),
                encoding="utf-8",
            )

        result = runner.invoke(app, ["trend", str(project), "--limit", "3"])

    assert result.exit_code == 0
    assert "Quality Trend" in result.stdout
    assert "regressing" in result.stdout
    assert "Recent Snapshots" in result.stdout
    assert "Score delta: -14.0" in result.stdout





def test_diff_compares_baseline_to_latest_snapshot() -> None:
    with runner.isolated_filesystem():
        project = Path("demo-project")
        snapshot_dir = project / ".codeguardian"
        snapshot_dir.mkdir(parents=True)

        latest_snapshot = _build_snapshot(project_path=project.resolve())
        baseline_snapshot = _build_snapshot(project_path=project.resolve())
        baseline_snapshot.project_profile.overall_score = 92.0
        baseline_snapshot.findings = []

        (snapshot_dir / "latest.json").write_text(latest_snapshot.model_dump_json(indent=2), encoding="utf-8")
        baseline_path = Path("baseline.json")
        baseline_path.write_text(baseline_snapshot.model_dump_json(indent=2), encoding="utf-8")

        result = runner.invoke(app, ["diff", "--baseline", str(baseline_path), "--project", str(project)])

    assert result.exit_code == 0
    assert "Diff summary" in result.stdout
    assert "New findings" in result.stdout
    assert "+" in result.stdout or "-" in result.stdout







def test_diff_command_supports_git_refs(monkeypatch) -> None:
    captured = {}

    def fake_compare_git_refs(_self, project_path: Path, base_ref: str, target_ref: str) -> DiffResult:
        captured["project_path"] = project_path
        captured["base_ref"] = base_ref
        captured["target_ref"] = target_ref
        return DiffResult(
            comparison_mode="git",
            base_label=base_ref,
            target_label=target_ref,
            merge_base="abc123",
            changed_files=["sample.py"],
            touched_hotspots=["sample.py"],
            base_score=88.0,
            target_score=81.0,
            score_delta=-7.0,
            new_findings=[_build_snapshot().findings[0]],
        )

    monkeypatch.setattr("codeguardian.cli.commands.diff.DiffService.compare_git_refs", fake_compare_git_refs)

    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("print('hello')\n", encoding="utf-8")
        expected_project = project.resolve()

        result = runner.invoke(app, ["diff", "main", "feature", "--project", str(project)])

        assert captured == {
            "project_path": expected_project,
            "base_ref": "main",
            "target_ref": "feature",
        }

    assert result.exit_code == 0
    assert "Mode: git" in result.stdout
    assert "Merge base: abc123" in result.stdout
    assert "Touched hotspots" in result.stdout



def test_doctor_command_succeeds() -> None:

    with runner.isolated_filesystem():
        result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "CodeGuardian Environment Check" in result.stdout
    assert "rich" in result.stdout
    assert "Result:" in result.stdout


def test_doctor_recognizes_hidden_config_file() -> None:
    with runner.isolated_filesystem():
        Path(".codeguardian.toml").write_text("[scan]\n", encoding="utf-8")
        result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "Config file exists: .codeguardian.toml" in result.stdout


def test_gate_command_uses_project_default_threshold() -> None:
    with runner.isolated_filesystem():
        project = Path("demo-project")
        project.mkdir()
        (project / "sample.py").write_text("x = 1\n", encoding="utf-8")
        (project / "codeguardian.toml").write_text(
            "[risk]\n"
            "default_threshold = 101.0\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["gate", str(project)])

    assert result.exit_code == 1
    assert "Quality Gate FAILED" in result.stdout
    assert "below threshold (101.0)" in result.stdout


def test_report_command_uses_project_snapshot_directory() -> None:

    with runner.isolated_filesystem():
        project = Path("demo-project")
        snapshot_dir = project / ".codeguardian"
        snapshot_dir.mkdir(parents=True)
        snapshot = _build_snapshot(project_path=project.resolve())
        (snapshot_dir / "latest.json").write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")

        result = runner.invoke(app, ["report", "--format", "json", "--project", str(project)])

        assert result.exit_code == 0
        assert (project / "reports" / "report.json").exists()
        assert "Generated report" in result.stdout


def test_report_command_uses_project_configured_output_dir() -> None:
    with runner.isolated_filesystem():
        project = Path("demo-project")
        snapshot_dir = project / ".codeguardian"
        snapshot_dir.mkdir(parents=True)
        snapshot = _build_snapshot(project_path=project.resolve())
        (snapshot_dir / "latest.json").write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        (project / "codeguardian.toml").write_text(
            "[reports]\n"
            "output_dir = \"custom-reports\"\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["report", "--format", "json", "--project", str(project)])

        assert result.exit_code == 0
        assert (project / "custom-reports" / "report.json").exists()
        assert "Generated report" in result.stdout


def test_explain_command_uses_local_fallback_for_project_snapshot() -> None:

    with runner.isolated_filesystem():
        project = Path("demo-project")
        snapshot_dir = project / ".codeguardian"
        snapshot_dir.mkdir(parents=True)
        snapshot = _build_snapshot(project_path=project.resolve(), with_evidence=True)
        (snapshot_dir / "latest.json").write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")

        result = runner.invoke(app, ["explain", "DEF-001", "--project", str(project)])

        assert result.exit_code == 0
        assert "使用本地解释模式" in result.stdout
        assert "Debug print found" in result.stdout
        assert "建议怎么修" in result.stdout
        assert "证据摘要" in result.stdout


def _build_snapshot(
    project_path: Path | None = None,
    with_evidence: bool = False,
) -> ScanResult:
    finding = Finding(
        id="DEF-001",
        title="Debug print found",
        category="defect",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="sample.py", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="PRINT-DEBUG",
        evidences=[
            {
                "type": "code_snippet",
                "content": "print('debug')",
                "file_path": "sample.py",
                "line_start": 1,
                "line_end": 1,
            }
        ] if with_evidence else [],
    )
    return ScanResult(
        project_path=str(project_path) if project_path is not None else "",
        project_profile=ProjectProfile(project_name="demo", overall_score=88.0),
        findings=[finding],
    )
