"""Tests for dimension-aware planning and configured report output."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from codeguardian.config.defaults import default_config
from codeguardian.core.context import ScanContext
from codeguardian.core.orchestrator import Orchestrator
from codeguardian.core.planner import DEEP_ENABLED_ENGINES, VALID_DIMENSIONS, build_plan
from codeguardian.models.metric import MetricNames
from codeguardian.models.scan import ScanRequest


def test_build_plan_filters_enabled_engines_by_dimension() -> None:
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        dimensions=["security"],
    )

    plan = build_plan(ctx)

    assert plan.enabled_dimensions == ["security"]
    # security dimension now only activates the code-security engine.
    # Config file scanning (config_risk) must be requested explicitly via
    # --dimensions config / deployment / security,config.
    assert plan.enabled_engines == ["security"]


def test_build_plan_deep_mode_only_uses_registered_engines() -> None:
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        depth="deep",
    )

    plan = build_plan(ctx)

    assert plan.enabled_engines == DEEP_ENABLED_ENGINES


def test_build_plan_rejects_unsupported_dimensions() -> None:
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        dimensions=["observability"],
    )

    with pytest.raises(ValueError, match="Unsupported dimensions requested"):
        build_plan(ctx)



def test_build_plan_supports_performance_dimension() -> None:
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        dimensions=["performance"],
    )

    plan = build_plan(ctx)

    assert plan.enabled_dimensions == ["performance"]
    assert plan.enabled_engines == ["performance"]





def test_build_plan_supports_testing_dimension() -> None:
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        dimensions=["testing"],
    )

    plan = build_plan(ctx)

    assert plan.enabled_dimensions == ["testing"]
    assert plan.enabled_engines == ["testing"]


def test_build_plan_supports_architecture_dimension() -> None:
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        dimensions=["architecture"],
        depth="deep",
    )

    plan = build_plan(ctx)

    assert plan.enabled_dimensions == ["architecture"]
    assert plan.enabled_engines == ["structure", "metrics", "complexity", "git", "oo_design", "dependency"]


def test_build_plan_default_profile_excludes_config_risk() -> None:
    """Default profile must not enable config_risk — configs are opt-in only."""
    ctx = ScanContext(project_root=".", config=default_config())

    plan = build_plan(ctx)

    assert "config_risk" not in plan.enabled_engines


def test_build_plan_config_dimension_enables_config_risk() -> None:
    """--dimensions config explicitly opts into the config_risk engine."""
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        dimensions=["config"],
    )

    plan = build_plan(ctx)

    assert plan.enabled_engines == ["config_risk"]


def test_build_plan_supports_all_keyword() -> None:
    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        dimensions=["all"],
        depth="deep",
    )

    plan = build_plan(ctx)

    assert plan.enabled_dimensions == VALID_DIMENSIONS
    assert plan.enabled_engines == DEEP_ENABLED_ENGINES


def test_build_plan_uses_incremental_target_files() -> None:

    ctx = ScanContext(
        project_root=".",
        config=default_config(),
        incremental=True,
        target_files=["sample.py"],
    )

    plan = build_plan(ctx)

    assert plan.target_files == ["sample.py"]
    assert plan.coverage_mode == "file"
    assert plan.git_mode == "diff"


def test_deep_review_file_map_falls_back_without_structure_results() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src_dir = root / "src"
        src_dir.mkdir()
        (src_dir / "service.ts").write_text("export function run() { return 1; }\n", encoding="utf-8")

        ctx = ScanContext(
            project_root=str(root),
            config=default_config(),
            depth="deep",
            dimensions=["defects"],
            languages=["typescript"],
        )

        mapping = Orchestrator._build_deep_review_file_language_map(ctx, [])

        assert mapping == {"src/service.ts": "typescript"}


async def test_orchestrator_respects_configured_report_output_dir() -> None:



    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        config = default_config()
        config.reports.output_dir = "custom-reports"
        orchestrator = Orchestrator(config)

        result = await orchestrator.run_scan(
            ScanRequest(
                project_path=root,
                report_formats=["json"],
                depth="quick",
            )
        )

        json_artifact = next(artifact for artifact in result.report_artifacts if artifact.format == "json")
        assert Path(json_artifact.path).name == "report.json"
        assert Path(json_artifact.path).parent.name == "custom-reports"
        assert Path(json_artifact.path).exists()


async def test_orchestrator_only_renders_requested_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal_calls: list[Path | None] = []

    def fake_terminal_render(_self, _result, output_dir):
        terminal_calls.append(output_dir)
        return None

    monkeypatch.setattr("codeguardian.core.orchestrator.TerminalReporter.render", fake_terminal_render)

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        orchestrator = Orchestrator(default_config())
        await orchestrator.run_scan(
            ScanRequest(
                project_path=root,
                report_formats=["json"],
                depth="quick",
            )
        )

    assert terminal_calls == []


async def test_orchestrator_uses_configured_risk_weights() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        default_orchestrator = Orchestrator(default_config())
        default_result = await default_orchestrator.run_scan(
            ScanRequest(
                project_path=root,
                report_formats=["json"],
                depth="quick",
            )
        )

        weighted_config = default_config()
        weighted_config.risk.weights = {"severity": 0.0}
        weighted_orchestrator = Orchestrator(weighted_config)
        weighted_result = await weighted_orchestrator.run_scan(
            ScanRequest(
                project_path=root,
                report_formats=["json"],
                depth="quick",
            )
        )

        assert weighted_result.project_profile.overall_score > default_result.project_profile.overall_score


async def test_orchestrator_populates_ai_summary_and_release_conclusion() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = await Orchestrator(default_config()).run_scan(
            ScanRequest(
                project_path=root,
                report_formats=["json"],
                depth="quick",
            )
        )

    assert result.ai_summary
    assert result.release_conclusion is not None
    assert result.release_conclusion.verdict in {"recommended", "conditional", "not_recommended", "blocked"}
    assert result.release_conclusion.review_source in {"local", "ai"}
    assert result.release_conclusion.review_summary


async def test_orchestrator_uses_ai_router_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeAIRouter:
        def __init__(self, provider=None) -> None:
            self.provider = provider or object()
            from codeguardian.ai.models import TokenUsage
            self.total_usage = TokenUsage()

        @classmethod
        def from_config(cls, config):
            return cls()

        async def summarize_findings(self, findings_summary: dict) -> str:
            return f"AI summary for {findings_summary['project_name']}"

        async def review_release(self, project_data: dict) -> str:
            return f"AI release review: {project_data['verdict']}"

    monkeypatch.setattr("codeguardian.core.orchestrator.AIRouter", FakeAIRouter)

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        config = default_config()
        config.ai.enabled = True
        result = await Orchestrator(config).run_scan(
            ScanRequest(
                project_path=root,
                report_formats=[],
                depth="quick",
            )
        )

    assert result.ai_summary == f"AI summary for {root.name}"
    assert result.release_conclusion is not None
    assert result.release_conclusion.review_source == "ai"
    assert result.release_conclusion.review_summary == f"AI release review: {result.release_conclusion.verdict}"


async def test_orchestrator_emits_project_risk_metrics_for_core_modules() -> None:

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "core").mkdir()
        (root / "core" / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = await Orchestrator(default_config()).run_scan(
            ScanRequest(
                project_path=root,
                report_formats=[],
                depth="quick",
            )
        )

    project_metrics = {
        metric.metric_name: metric
        for metric in result.metrics
        if metric.target_id == "project"
    }

    assert project_metrics[MetricNames.RISK_SCORE].value == result.project_profile.overall_score
    assert project_metrics[MetricNames.CORE_MODULE_SCORE].value == result.project_profile.overall_score
    assert project_metrics[MetricNames.CORE_MODULE_SCORE].extra["modules"] == ["core"]


async def test_orchestrator_populates_module_dimension_scores() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "core").mkdir()
        (root / "core" / "sample.py").write_text("print('hello')\n", encoding="utf-8")

        result = await Orchestrator(default_config()).run_scan(
            ScanRequest(
                project_path=root,
                report_formats=[],
                depth="quick",
            )
        )

    module = next(profile for profile in result.project_profile.modules if profile.path == "core")
    assert module.dimension_scores
    assert all(0.0 <= score <= 100.0 for score in module.dimension_scores.values())


async def test_orchestrator_populates_module_special_report_fields() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "core").mkdir()
        (root / "core" / "sample.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (root / "coverage.json").write_text(
            """
{
  "meta": {"format": 2},
  "files": {
    "core/sample.py": {
      "executed_lines": [1],
      "missing_lines": [2],
      "summary": {
        "covered_lines": 1,
        "num_statements": 2,
        "percent_covered": 50.0
      }
    }
  }
}
""".strip(),
            encoding="utf-8",
        )

        config = default_config()
        config.test.coverage_files = ["coverage.json"]
        result = await Orchestrator(config).run_scan(
            ScanRequest(
                project_path=root,
                report_formats=[],
                depth="quick",
            )
        )

    module = next(profile for profile in result.project_profile.modules if profile.path == "core")
    assert module.loc > 0
    assert module.testing_profile.line_coverage == 50.0
    assert module.testing_profile.status == "critical"
    assert module.top_findings
    assert module.architecture_profile.notes
    assert module.action_items



def test_terminal_reporter_renders_module_and_release_sections() -> None:

    from io import StringIO

    from rich.console import Console

    from codeguardian.reporters.terminal import TerminalReporter

    reporter = TerminalReporter()
    buffer = StringIO()
    reporter.console = Console(file=buffer, force_terminal=False, color_system=None, width=120)

    reporter.render(_report_snapshot(), None)

    output = buffer.getvalue()
    assert "高风险模块" in output
    assert "模块专项报告" in output
    assert "阻塞项" in output
    assert "残余风险" in output
    assert "发布后监控" in output
    assert "历史稳定性" in output
    assert "待办事项" in output
    assert "core/api" in output
    assert "证据" in output







def test_html_reporter_renders_module_and_release_sections() -> None:
    from codeguardian.reporters.html_reporter import HtmlReporter

    with TemporaryDirectory() as tmpdir:
        artifact = HtmlReporter().render(_report_snapshot(), Path(tmpdir))
        assert artifact is not None
        html = Path(artifact.path).read_text(encoding="utf-8")

    assert "高风险模块" in html
    assert "模块专项报告" in html
    assert "阻塞项" in html
    assert "发布后监控" in html
    assert "历史稳定性" in html
    assert "待办事项" in html
    assert "core/api" in html
    assert "Observe API latency" in html
    assert "证据等级" in html
    assert "疑似风险" in html







def _report_snapshot():
    from codeguardian.models.common import Location
    from codeguardian.models.enums import Confidence, Severity
    from codeguardian.models.finding import Finding
    from codeguardian.models.profile import (
        ModuleActionItem,
        ModuleArchitectureProfile,
        ModuleProfile,
        ModuleReportIssue,
        ModuleStabilityProfile,
        ModuleTestingProfile,
        ProjectProfile,
        ReleaseConclusion,
    )
    from codeguardian.models.scan import ScanResult

    finding = Finding(
        id="SEC-900",
        title="Critical secret leak",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        location=Location(file_path="core/api.py", line_start=12, line_end=12),
        source_engine="security",
        rule_id="SECRET-LEAK",
        risk_priority="must-fix",
        blocks_release=True,
    )
    module = ModuleProfile(
        name="api",
        path="core/api",
        file_count=2,
        function_count=4,
        language="python",
        loc=180,
        sloc=142,
        risk_score=61.0,
        risk_level="high",
        findings=[finding],
        top_findings=[
            ModuleReportIssue(
                id="SEC-900",
                title="Critical secret leak",
                severity="critical",
                priority="must-fix",
                location="core/api.py:12",
            )
        ],
        dimension_scores={"security": 55.0, "complexity": 68.0},
        test_coverage=72.0,
        branch_coverage=61.0,
        function_coverage=75.0,
        churn_score=128.0,
        testing_profile=ModuleTestingProfile(
            line_coverage=72.0,
            branch_coverage=61.0,
            function_coverage=75.0,
            status="warning",
        ),
        historical_stability=ModuleStabilityProfile(
            churn_score=128.0,
            churn_trend="rising",
            hotspot=True,
            recent_large_change=False,
        ),
        architecture_profile=ModuleArchitectureProfile(
            notes=["Dependency graph is not available yet; keep reviewing module boundaries manually."]
        ),
        action_items=[
            ModuleActionItem(
                type="test",
                priority="recommended",
                summary="Extend auth and API regression coverage for failure paths.",
            ),
            ModuleActionItem(
                type="stability",
                priority="recommended",
                summary="Track API latency and release error rate after rollout.",
            ),
        ],
        recommendation="plan_refactor",
    )

    profile = ProjectProfile(
        project_name="demo",
        overall_score=74.0,
        health_status="warning",
        modules=[module],
    )
    conclusion = ReleaseConclusion(
        verdict="conditional",
        review_summary="Release is possible with focused follow-up checks.",
        review_source="local",
        blocking_items=[{"title": "Critical secret leak", "location": "core/api.py:12"}],
        residual_risks=[{"title": "Coverage still thin on API edges", "severity": "medium"}],
        suggested_verifications=[{"suggestion": "Run regression suite for auth and API flows."}],
        post_release_monitoring=[{"suggestion": "Observe API latency and error rate after release."}],
    )
    return ScanResult(
        project_profile=profile,
        findings=[finding],
        metrics=[],
        ai_summary="Core API still carries concentrated release risk.",
        release_conclusion=conclusion,
    )







