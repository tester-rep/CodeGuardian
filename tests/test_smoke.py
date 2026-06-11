"""Smoke tests for CodeGuardian CLI — verifies basic project structure works."""

import asyncio
from pathlib import Path

from codeguardian.config.loader import load_app_config
from codeguardian.core.orchestrator import Orchestrator
from codeguardian.models.entity import FileEntity
from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric
from codeguardian.models.scan import EngineResult, ScanRequest, ScanResult
from codeguardian.storage.snapshots import load_latest_snapshot, save_snapshot


class TestModels:
    """Verify data models can be instantiated and serialized."""

    def test_file_entity(self):
        f = FileEntity(path="src/main.py", language="python", loc=100, sloc=80)
        assert f.path == "src/main.py"
        assert f.language == "python"
        assert f.extension == "py"

    def test_metric(self):
        m = Metric(target_id="test", target_type="function", metric_name="cc", value=10.0, source_engine="test")
        assert m.value == 10.0

    def test_finding(self):
        from codeguardian.models.common import Location
        from codeguardian.models.enums import Confidence, Severity

        f = Finding(
            id="TEST-001",
            title="Test finding",
            category="defect",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            location=Location(file_path="test.py", line_start=1),
            source_engine="test",
        )
        assert not f.blocks_release
        assert f.risk_priority == "should-fix"
        assert f.evidence_level == "suspected"
        assert f.verification_status == "unverified"
        assert f.evidence_rank > 0

    def test_scan_request(self):

        req = ScanRequest(project_path=Path("."))
        assert req.depth == "standard"
        assert len(req.report_formats) >= 1

    def test_scan_result(self):
        result = ScanResult(
            project_profile=self._mock_profile(),
            findings=[self._mock_finding()],
        )
        assert result.schema_version == "1.0"
        assert len(result.findings) == 1
        # Verify serialization round-trip
        json_str = result.model_dump_json()
        restored = ScanResult.model_validate_json(json_str)
        assert restored.project_profile.project_name == "test-project"

    @staticmethod
    def _mock_profile():
        from codeguardian.models.profile import ProjectProfile
        return ProjectProfile(project_name="test-project", overall_score=85.0)

    @staticmethod
    def _mock_finding():
        from codeguardian.models.common import Location
        from codeguardian.models.enums import Confidence, Severity
        return Finding(
            id="TEST-001", title="T", category="defect",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            location=Location(file_path="t.py"),
            source_engine="test",
        )


class TestConfig:
    """Verify configuration loading."""

    def test_default_config(self):
        config = load_app_config(None)  # No file → defaults
        assert config is not None
        assert config.scan.depth == "standard"

    def test_config_schema(self):
        from codeguardian.config.schema import AppConfig
        c = AppConfig()
        assert c.ai.enabled is False
        assert c.reports.formats == ["terminal"]
        assert c.rules.disabled == []
        assert c.rules.min_severity is None



class TestDetectors:
    """Verify project detection."""

    def test_language_detector(self):
        from codeguardian.detectors.language_detector import LanguageDetector
        detector = LanguageDetector()

        # Current directory should have Python files
        langs = detector.detect(Path("."))
        assert isinstance(langs, list)
        assert len(langs) > 0  # At least something detected or "unknown")

    def test_project_detector(self):
        from codeguardian.detectors.project_detector import ProjectDetector
        detector = ProjectDetector()
        result = detector.detect(Path("."))
        assert isinstance(result.languages, list)


class TestEngines:
    """Verify engine interface and basic operation."""

    async def test_structure_engine(self):
        from codeguardian.core.context import ScanContext
        from codeguardian.engines.structure_engine import StructureEngine

        engine = StructureEngine()
        ctx = ScanContext(project_root=".", config=load_app_config(None))
        result = await engine.analyze(ctx)

        assert isinstance(result, EngineResult)
        assert engine.name == "structure"
        assert len(result.files) > 0  # Should find some source files

    async def test_metrics_engine(self):
        from codeguardian.core.context import ScanContext
        from codeguardian.engines.metrics_engine import MetricsEngine
        from codeguardian.models.metric import MetricNames

        engine = MetricsEngine()
        ctx = ScanContext(project_root=".", config=load_app_config(None))
        result = await engine.analyze(ctx)

        assert isinstance(result, EngineResult)
        assert len(result.metrics) > 0
        project_metrics = {metric.metric_name for metric in result.metrics if metric.target_id == "project"}
        assert MetricNames.DUPLICATION_RATE in project_metrics


    async def test_defect_engine(self):
        from codeguardian.core.context import ScanContext
        from codeguardian.engines.defect_engine import DefectEngine

        engine = DefectEngine()
        ctx = ScanContext(project_root=".", config=load_app_config(None))
        result = await engine.analyze(ctx)

        assert isinstance(result, EngineResult)
        # May or may not have findings depending on codebase content

    async def test_security_engine(self):
        from codeguardian.core.context import ScanContext
        from codeguardian.engines.security_engine import SecurityEngine

        engine = SecurityEngine()
        ctx = ScanContext(project_root=".", config=load_app_config(None))
        result = await engine.analyze(ctx)

        assert isinstance(result, EngineResult)


class TestRisk:
    """Verify risk scoring and prioritization."""

    def test_scorer_empty(self):
        from codeguardian.risk.scorer import RiskScorer
        scorer = RiskScorer()
        assert scorer.score([]) == 100.0  # No findings = perfect score

    def test_scorer_with_findings(self):
        from codeguardian.models.enums import Confidence, Severity
        from codeguardian.models.finding import Finding
        from codeguardian.risk.scorer import RiskScorer

        scorer = RiskScorer()
        findings = [
            Finding(id="1", title="C1", category="security",
                     severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                     location=file_loc("f.py"), source_engine="t"),
            Finding(id="2", title="H1", category="defect",
                     severity=Severity.HIGH, confidence=Confidence.HIGH,
                     location=file_loc("f.py"), source_engine="t"),
            Finding(id="3", title="M1", category="maintainability",
                     severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                     location=file_loc("f.py"), source_engine="t"),
        ]
        score = scorer.score(findings)
        assert 0 <= score < 100.0  # Should deduct for issues

    def test_prioritizer(self):
        from codeguardian.models.enums import Confidence, Severity
        from codeguardian.models.finding import Finding
        from codeguardian.risk.prioritizer import Prioritizer

        p = Prioritizer()
        findings = [
            Finding(id="1", title="C", category="s", severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                     location=file_loc("f"), source_engine="t"),
            Finding(id="2", title="H", category="d", severity=Severity.HIGH, confidence=Confidence.HIGH,
                     location=file_loc("f"), source_engine="t"),
            Finding(id="3", title="L", category="m", severity=Severity.LOW, confidence=Confidence.LOW,
                     location=file_loc("f"), source_engine="t"),
        ]
        result = p.apply(findings)
        assert result[0].risk_priority == "must-fix"


class TestReporters:
    """Verify report generation."""

    def test_json_reporter(self):
        from tempfile import TemporaryDirectory

        from codeguardian.reporters.json_reporter import JsonReporter

        reporter = JsonReporter()
        with TemporaryDirectory() as tmpdir:
            artifact = reporter.render(_scan_result(), Path(tmpdir))
            assert artifact is not None
            assert artifact.format == "json"

    def test_html_reporter(self):
        from tempfile import TemporaryDirectory

        from codeguardian.reporters.html_reporter import HtmlReporter

        reporter = HtmlReporter()
        with TemporaryDirectory() as tmpdir:
            artifact = reporter.render(_scan_result(), Path(tmpdir))
            assert artifact is not None
            assert artifact.format == "html"


class TestOrchestrator:
    """Integration-level smoke test of the full pipeline."""

    def test_smoke_scan(self):
        config = load_app_config(None)
        orchestrator = Orchestrator(config)

        result = asyncio.run(
            orchestrator.run_scan(
                ScanRequest(
                    project_path=Path("."),
                    report_formats=["json"],
                    depth="quick",
                )
            )
        )

        assert result.project_profile.project_name
        assert result.schema_version == "1.0"
        assert result.project_profile.overall_score >= 0.0
        assert result.project_profile.overall_score <= 100.0
        assert result.started_at.startswith("20")
        assert result.finished_at.startswith("20")

        # Should have generated at least a JSON report

        json_artifact = next((a for a in result.report_artifacts if a.format == "json"), None)
        if json_artifact:
            assert Path(json_artifact.path).exists()


class TestStorage:
    """Verify snapshot save/load cycle."""

    def test_save_load_cycle(self):
        from tempfile import TemporaryDirectory

        result = _scan_result()
        with TemporaryDirectory() as tmpdir:
            save_snapshot(result, Path(tmpdir))
            loaded = load_latest_snapshot(Path(tmpdir))


            assert loaded is not None
            assert loaded.scan_id == result.scan_id
            assert loaded.project_profile.project_name == result.project_profile.project_name


# Helpers
def file_loc(path: str = "sample.py"):
    from codeguardian.models.common import Location
    return Location(file_path=path)


def _scan_result() -> ScanResult:
    return ScanResult(
        project_profile=_profile(),
        findings=[_finding()],
        metrics=[Metric(target_id="p", target_type="p", metric_name="test", value=1.0, unit="", source_engine="t")],
    )


def _profile():
    from codeguardian.models.profile import ProjectProfile
    return ProjectProfile(project_name="smoke-test", overall_score=72.0)


def _finding():
    from codeguardian.models.common import Location
    from codeguardian.models.enums import Confidence, Severity
    return Finding(
        id="SMOKE-001", title="Smoke test finding", category="maintainability",
        severity=Severity.LOW, confidence=Confidence.MEDIUM,
        location=Location(file_path="sample.py"),
        source_engine="smoke-test",
    )
