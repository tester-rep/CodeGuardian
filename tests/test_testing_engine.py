"""Tests for coverage-driven testing analysis."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.testing_engine import TestingEngine
from codeguardian.models.metric import MetricNames


async def test_testing_engine_parses_coverage_json_and_emits_findings() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (root / "coverage.json").write_text(
            """
{
  "meta": {"format": 2},
  "files": {
    "sample.py": {
      "executed_lines": [1, 2],
      "missing_lines": [3, 4, 5],
      "summary": {
        "covered_lines": 2,
        "num_statements": 5,
        "percent_covered": 40.0,
        "covered_branches": 1,
        "num_branches": 2
      }
    }
  }
}
""".strip(),
            encoding="utf-8",
        )

        config = load_app_config(None)
        config.test.coverage_files = ["coverage.json"]
        ctx = ScanContext(project_root=str(root), config=config)

        result = await TestingEngine().analyze(ctx)

        project_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "project"
        }
        file_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "sample.py" and metric.target_type == "file"
        }

        assert project_metrics[MetricNames.LINE_COVERAGE].value == 40.0
        assert project_metrics[MetricNames.BRANCH_COVERAGE].value == 50.0
        assert file_metrics[MetricNames.LINE_COVERAGE].value == 40.0

        rule_ids = {finding.rule_id for finding in result.findings}
        assert "LOW-PROJECT-COVERAGE" in rule_ids
        assert "LOW-FILE-COVERAGE" in rule_ids


async def test_testing_engine_auto_discovers_coverage_xml() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "app.py").write_text("def handler(x):\n    if x:\n        return 1\n    return 0\n", encoding="utf-8")
        (root / "coverage.xml").write_text(
            """
<?xml version="1.0" ?>
<coverage version="7.0">
  <packages>
    <package name=".">
      <classes>
        <class name="app.py" filename="app.py" line-rate="0.75" branch-rate="0.5">
          <methods>
            <method name="handler" signature="(x)" line-rate="1.0" />
            <method name="fallback" signature="()" line-rate="0.0" />
          </methods>
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="1" branch="true" condition-coverage="50% (1/2)"/>
            <line number="3" hits="1"/>
            <line number="4" hits="0"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
""".strip(),
            encoding="utf-8",
        )

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await TestingEngine().analyze(ctx)

        project_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "project"
        }

        assert project_metrics[MetricNames.LINE_COVERAGE].value == 75.0
        assert project_metrics[MetricNames.BRANCH_COVERAGE].value == 50.0
        assert project_metrics[MetricNames.FUNCTION_COVERAGE].value == 50.0
        assert result.warnings == []


async def test_testing_engine_emits_changed_line_coverage() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (root / "coverage.json").write_text(
            """
{
  "meta": {"format": 2},
  "files": {
    "sample.py": {
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

        config = load_app_config(None)
        config.test.coverage_files = ["coverage.json"]
        ctx = ScanContext(
            project_root=str(root),
            config=config,
            incremental=True,
            changed_lines={"sample.py": [1, 2]},
        )
        result = await TestingEngine().analyze(ctx)

        project_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "project"
        }
        rule_ids = {finding.rule_id for finding in result.findings}

        assert project_metrics[MetricNames.CHANGE_LINE_COVERAGE].value == 50.0
        assert "LOW-CHANGE-COVERAGE" in rule_ids

