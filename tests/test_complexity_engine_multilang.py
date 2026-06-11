"""Focused tests for parser-backed multi-language complexity analysis."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.complexity_engine import ComplexityEngine
from codeguardian.models.metric import MetricNames


async def test_complexity_engine_analyzes_javascript_functions_via_parser() -> None:
    source = """
function orchestrate(items, enabled, fallback, limit, label, extra) {
  if (enabled && label) {
    for (const item of items) {
      if (item.ready) {
        while (fallback) {
          console.log(item);
          break;
        }
      }
    }
  }
  return limit + extra;
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.js").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await ComplexityEngine().analyze(ctx)

        project_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "project"
        }
        assert project_metrics[MetricNames.CYCLOMATIC_COMPLEXITY].value > 1
        assert project_metrics[MetricNames.PARAM_COUNT].value == 6

        function_metric_targets = {metric.target_id for metric in result.metrics if metric.target_type == "function"}
        assert any(target.endswith(":orchestrate") for target in function_metric_targets)

        rule_ids = {finding.rule_id for finding in result.findings}
        assert "HIGH-CC-FUNCTION" in rule_ids or "TOO-MANY-PARAMS" in rule_ids or "DEEP-NESTING" in rule_ids


async def test_complexity_engine_analyzes_priority_languages_via_heuristics() -> None:
    go_source = """
package main

type Service struct{}

func (s *Service) orchestrate(a int, b int, c int, d int, e int, f int) int {
  if a > 0 {
    for b > 0 {
      if c > 0 && d > 0 {
        return e + f
      }
      break
    }
  }
  return 0
}
"""
    lua_source = """
local function compute(a, b, c, d, e, f)
  if a then
    while b do
      if c and d then
        return e + f
      end
      break
    end
  end
  return 0
end
"""
    rust_source = """
impl Worker {
  pub fn run(&self, a: bool, b: bool, c: bool, d: bool, e: i32, f: i32) -> i32 {
    if a {
      if b && c {
        return e + f;
      }
    }
    if d {
      return e;
    }
    0
  }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "service.go").write_text(go_source.strip() + "\n", encoding="utf-8")
        (root / "script.lua").write_text(lua_source.strip() + "\n", encoding="utf-8")
        (root / "worker.rs").write_text(rust_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await ComplexityEngine().analyze(ctx)

    project_metrics = {
        metric.metric_name: metric
        for metric in result.metrics
        if metric.target_id == "project"
    }
    assert project_metrics[MetricNames.CYCLOMATIC_COMPLEXITY].value > 1
    assert project_metrics[MetricNames.PARAM_COUNT].value >= 6

    function_metric_targets = {metric.target_id for metric in result.metrics if metric.target_type == "function"}
    assert any("orchestrate" in target for target in function_metric_targets)
    assert any("compute" in target for target in function_metric_targets)
    assert any("run" in target for target in function_metric_targets)


    rule_ids = {finding.rule_id for finding in result.findings}
    assert "TOO-MANY-PARAMS" in rule_ids

