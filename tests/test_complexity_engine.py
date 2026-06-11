"""Focused tests for AST-backed complexity analysis."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.complexity_engine import ComplexityEngine
from codeguardian.models.metric import MetricNames


async def test_complexity_engine_detects_python_function_risks() -> None:
    # This function is deliberately made extremely complex to exceed the
    # updated thresholds: CC≥15, nesting≥5, params≥6, LOC≥60.
    source = '''
def complex_handler(a, b, c, d, e, f, g, h, i, j):
    result = 0
    if a:
        for item in range(3):
            if b and c:
                while d:
                    if e:
                        try:
                            if f:
                                result += item
                            if g:
                                result -= 1
                            if h:
                                result *= 2
                        except ValueError:
                            result = -1
                        except TypeError:
                            result = -2
                    elif i:
                        result += 10
                    else:
                        result -= 10
            elif d or e:
                result += 5
            else:
                result -= 5
    elif b:
        for x in range(10):
            if c and d:
                result += x
            elif e or f:
                result -= x
            else:
                result = 0
    elif c:
        if d:
            if e:
                result = 100
            elif f:
                result = 200
            else:
                result = 300
        elif g:
            result = 400
        else:
            result = 500
    else:
        for y in range(5):
            if a or b:
                result += y
            elif c or d:
                result -= y
            elif e or f:
                result *= y
            elif g or h:
                result //= max(y, 1)
            else:
                result = y
    if j:
        result = -result
    return result



def tiny(x):
    return x
'''

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "sample.py"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await ComplexityEngine().analyze(ctx)

        project_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "project"
        }
        assert project_metrics[MetricNames.CYCLOMATIC_COMPLEXITY].value >= 4
        assert project_metrics[MetricNames.NESTING_DEPTH].value >= 5
        assert project_metrics[MetricNames.PARAM_COUNT].value >= 6

        rule_ids = {finding.rule_id for finding in result.findings}
        # The aggregated finding should use HIGH-CC-FUNCTION as the dominant rule_id
        assert "HIGH-CC-FUNCTION" in rule_ids

        # Verify the aggregated finding title mentions complexity issues
        cc_findings = [f for f in result.findings if f.rule_id == "HIGH-CC-FUNCTION"]
        assert len(cc_findings) >= 1
        assert "复杂度" in cc_findings[0].title or "complexity" in cc_findings[0].title.lower()

        function_metrics = [metric for metric in result.metrics if metric.target_type == "function"]
        assert any(metric.target_id.endswith(":complex_handler") for metric in function_metrics)
