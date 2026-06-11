"""Tests for language priority ordering and reporting."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.detectors.language_detector import LanguageDetector
from codeguardian.engines.metrics_engine import MetricsEngine
from codeguardian.models.metric import MetricNames


def test_language_detector_orders_languages_by_target_priority() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
        (root / "App.java").write_text("class App {}\n", encoding="utf-8")
        (root / "main.go").write_text("package main\n", encoding="utf-8")
        (root / "main.lua").write_text("print('ok')\n", encoding="utf-8")
        (root / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "App.cs").write_text("class App {}\n", encoding="utf-8")
        (root / "main.js").write_text("console.log('ok');\n", encoding="utf-8")
        (root / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

        detected = LanguageDetector().detect(root)

    assert detected[:8] == ["cpp", "java", "go", "lua", "python", "csharp", "javascript", "rust"]


async def test_metrics_engine_reports_language_priority_tiers() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
        (root / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await MetricsEngine().analyze(ctx)

    language_metrics = {
        metric.target_id: metric
        for metric in result.metrics
        if metric.metric_name == MetricNames.FILE_COUNT and metric.target_type == "language"
    }

    assert language_metrics["cpp"].extra["priority_tier"] == 1
    assert language_metrics["python"].extra["priority_tier"] == 2
    assert language_metrics["rust"].extra["priority_tier"] == 3
