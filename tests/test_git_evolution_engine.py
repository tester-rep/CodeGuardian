"""Tests for Git evolution metrics and findings."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.git_evolution_engine import GitEvolutionEngine
from codeguardian.models.metric import MetricNames


async def test_git_evolution_engine_reports_hotspots_and_ownership_risk() -> None:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        _git(root, "init")
        _git(root, "config", "user.name", "Alice")
        _git(root, "config", "user.email", "alice@example.com")

        hotspot = root / "hotspot.py"
        hotspot.write_text("value = 1\n", encoding="utf-8")
        _commit_all(root, "Alice", "alice@example.com", "init hotspot")

        hotspot.write_text("value = 2\n" + "print('a')\n" * 12, encoding="utf-8")
        _commit_all(root, "Alice", "alice@example.com", "expand hotspot")

        hotspot.write_text("value = 3\n" + "print('b')\n" * 20, encoding="utf-8")
        _commit_all(root, "Alice", "alice@example.com", "touch hotspot again")

        shared = root / "shared.py"
        shared.write_text("name = 'bob'\n", encoding="utf-8")
        _commit_all(root, "Bob", "bob@example.com", "add shared file")

        ctx = ScanContext(
            project_root=str(root),
            config=load_app_config(None),
            is_git_repo=True,
        )
        result = await GitEvolutionEngine().analyze(ctx)

        project_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "project"
        }
        hotspot_metrics = {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "hotspot.py" and metric.target_type == "file"
        }

        assert project_metrics["total_commits"].value == 4.0
        assert project_metrics["active_authors"].value == 2.0
        assert project_metrics[MetricNames.CHURN_SCORE].value >= 1.0
        assert hotspot_metrics[MetricNames.CHURN_SCORE].value >= 20.0
        assert hotspot_metrics["author_count"].value == 1.0
        assert hotspot_metrics["ownership_share"].value == 100.0

        rule_ids = {finding.rule_id for finding in result.findings}
        assert "GIT-HOTSPOT" in rule_ids
        assert "OWNERSHIP-RISK" in rule_ids


async def test_git_evolution_engine_warns_for_non_git_repo() -> None:
    with TemporaryDirectory() as tmpdir:
        ctx = ScanContext(project_root=tmpdir, config=load_app_config(None), is_git_repo=False)

        result = await GitEvolutionEngine().analyze(ctx)

        assert result.metrics == []
        assert result.findings == []
        assert result.warnings == ["Not a Git repository — skipping Git analysis"]


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> None:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=full_env,
    )


def _commit_all(root: Path, author_name: str, author_email: str, message: str) -> None:
    env = {
        "GIT_AUTHOR_NAME": author_name,
        "GIT_AUTHOR_EMAIL": author_email,
        "GIT_COMMITTER_NAME": author_name,
        "GIT_COMMITTER_EMAIL": author_email,
    }
    _git(root, "add", ".", env=env)
    _git(root, "commit", "-m", message, env=env)
