"""Tests for diff service snapshot and Git ref semantics."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.core.diff_service import DiffService
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.models.profile import ProjectProfile
from codeguardian.models.scan import ScanResult


def test_diff_service_semantic_match_ignores_line_moves() -> None:
    service = DiffService()
    base = _build_snapshot([_build_finding(line_start=10)])
    target = _build_snapshot([_build_finding(line_start=42)])

    diff = service.compare(base, target, semantic_match=True)

    assert diff.new_findings == []
    assert diff.resolved_findings == []


def test_diff_service_compare_git_refs_uses_merge_base_scope(monkeypatch) -> None:
    def fake_scan_tree(_self, root: Path) -> ScanResult:
        sample = root / "sample.py"
        content = sample.read_text(encoding="utf-8") if sample.exists() else ""
        findings = []
        score = 95.0
        if "new_issue = True" in content:
            findings = [_build_finding(title="New branch issue", line_start=2)]
            score = 78.0
        return _build_snapshot(findings, project_path=root, overall_score=score)

    monkeypatch.setattr(DiffService, "_scan_tree", fake_scan_tree)

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        _git(root, "init")
        _git(root, "config", "user.name", "Alice")
        _git(root, "config", "user.email", "alice@example.com")
        _git(root, "branch", "-M", "main")

        (root / "sample.py").write_text("value = 1\n", encoding="utf-8")
        _commit_all(root, "Alice", "alice@example.com", "init")

        _git(root, "checkout", "-b", "feature")
        (root / "sample.py").write_text(
            "value = 1\nnew_issue = True\n" + "print('x')\n" * 25,
            encoding="utf-8",
        )
        _commit_all(root, "Alice", "alice@example.com", "introduce issue")

        _git(root, "checkout", "main")
        (root / "base.txt").write_text("baseline\n", encoding="utf-8")
        _commit_all(root, "Alice", "alice@example.com", "main branch only change")

        _git(root, "checkout", "feature")

        diff = DiffService().compare_git_refs(root, "main", "feature")

    assert diff.comparison_mode == "git"
    assert diff.base_label == "main"
    assert diff.target_label == "feature"
    assert diff.merge_base is not None
    assert diff.changed_files == ["sample.py"]
    assert diff.touched_hotspots == ["sample.py"]
    assert [finding.title for finding in diff.new_findings] == ["New branch issue"]
    assert diff.resolved_findings == []


def _build_snapshot(
    findings: list[Finding],
    project_path: Path | None = None,
    overall_score: float = 88.0,
) -> ScanResult:
    return ScanResult(
        project_path=str(project_path) if project_path is not None else "",
        project_profile=ProjectProfile(project_name="demo", overall_score=overall_score),
        findings=findings,
    )


def _build_finding(title: str = "Debug print found", line_start: int = 10) -> Finding:
    return Finding(
        id=f"DEF-{line_start}",
        title=title,
        category="defect",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="sample.py", line_start=line_start, line_end=line_start),
        source_engine="defect",
        rule_id="PRINT-DEBUG",
    )


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
