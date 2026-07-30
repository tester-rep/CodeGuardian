"""Diff service for comparing snapshots or Git refs with PR-style scope semantics."""

from __future__ import annotations

import asyncio
import io
import re
import subprocess
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from codeguardian.config.loader import load_app_config
from codeguardian.core.orchestrator import Orchestrator
from codeguardian.engines.rule_registry import finding_signature
from codeguardian.models.metric import Metric
from codeguardian.models.scan import DiffResult, ScanRequest, ScanResult

if TYPE_CHECKING:
    from codeguardian.models.finding import Finding


_CONFIG_FILENAMES = ("codeguardian.toml", ".codeguardian.toml")
_HOTSPOT_MIN_COMMITS = 3
_HOTSPOT_MIN_CHANGED_LINES = 20
_WHITESPACE_RE = re.compile(r"\s+")


class DiffService:
    """Compare scan results or Git refs and summarize regressions."""

    def compare(
        self,
        base: ScanResult,
        target: ScanResult,
        *,
        semantic_match: bool = False,
        changed_files: list[str] | None = None,
        comparison_mode: str = "snapshot",
        base_label: str | None = None,
        target_label: str | None = None,
        merge_base: str | None = None,
        touched_hotspots: list[str] | None = None,
    ) -> DiffResult:
        filtered_base_findings = self._filter_findings(base.findings, changed_files)
        filtered_target_findings = self._filter_findings(target.findings, changed_files)
        key_builder = self._semantic_finding_key if semantic_match else finding_signature

        base_by_signature = {key_builder(finding): finding for finding in filtered_base_findings}
        target_by_signature = {key_builder(finding): finding for finding in filtered_target_findings}

        new_keys = [key for key in target_by_signature if key not in base_by_signature]
        resolved_keys = [key for key in base_by_signature if key not in target_by_signature]

        return DiffResult(
            comparison_mode=comparison_mode,
            base_label=base_label,
            target_label=target_label,
            merge_base=merge_base,
            changed_files=changed_files or [],
            touched_hotspots=touched_hotspots or [],
            base_score=base.project_profile.overall_score,
            target_score=target.project_profile.overall_score,
            score_delta=round(target.project_profile.overall_score - base.project_profile.overall_score, 1),
            new_findings=[target_by_signature[key] for key in new_keys],
            resolved_findings=[base_by_signature[key] for key in resolved_keys],
            regression_metrics=self._metric_deltas(base, target),
        )

    def compare_git_refs(self, project_root: Path, base_ref: str, target_ref: str) -> DiffResult:
        merge_base = self._resolve_merge_base(project_root, base_ref, target_ref)
        changed_files = self._resolve_changed_files(project_root, merge_base or base_ref, target_ref)
        touched_hotspots = self._resolve_touched_hotspots(project_root, changed_files)

        with TemporaryDirectory(prefix="codeguardian-diff-") as tmpdir:
            temp_root = Path(tmpdir)
            base_root = temp_root / "base"
            target_root = temp_root / "target"
            self._export_git_ref(project_root, base_ref, base_root)
            self._export_git_ref(project_root, target_ref, target_root)
            base_result = self._scan_tree(base_root)
            target_result = self._scan_tree(target_root)

        return self.compare(
            base_result,
            target_result,
            semantic_match=True,
            changed_files=changed_files,
            comparison_mode="git",
            base_label=base_ref,
            target_label=target_ref,
            merge_base=merge_base,
            touched_hotspots=touched_hotspots,
        )

    @staticmethod
    def load_result(path: Path) -> ScanResult:
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))

    def _scan_tree(self, root: Path) -> ScanResult:
        config_path = self._resolve_config_path(root)
        config = load_app_config(str(config_path) if config_path is not None else None)
        request = ScanRequest(
            project_path=root,
            report_formats=[],
            review_mode=config.scan.review_mode,
            dimensions=config.scan.dimensions,
            languages=config.scan.languages,
        )
        return asyncio.run(Orchestrator(config).run_scan(request))

    @staticmethod
    def _resolve_config_path(root: Path) -> Path | None:
        for filename in _CONFIG_FILENAMES:
            candidate = root / filename
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _filter_findings(findings: list[Finding], changed_files: list[str] | None) -> list[Finding]:

        if not changed_files:
            return list(findings)
        changed = {path.replace("\\", "/") for path in changed_files}
        return [
            finding
            for finding in findings
            if finding.location.file_path in {"project", ""} or finding.location.file_path.replace("\\", "/") in changed
        ]

    @staticmethod
    def _semantic_finding_key(finding: Finding) -> str:

        title = _WHITESPACE_RE.sub(" ", (finding.title or "").strip().lower())
        return "::".join(
            [
                (finding.category or "").strip().lower(),
                (finding.rule_id or "").strip().lower(),
                finding.location.file_path.replace("\\", "/").strip().lower(),
                title,
            ]
        )

    def _metric_deltas(self, base: ScanResult, target: ScanResult) -> list[Metric]:
        base_metrics = self._project_metrics(base)
        target_metrics = self._project_metrics(target)

        deltas: list[Metric] = []
        for metric_name in sorted(set(base_metrics) | set(target_metrics)):
            base_metric = base_metrics.get(metric_name)
            target_metric = target_metrics.get(metric_name)
            base_value = base_metric.value if base_metric is not None else 0.0
            target_value = target_metric.value if target_metric is not None else 0.0
            if abs(target_value - base_value) < 0.001:
                continue

            template = target_metric or base_metric
            deltas.append(
                Metric(
                    target_id="project",
                    target_type="project",
                    metric_name=metric_name,
                    value=round(target_value - base_value, 1),
                    unit=template.unit if template is not None else None,
                    source_engine="diff",
                    dimension=template.dimension if template is not None else None,
                    extra={
                        "base": round(base_value, 1),
                        "target": round(target_value, 1),
                    },
                )
            )

        return deltas

    @staticmethod
    def _project_metrics(result: ScanResult) -> dict[str, Metric]:
        return {
            metric.metric_name: metric
            for metric in result.metrics
            if metric.target_id == "project"
        }

    def _resolve_merge_base(self, project_root: Path, base_ref: str, target_ref: str) -> str | None:
        result = self._run_git(project_root, ["merge-base", base_ref, target_ref])
        if result is None:
            return None
        value = result.stdout.strip()
        return value or None

    def _resolve_changed_files(self, project_root: Path, base_ref: str, target_ref: str) -> list[str]:
        result = self._run_git(
            project_root,
            ["diff", "--name-only", "--diff-filter=ACMR", base_ref, target_ref, "--"],
        )
        if result is None:
            return []
        return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]

    def _resolve_touched_hotspots(self, project_root: Path, changed_files: list[str]) -> list[str]:
        if not changed_files:
            return []

        result = self._run_git(
            project_root,
            ["log", "--date-order", "--numstat", "--format=__CG_COMMIT__%H|%ae|%ct", "--", *changed_files],
        )
        if result is None:
            return []

        stats: dict[str, dict[str, int]] = {}
        touched_in_commit: set[str] = set()
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("__CG_COMMIT__"):
                touched_in_commit = set()
                continue

            parts = raw_line.split("\t")
            if len(parts) < 3:
                continue
            file_path = parts[2].strip().replace("\\", "/")
            entry = stats.setdefault(file_path, {"changed_lines": 0, "commit_count": 0})
            entry["changed_lines"] += _coerce_int(parts[0]) + _coerce_int(parts[1])
            if file_path not in touched_in_commit:
                entry["commit_count"] += 1
                touched_in_commit.add(file_path)

        hotspots = [
            file_path
            for file_path, entry in stats.items()
            if entry["commit_count"] >= _HOTSPOT_MIN_COMMITS or entry["changed_lines"] >= _HOTSPOT_MIN_CHANGED_LINES
        ]
        return sorted(hotspots)

    def _export_git_ref(self, project_root: Path, ref: str, destination: Path) -> None:
        result = subprocess.run(
            ["git", "-C", str(project_root), "archive", "--format=tar", ref],
            capture_output=True,
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(stderr or f"Failed to export git ref: {ref}")

        destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
            for member in archive.getmembers():
                member_path = destination / member.name
                if not member_path.resolve().is_relative_to(destination.resolve()):
                    raise ValueError(f"Unsafe archive entry detected: {member.name}")
            archive.extractall(destination, filter="data")


    @staticmethod
    def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        return result



def _coerce_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0
