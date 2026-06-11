"""GitEvolutionEngine — analyzes Git history for evolution metrics.

MVP scope:
- Project-level commit / author / churn summary
- File-level churn metrics
- Hotspot and ownership-risk findings
"""

from __future__ import annotations

import subprocess
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

from codeguardian.core.context import ScanContext
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric, MetricNames
from codeguardian.models.scan import EngineResult

_COMMIT_MARKER = "__CG_COMMIT__"
_HOTSPOT_MIN_COMMITS = 3
_HOTSPOT_MIN_CHANGED_LINES = 20
_OWNERSHIP_MIN_COMMITS = 3
_OWNERSHIP_MIN_SHARE = 0.8


@dataclass(slots=True)
class FileHistory:
    file_path: str
    changed_lines: int = 0
    commit_count: int = 0
    author_commits: Counter[str] = field(default_factory=Counter)

    @property
    def author_count(self) -> int:
        return len(self.author_commits)

    @property
    def top_owner(self) -> tuple[str | None, float]:
        if self.commit_count <= 0 or not self.author_commits:
            return (None, 0.0)
        author, commits = self.author_commits.most_common(1)[0]
        return author, round(commits / self.commit_count, 3)


class GitEvolutionEngine:
    """Analyzes Git history for churn, hotspots, and author distribution."""

    name = "git"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root)
        if not ctx.is_git_repo:
            return EngineResult(
                engine_name=self.name,
                warnings=["Not a Git repository — skipping Git analysis"],
            )

        try:
            stats = self._collect_history(root)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return EngineResult(engine_name=self.name, warnings=[f"Git analysis unavailable: {exc}"])
        except ValueError as exc:
            return EngineResult(engine_name=self.name, warnings=[str(exc)])

        metrics = self._build_metrics(stats)
        findings = self._build_findings(stats)
        return EngineResult(engine_name=self.name, metrics=metrics, findings=findings)

    def _collect_history(self, root: Path) -> dict[str, object]:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "log",
                "--date-order",
                "--numstat",
                f"--format={_COMMIT_MARKER}%H|%ae|%ct",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError(result.stderr.strip() or "Failed to read git history")

        authors: set[str] = set()
        timestamps: list[int] = []
        files: dict[str, FileHistory] = {}
        current_author: str | None = None
        touched_in_commit: set[str] = set()

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith(_COMMIT_MARKER):
                touched_in_commit = set()
                _, payload = line.split(_COMMIT_MARKER, maxsplit=1)
                parts = payload.split("|")
                if len(parts) != 3:
                    current_author = None
                    continue
                current_author = parts[1] or "unknown"
                authors.add(current_author)
                with suppress(ValueError):
                    timestamps.append(int(parts[2]))
                continue


            parts = raw_line.split("\t")
            if len(parts) < 3 or current_author is None:
                continue

            added = _coerce_diff_count(parts[0])
            deleted = _coerce_diff_count(parts[1])
            file_path = _normalize_git_path(parts[2])
            history = files.setdefault(file_path, FileHistory(file_path=file_path))
            history.changed_lines += added + deleted
            if file_path not in touched_in_commit:
                history.commit_count += 1
                history.author_commits[current_author] += 1
                touched_in_commit.add(file_path)

        if not timestamps and not files:
            raise ValueError("Git history is empty or unavailable")

        return {
            "commit_count": len(timestamps),
            "active_authors": len(authors),
            "timestamps": timestamps,
            "files": files,
        }

    def _build_metrics(self, stats: dict[str, object]) -> list[Metric]:
        commit_count = int(stats["commit_count"])
        active_authors = int(stats["active_authors"])
        timestamps = list(stats["timestamps"])
        files: dict[str, FileHistory] = stats["files"]  # type: ignore[assignment]

        churn_score = 0.0
        if timestamps:
            span_days = max(1, int((max(timestamps) - min(timestamps)) / 86400) + 1)
            churn_score = round(commit_count / span_days, 2)

        metrics = [
            Metric(
                target_id="project",
                target_type="project",
                metric_name="total_commits",
                value=float(commit_count),
                unit="commits",
                source_engine=self.name,
                dimension="evolution",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name="active_authors",
                value=float(active_authors),
                unit="authors",
                source_engine=self.name,
                dimension="evolution",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.CHURN_SCORE,
                value=churn_score,
                unit="commits/day",
                source_engine=self.name,
                dimension="evolution",
            ),
        ]

        for file_path, history in sorted(files.items()):
            _owner, owner_share = history.top_owner
            metrics.extend(
                [
                    Metric(
                        target_id=file_path,
                        target_type="file",
                        metric_name=MetricNames.CHURN_SCORE,
                        value=float(history.changed_lines),
                        unit="changed-lines",
                        source_engine=self.name,
                        dimension="evolution",
                        extra={"commit_count": history.commit_count},
                    ),
                    Metric(
                        target_id=file_path,
                        target_type="file",
                        metric_name="author_count",
                        value=float(history.author_count),
                        unit="authors",
                        source_engine=self.name,
                        dimension="evolution",
                    ),
                    Metric(
                        target_id=file_path,
                        target_type="file",
                        metric_name="ownership_share",
                        value=round(owner_share * 100.0, 1),
                        unit="%",
                        source_engine=self.name,
                        dimension="evolution",
                    ),
                ]
            )

        return metrics

    def _build_findings(self, stats: dict[str, object]) -> list[Finding]:
        files: dict[str, FileHistory] = stats["files"]  # type: ignore[assignment]
        findings: list[Finding] = []
        counter = 1

        hotspots = sorted(
            (
                history
                for history in files.values()
                if history.commit_count >= _HOTSPOT_MIN_COMMITS or history.changed_lines >= _HOTSPOT_MIN_CHANGED_LINES
            ),
            key=lambda history: (-history.changed_lines, -history.commit_count, history.file_path),
        )[:10]

        for history in hotspots:
            severity = Severity.HIGH if history.changed_lines >= 60 or history.commit_count >= 5 else Severity.MEDIUM
            findings.append(
                self._finding(
                    finding_id=f"EVO-{counter:03d}",
                    title=f"检测到热点文件: {history.file_path} (Hotspot file)",
                    rule_id="GIT-HOTSPOT",
                    severity=severity,
                    file_path=history.file_path,
                    detail=(
                        f"{history.file_path} 在 {history.commit_count} 次提交中变更了 {history.changed_lines} 行，"
                        "属于回归风险较高的热点文件。"
                    ),
                    fix_suggestion="在进行大改动前先稳定该文件，并优先围绕近期修改补充回归覆盖。",
                )
            )
            counter += 1

        ownership_risks = sorted(
            (
                history
                for history in files.values()
                if history.commit_count >= _OWNERSHIP_MIN_COMMITS and history.top_owner[1] >= _OWNERSHIP_MIN_SHARE
            ),
            key=lambda history: (-history.top_owner[1], -history.commit_count, history.file_path),
        )[:10]

        for history in ownership_risks:
            owner, owner_share = history.top_owner
            severity = Severity.HIGH if owner_share >= 0.95 and history.commit_count >= 5 else Severity.MEDIUM
            findings.append(
                self._finding(
                    finding_id=f"EVO-{counter:03d}",
                    title=f"代码归属集中风险: {history.file_path} (Ownership concentration)",
                    rule_id="OWNERSHIP-RISK",
                    severity=severity,
                    file_path=history.file_path,
                    detail=(
                        f"{owner or '单一作者'} 负责了 {history.file_path} 相关提交的 {owner_share * 100:.0f}%，"
                        "存在知识孤岛风险。"
                    ),
                    fix_suggestion="通过代码评审、结对维护或定向交接文档分散该文件的维护知识。",
                )
            )
            counter += 1

        return findings

    def _finding(
        self,
        finding_id: str,
        title: str,
        rule_id: str,
        severity: Severity,
        file_path: str,
        detail: str,
        fix_suggestion: str,
    ) -> Finding:
        return Finding(
            id=finding_id,
            title=title,
            category="maintainability",
            severity=severity,
            confidence=Confidence.HIGH,
            location=Location(file_path=file_path, line_start=1, line_end=1),
            source_engine=self.name,
            rule_id=rule_id,
            root_cause=detail,
            impact="频繁修改和知识集中会抬高回归风险，并增加后续变更的不确定性。",
            fix_suggestion=fix_suggestion,
            test_suggestion="为该文件最近活跃的路径补回归测试，并在后续变更中重点回归。",
            risk_priority="must-fix" if severity == Severity.HIGH else "should-fix",
        )


def _coerce_diff_count(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def _normalize_git_path(value: str) -> str:
    return value.strip().replace("\\", "/")
