"""ProjectDetector — unified entry point for project detection."""

from pathlib import Path

from pydantic import BaseModel, Field

from codeguardian.detectors.build_detector import BuildDetector
from codeguardian.detectors.framework_detector import FrameworkDetector
from codeguardian.detectors.language_detector import LanguageDetector
from codeguardian.detectors.test_detector import TestDetector


class ProjectDetectionResult(BaseModel):
    """Result of project detection."""

    repo_type: str = "single"  # single / monorepo
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    build_systems: list[str] = Field(default_factory=list)
    test_frameworks: list[str] = Field(default_factory=list)
    is_git_repo: bool = False


class ProjectDetector:
    """Detects project characteristics: language, framework, build system, test setup."""

    def detect(self, root: Path) -> ProjectDetectionResult:
        languages = LanguageDetector().detect(root)
        frameworks = FrameworkDetector().detect(root)
        build_systems = BuildDetector().detect(root)
        test_frameworks = TestDetector().detect(root)
        is_git_repo = (root / ".git").is_dir()

        # Detect monorepo (simplified heuristic)
        repo_type = "single"
        if is_git_repo:
            # Check for common monorepo indicators
            workspaces_file = root / "pnpm-workspace.yaml"
            if not workspaces_file.exists():
                workspaces_file = root / "lerna.json"
            if workspaces_file.exists():
                repo_type = "monorepo"

        return ProjectDetectionResult(
            repo_type=repo_type,
            languages=languages,
            frameworks=frameworks,
            build_systems=build_systems,
            test_frameworks=test_frameworks,
            is_git_repo=is_git_repo,
        )
