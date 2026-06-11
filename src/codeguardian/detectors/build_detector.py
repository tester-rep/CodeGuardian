"""BuildDetector — identifies build systems."""

from pathlib import Path

BUILD_SYSTEM_FILES: dict[str, list[str]] = {
    "maven": ["pom.xml"],
    "gradle": ["build.gradle", "build.gradle.kts"],
    "npm": ["package.json"],
    "pnpm": ["pnpm-lock.yaml", "pnpm-workspace.yaml"],
    "yarn": ["yarn.lock"],
    "pip": ["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"],
    "poetry": ["pyproject.toml", "poetry.lock"],
    "go-mod": ["go.mod"],
    "cargo": ["Cargo.toml"],
    "cmake": ["CMakeLists.txt"],
    "makefile": ["Makefile"],
    "dotnet": ["*.csproj", "*.sln"],
    "meson": ["meson.build"],
}


class BuildDetector:
    """Detect build/package management systems."""

    def detect(self, root: Path) -> list[str]:
        build_tools: list[str] = []
        detected: set[str] = set()

        for tool, patterns in BUILD_SYSTEM_FILES.items():
            for pattern in patterns:
                if pattern.startswith("*"):
                    # Glob pattern
                    matches = list(root.glob(pattern))
                    if matches:
                        if tool not in detected:
                            build_tools.append(tool)
                            detected.add(tool)
                        break
                else:
                    if (root / pattern).exists() and tool not in detected:
                        build_tools.append(tool)
                        detected.add(tool)

        # Special case: pyproject.toml could be poetry or pip or setuptools
        if (root / "pyproject.toml").exists():
            content = (root / "pyproject.toml").read_text(encoding="utf-8")
            if "[tool.poetry]" in content and "poetry" not in detected:
                build_tools.append("poetry")

        return build_tools
