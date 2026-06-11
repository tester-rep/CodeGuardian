"""TestDetector — identifies testing frameworks and configuration."""

from pathlib import Path

TEST_FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "pytest": [
        "conftest.py",
        "pytest.ini",
        "pyproject.toml",  # Could have [tool.pytest]
        "tox.ini",
        "setup.cfg",
    ],
    "unittest": [],  # Built-in, hard to detect without scanning
    "junit": ["*Test.java", "*Tests.java"],
    "testng": ["testng.xml"],
    "jest": ["jest.config.*", "__tests__"],
    "mocha": ["*.spec.js", "*.test.js", "test/"],
    "go-test": ["*_test.go"],
    "catch2": ["*Test.cpp", "*_test.cpp"],
}


class TestDetector:
    """Detect testing frameworks from project structure."""

    def detect(self, root: Path) -> list[str]:
        found: list[str] = []

        for framework, patterns in TEST_FRAMEWORK_PATTERNS.items():
            if not patterns:
                # Check by convention-based naming
                if framework == "pytest":
                    if any(root.rglob("test_*.py")):
                        found.append(framework)
                elif framework == "jest":
                    pkg = root / "package.json"
                    if pkg.exists() and '"jest"' in pkg.read_text(encoding="utf-8"):
                        found.append(framework)
                elif framework == "go-test":
                    if any(root.rglob("*_test.go")):
                        found.append(framework)
                elif framework == "junit":
                    if any(root.rglob("*Test.java")):
                        found.append(framework)
                continue

            matched = False
            for pattern in patterns:
                if "*" in pattern:
                    if list(root.glob(pattern)):
                        matched = True
                        break
                elif (root / pattern).exists():
                    matched = True
                    break

            if matched:
                found.append(framework)

        return found
