"""FrameworkDetector — identifies application frameworks."""

from pathlib import Path

FRAMEWORK_INDICATORS: dict[str, list[str]] = {
    "django": ["manage.py"],
    "flask": [],  # Hard to detect without imports analysis
    "fastapi": [],
    "spring-like": ["pom.xml", "build.gradle"],
    "express": ["package.json"],  # Node.js generic
    "gin-gonic": ["go.mod"],
    "rails": ["Gemfile"],
    "laravel": ["composer.json", "artisan"],
    "next.js": ["next.config.js", "next.config.mjs", "next.config.ts"],
    "vue": ["vue.config.js", "vite.config.ts"],
    "react": [],  # Detected via package.json dependencies
}


class FrameworkDetector:
    """Detect web/application frameworks from project structure."""

    def detect(self, root: Path) -> list[str]:
        frameworks: list[str] = []

        for framework, indicators in FRAMEWORK_INDICATORS.items():
            if indicators:
                if all((root / ind).exists() for ind in indicators):
                    frameworks.append(framework)
            else:
                # For frameworks without strong file indicators,
                # we'll defer to AST-based detection later
                pass

        # Generic checks
        if (root / "package.json").exists():
            frameworks.append("nodejs-like")

        # C# / .NET framework detection
        frameworks.extend(self._detect_dotnet_frameworks(root))

        return frameworks

    def _detect_dotnet_frameworks(self, root: Path) -> list[str]:
        """Detect .NET/C# frameworks from .csproj and solution files."""
        frameworks: list[str] = []
        csproj_files = list(root.rglob("*.csproj"))

        if not csproj_files and not list(root.glob("*.sln")):
            return frameworks

        frameworks.append("dotnet")

        # Parse .csproj for framework references
        for csproj in csproj_files[:5]:  # Limit to avoid scanning massive mono-repos
            try:
                content = csproj.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            content_lower = content.lower()

            if "microsoft.aspnetcore" in content_lower or "microsoft.net.sdk.web" in content_lower:
                if "aspnet-core" not in frameworks:
                    frameworks.append("aspnet-core")

            if "microsoft.entityframeworkcore" in content_lower or "entityframework" in content_lower:
                if "entity-framework" not in frameworks:
                    frameworks.append("entity-framework")

            if "microsoft.net.sdk.blazorwebassembly" in content_lower or "blazor" in content_lower:
                if "blazor" not in frameworks:
                    frameworks.append("blazor")

            if "wpf" in content_lower or "microsoft.net.sdk.windowsdesktop" in content_lower:
                if "wpf" not in frameworks:
                    frameworks.append("wpf")

            if "xunit" in content_lower:
                if "xunit" not in frameworks:
                    frameworks.append("xunit")
            elif "nunit" in content_lower:
                if "nunit" not in frameworks:
                    frameworks.append("nunit")
            elif "mstest" in content_lower:
                if "mstest" not in frameworks:
                    frameworks.append("mstest")

        return frameworks
