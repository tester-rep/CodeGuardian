"""StructureEngine — extracts file/class/function/module entities from the project.

Dimension 1: Scale Analyzer (partial)
Also provides structural data for other engines.
"""

from pathlib import Path

from codeguardian.core.context import ScanContext
from codeguardian.languages import (
    is_language_enabled,
    language_from_extension,
    sort_paths_by_language_priority,
)
from codeguardian.models.entity import ClassEntity, FileEntity, FunctionEntity, ModuleEntity
from codeguardian.models.metric import Metric, MetricNames
from codeguardian.models.scan import EngineResult
from codeguardian.parsers import get_parser
from codeguardian.utils.ignore import should_ignore


class StructureEngine:
    """Discovers files, calculates basic size metrics (LOC/SLOC)."""

    name = "structure"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root)
        files: list[FileEntity] = []
        functions: list[FunctionEntity] = []
        classes: list[ClassEntity] = []
        modules: list[ModuleEntity] = []
        total_loc = 0
        total_sloc = 0
        total_comment = 0
        total_blank = 0

        candidate_paths = [
            path
            for path in ctx.collect_candidate_files(root)
            if not should_ignore(path) and path.is_file() and not self._is_binary(path)
        ]


        for path in sort_paths_by_language_priority(candidate_paths):
            rel_path = str(path.relative_to(root)).replace("\\", "/")
            ext = path.suffix.lstrip(".") or "unknown"
            language = self._detect_language(ext)
            if not is_language_enabled(language, ctx.languages):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                loc = len(content.splitlines())
                sloc = self._count_sloc(content)
                comment_lines = self._count_comments(content)
                blank_lines = self._count_blank(content)

                total_loc += loc
                total_sloc += sloc
                total_comment += comment_lines
                total_blank += blank_lines

                file_entity = FileEntity(
                    path=rel_path,
                    language=language,
                    loc=loc,
                    sloc=sloc,
                    comment_lines=comment_lines,
                    blank_lines=blank_lines,
                )
                files.append(file_entity)

                parsed = self._parse_structure(path=path, root=root, language=language)
                functions.extend(parsed["functions"])
                classes.extend(parsed["classes"])
                modules.extend(parsed["modules"])
            except OSError:
                continue

        metrics = [
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.LOC,
                value=float(total_loc),
                unit="lines",
                source_engine=self.name,
                dimension="scale",
            ),
            Metric(
                target_id="project",
                target_type="project",
                metric_name=MetricNames.SLOC,
                value=float(total_sloc),
                unit="lines",
                source_engine=self.name,
                dimension="scale",
            ),
        ]

        return EngineResult(
            engine_name=self.name,
            files=files,
            functions=functions,
            classes=classes,
            modules=modules,
            metrics=metrics,
        )

    @staticmethod
    def _parse_structure(path: Path, root: Path, language: str) -> dict[str, list]:
        parser = get_parser(language)
        if parser is None:
            return {"functions": [], "classes": [], "modules": []}

        parsed = parser.parse_file(path, root)
        return {
            "functions": [
                FunctionEntity(
                    name=item.name,
                    signature=item.signature,
                    file_path=item.file_path,
                    start_line=item.start_line,
                    end_line=item.end_line,
                    class_or_module=item.class_or_module,
                    is_method=item.is_method,
                    is_async=item.is_async,
                    param_count=item.param_count,
                    loc=item.loc,
                )
                for item in parsed.functions
            ],
            "classes": [
                ClassEntity(
                    name=item.name,
                    file_path=item.file_path,
                    start_line=item.start_line,
                    end_line=item.end_line,
                    kind=item.kind,
                    methods=item.methods,
                    fields=item.fields,
                )
                for item in parsed.classes
            ],
            "modules": [
                ModuleEntity(
                    name=item.name,
                    path=item.path,
                    module_type=item.module_type,
                    file_paths=item.file_paths,
                    language=item.language,
                )
                for item in parsed.modules
            ],
        }

    @staticmethod
    def _detect_language(ext: str) -> str:
        return language_from_extension(ext) or ext.lower() or "text"

    @staticmethod
    def _is_binary(path: Path) -> bool:
        """Heuristic check for binary files."""
        binary_exts = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
            ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
            ".exe", ".dll", ".so", ".dylib", ".o", ".a",
            ".pyc", ".pyo", ".whl", ".egg-info",
            ".woff", ".woff2", ".ttf", ".eot",
            ".mp3", ".mp4", ".avi", ".mov", ".wav",
        }
        return path.suffix.lower() in binary_exts

    @staticmethod
    def _count_sloc(content: str) -> int:
        count = 0
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            count += 1
        return count

    @staticmethod
    def _count_comments(content: str) -> int:
        count = 0
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#") or stripped.startswith("//"):
                count += 1
        return count

    @staticmethod
    def _count_blank(content: str) -> int:
        return sum(1 for line in content.splitlines() if not line.strip())
