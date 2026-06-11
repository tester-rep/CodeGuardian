"""Core domain entities: File, Class, Function, Module."""

from pydantic import BaseModel, Field


class FileEntity(BaseModel):
    """Represents a source code file."""

    path: str  # Relative to project root
    language: str
    loc: int = 0  # Lines of code (total)
    sloc: int = 0  # Source lines of code (non-empty, non-comment)
    comment_lines: int = 0
    blank_lines: int = 0

    @property
    def extension(self) -> str:
        return self.path.rsplit(".", 1)[-1] if "." in self.path else ""


class ClassEntity(BaseModel):
    """Represents a class/interface/enum definition."""

    name: str
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    kind: str = "class"  # class / interface / enum / record / trait
    methods: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)

    # OO metrics (computed by OO Design Analyzer)
    wmc: int = 0  # Weighted Method Complexity
    dit: int = 0  # Depth of Inheritance Tree
    noc: int = 0  # Number of Children
    cbo: int = 0  # Coupling Between Objects
    rfc: int = 0  # Response For a Class
    lcom: float = 0.0  # Lack of Cohesion of Methods
    ca: int = 0  # Afferent Coupling
    ce: int = 0  # Efferent Coupling


class FunctionEntity(BaseModel):
    """Represents a function/method/procedure."""

    name: str
    signature: str | None = None
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    class_or_module: str | None = None
    is_method: bool = False
    is_async: bool = False

    # Complexity metrics (computed by Complexity Analyzer)
    cyclomatic_complexity: int = 0  # McCabe CC
    cognitive_complexity: int = 0
    nesting_depth: int = 0
    param_count: int = 0
    loc: int = 0


class ModuleEntity(BaseModel):
    """Represents a logical module (package/library/directory)."""

    name: str
    path: str  # Directory path relative to project root
    module_type: str = "package"  # package / library / service
    file_paths: list[str] = Field(default_factory=list)
    language: str | None = None
