"""Report model — output artifact metadata."""

from pydantic import BaseModel


class ReportArtifact(BaseModel):
    """Metadata about a generated report file."""

    format: str  # terminal / json / html / sarif / pdf
    path: str  # File system path to the report
    size_bytes: int = 0
    generated_at: str | None = None  # ISO timestamp
