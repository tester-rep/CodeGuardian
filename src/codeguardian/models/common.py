"""Common model components shared by other models."""

from pydantic import BaseModel


class Location(BaseModel):
    """Source code location of an entity or finding."""

    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
