"""Relation model — relationships between entities."""

from pydantic import BaseModel, Field


class Relation(BaseModel):
    """A directed relationship between two entities."""

    source_id: str  # Source entity identifier
    target_id: str  # Target entity identifier
    relation_type: str  # "calls" / "depends_on" / "inherits" / "covers" / "modifies" / "data_flows_to"
    metadata: dict[str, str] = Field(default_factory=dict)
    weight: float = 1.0  # Strength/importance of this relation
