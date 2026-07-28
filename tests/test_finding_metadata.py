"""Regression tests for Finding.metadata field.

Root cause guarded here: cross_function_engine / process_analyzer construct
``Finding(..., metadata={...})`` and impact_scorer / process_enricher read
``finding.metadata``. The Finding model previously had no ``metadata`` field,
so (a) constructor values were silently dropped (pydantic extra='ignore') and
(b) every ``.metadata`` read raised AttributeError, crashing the whole scan
during PCI enrichment.
"""

from __future__ import annotations

from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding


def _make_finding(**overrides) -> Finding:
    base = dict(
        id="X-1",
        title="t",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="a.py", line_start=1, line_end=1),
        source_engine="test",
    )
    base.update(overrides)
    return Finding(**base)


def test_metadata_field_exists_with_default_empty_dict():
    f = _make_finding()
    assert "metadata" in type(f).model_fields
    assert f.metadata == {}


def test_metadata_constructor_value_is_preserved():
    f = _make_finding(metadata={"resource_kind": "file", "acquirer": "app.foo"})
    assert f.metadata == {"resource_kind": "file", "acquirer": "app.foo"}


def test_metadata_model_copy_update_used_by_enrichers():
    """impact_scorer / process_enricher enrich via model_copy(update={'metadata': ...})."""
    f = _make_finding()
    enriched = f.model_copy(update={"metadata": {"impact_score": "50", "affected_callers": "7"}})
    assert enriched.metadata["impact_score"] == "50"
    assert enriched.metadata["affected_callers"] == "7"
    # Original untouched
    assert f.metadata == {}
