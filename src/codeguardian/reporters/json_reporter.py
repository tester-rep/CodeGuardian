"""JsonReporter — outputs machine-readable JSON report."""

import json
from datetime import UTC, datetime
from pathlib import Path

from codeguardian.models.report import ReportArtifact
from codeguardian.models.scan import ScanResult


class JsonReporter:
    """Generates a structured JSON report file."""

    def render(self, result: ScanResult, output_dir: Path | None) -> ReportArtifact | None:
        if output_dir is None:
            return None

        target = output_dir / "report.json"

        data = result.model_dump(mode="json")

        target.write_text(json.dumps(data, indent=2), encoding="utf-8")

        return ReportArtifact(format="json", path=str(target),
                           size_bytes=target.stat().st_size,
                           generated_at=datetime.now(UTC).isoformat())

