"""SarifReporter — outputs SARIF 2.1.0 format for CI/CD integration.

SARIF (Static Analysis Results Interchange Format) is the standard format
supported by GitHub Code Scanning, Azure DevOps, GitLab SAST, and other
security/quality platforms.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from codeguardian.models.report import ReportArtifact
from codeguardian.models.scan import ScanResult


# SARIF severity mapping
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# SARIF confidence mapping (to security-severity for GitHub)
_CONFIDENCE_TO_PRECISION = {
    "high": "very-high",
    "medium": "high",
    "low": "medium",
}


class SarifReporter:
    """Generates a SARIF 2.1.0 report file."""

    def render(self, result: ScanResult, output_dir: Path | None) -> ReportArtifact | None:
        if output_dir is None:
            return None

        target = output_dir / "report.sarif"
        sarif = self._build_sarif(result)
        target.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")

        return ReportArtifact(
            format="sarif",
            path=str(target),
            size_bytes=target.stat().st_size,
            generated_at=datetime.now(UTC).isoformat(),
        )

    def _build_sarif(self, result: ScanResult) -> dict:
        """Build complete SARIF 2.1.0 document."""
        # Collect all unique rules across findings
        rules_map: dict[str, dict] = {}
        results_list: list[dict] = []

        all_findings = list(result.findings) + list(result.supplementary_findings)

        for finding in all_findings:
            rule_id = finding.rule_id or finding.id
            # Register rule
            if rule_id not in rules_map:
                rules_map[rule_id] = self._build_rule(finding)

            # Build result
            results_list.append(self._build_result(finding, rule_id))

        # Build the run
        run = {
            "tool": {
                "driver": {
                    "name": "CodeGuardian",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/codeguardian/cli",
                    "rules": list(rules_map.values()),
                },
            },
            "results": results_list,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "startTimeUtc": result.started_at,
                    "endTimeUtc": result.finished_at,
                }
            ],
        }

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [run],
        }

    @staticmethod
    def _build_rule(finding) -> dict:
        """Build SARIF rule descriptor from a Finding."""
        rule_id = finding.rule_id or finding.id
        rule = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {
                "text": finding.title,
            },
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning"),
            },
            "properties": {
                "tags": finding.tags or [finding.category],
                "security-severity": _severity_score(finding.severity.value),
                "precision": _CONFIDENCE_TO_PRECISION.get(finding.confidence.value, "medium"),
            },
        }

        if finding.fix_suggestion:
            rule["help"] = {
                "text": finding.fix_suggestion,
            }

        return rule

    @staticmethod
    def _build_result(finding, rule_id: str) -> dict:
        """Build SARIF result from a Finding."""
        result: dict = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning"),
            "message": {
                "text": finding.title,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.location.line_start or 1,
                            "endLine": finding.location.line_end or finding.location.line_start or 1,
                        },
                    },
                }
            ],
            "properties": {
                "risk_priority": finding.risk_priority,
                "blocks_release": finding.blocks_release,
                "evidence_level": finding.evidence_level,
                "category": finding.category,
                "source_engine": finding.source_engine,
            },
        }

        # Add fix suggestion
        if finding.fix_suggestion:
            result["fixes"] = [
                {
                    "description": {
                        "text": finding.fix_suggestion,
                    },
                }
            ]

        # Add root cause as related locations or properties
        if finding.root_cause:
            result["properties"]["root_cause"] = finding.root_cause

        # Add code flow from evidences (if available)
        if finding.evidences:
            snippets = []
            for evidence in finding.evidences[:3]:
                if hasattr(evidence, "content") and evidence.content:
                    snippets.append(evidence.content[:200])
            if snippets:
                result["properties"]["evidence_snippets"] = snippets

        return result


def _severity_score(severity: str) -> str:
    """Map severity to GitHub security-severity score (0-10 string)."""
    scores = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }
    return scores.get(severity, "5.0")
