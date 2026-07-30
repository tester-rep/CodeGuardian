"""Tests for rule registry, filtering, and baseline support."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import BARE_EXCEPT, PRINT_DEBUG
from codeguardian.engines.rule_helpers import RuleHit
from codeguardian.engines.rule_registry import (
    apply_baseline,
    filter_rule_hits,
    get_rules_for_engine,
)
from codeguardian.engines.security_engine import EVAL_USAGE, SQL_INJECTION_RISK, SecurityEngine
from codeguardian.models.common import Location
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding


def test_load_rules_config_from_toml() -> None:
    config_text = """
[scan]
review_mode = "ai_off"

[rules]
enabled = ["SQL-INJECTION-RISK"]
disabled = ["PRINT-DEBUG"]
include_tags = ["sql"]
exclude_tags = ["cleanup"]
min_severity = "high"
baseline_path = ".codeguardian/latest.json"
"""

    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "codeguardian.toml"
        config_path.write_text(config_text.strip() + "\n", encoding="utf-8")

        config = load_app_config(str(config_path))

    assert config.scan.review_mode == "ai_off"
    assert config.rules.enabled == ["SQL-INJECTION-RISK"]
    assert config.rules.disabled == ["PRINT-DEBUG"]
    assert config.rules.include_tags == ["sql"]
    assert config.rules.exclude_tags == ["cleanup"]
    assert config.rules.min_severity == Severity.HIGH
    assert config.rules.baseline_path == ".codeguardian/latest.json"


def test_rule_registry_exposes_registered_rules() -> None:
    security_rule_ids = {rule.rule_id for rule in get_rules_for_engine("security")}
    defect_rule_ids = {rule.rule_id for rule in get_rules_for_engine("defect")}

    assert "SQL-INJECTION-RISK" in security_rule_ids
    assert "EVAL-USAGE" in security_rule_ids
    assert "BARE-EXCEPT" in defect_rule_ids
    assert "PRINT-DEBUG" in defect_rule_ids


def test_filter_rule_hits_respects_rule_ids_tags_and_severity() -> None:
    config = load_app_config(None)
    config.rules.enabled = ["SQL-INJECTION-RISK", "EVAL-USAGE", "PRINT-DEBUG"]
    config.rules.disabled = ["EVAL-USAGE"]
    config.rules.include_tags = ["sql", "logging"]
    config.rules.exclude_tags = ["logging"]
    config.rules.min_severity = Severity.HIGH

    hits = [
        RuleHit(SQL_INJECTION_RISK, "sample.py", 1, 1, language="python"),
        RuleHit(EVAL_USAGE, "sample.py", 2, 2, language="python"),
        RuleHit(PRINT_DEBUG, "sample.py", 3, 3, language="python"),
        RuleHit(BARE_EXCEPT, "sample.py", 4, 4, language="python"),
    ]

    filtered = filter_rule_hits(hits, config.rules)

    assert [hit.rule.rule_id for hit in filtered] == ["SQL-INJECTION-RISK"]


def test_apply_baseline_filters_existing_findings() -> None:
    baseline_payload = {
        "findings": [
            {
                "rule_id": "SQL-INJECTION-RISK",
                "location": {
                    "file_path": "sample.py",
                    "line_start": 7,
                    "line_end": 7,
                },
            }
        ]
    }

    with TemporaryDirectory() as tmpdir:
        baseline_path = Path(tmpdir) / "baseline.json"
        baseline_path.write_text(json.dumps(baseline_payload), encoding="utf-8")

        findings = [
            Finding(
                id="SEC-001",
                title="SQL injection",
                category="security",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=Location(file_path="sample.py", line_start=7, line_end=7),
                source_engine="security",
                rule_id="SQL-INJECTION-RISK",
            ),
            Finding(
                id="SEC-002",
                title="Eval usage",
                category="security",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                location=Location(file_path="sample.py", line_start=9, line_end=9),
                source_engine="security",
                rule_id="EVAL-USAGE",
            ),
        ]

        filtered = apply_baseline(findings, baseline_path)

    assert [finding.rule_id for finding in filtered] == ["EVAL-USAGE"]


async def test_security_engine_respects_rule_selection() -> None:
    source = """
import hashlib
import subprocess


def run(command):
    subprocess.run(command, shell=True)
    hashlib.md5(b"demo")
"""


    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")

        config = load_app_config(None)
        config.rules.enabled = ["COMMAND-INJECTION-RISK"]
        ctx = ScanContext(project_root=str(root), config=config)
        result = await SecurityEngine().analyze(ctx)


    assert {finding.rule_id for finding in result.findings} == {"COMMAND-INJECTION-RISK"}
