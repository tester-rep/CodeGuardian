"""Shared rule registry, selector, and baseline helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from codeguardian.config.schema import RulesConfig
from codeguardian.engines.rule_helpers import RuleHit, RuleSpec
from codeguardian.models.enums import Severity
from codeguardian.models.finding import Finding

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_RULES_BY_ENGINE: dict[str, tuple[RuleSpec, ...]] = {}
_RULES_BY_ID: dict[str, RuleSpec] = {}


def register_rules(engine_name: str, rules: tuple[RuleSpec, ...] | list[RuleSpec]) -> tuple[RuleSpec, ...]:
    """Register a stable rule set for an engine and return it unchanged."""
    normalized = tuple(rules)
    existing = _RULES_BY_ENGINE.get(engine_name)
    if existing is not None:
        return existing

    for rule in normalized:
        registered = _RULES_BY_ID.get(rule.rule_id)
        if registered is not None and registered != rule:
            msg = f"Rule id already registered with different metadata: {rule.rule_id}"
            raise ValueError(msg)
        _RULES_BY_ID[rule.rule_id] = rule

    _RULES_BY_ENGINE[engine_name] = normalized
    return normalized


def get_rules_for_engine(engine_name: str) -> tuple[RuleSpec, ...]:
    """Return registered rules for a given engine."""
    return _RULES_BY_ENGINE.get(engine_name, ())


def get_registered_rule(rule_id: str) -> RuleSpec | None:
    """Return a registered rule by rule id."""
    return _RULES_BY_ID.get(rule_id)


def list_registered_rules() -> tuple[RuleSpec, ...]:
    """Return all registered rules ordered by registration."""
    return tuple(_RULES_BY_ID.values())


def filter_rule_hits(hits: list[RuleHit], config: RulesConfig) -> list[RuleHit]:
    """Apply rule selection filters to raw rule hits."""
    return [hit for hit in hits if is_rule_enabled(hit.rule, config, hit.language)]


def is_rule_enabled(rule: RuleSpec, config: RulesConfig, language: str | None = None) -> bool:
    """Check whether a rule is enabled for the current config and language."""
    enabled_rules = _lowered_set(config.enabled)
    disabled_rules = _lowered_set(config.disabled)
    include_tags = _lowered_set(config.include_tags)
    exclude_tags = _lowered_set(config.exclude_tags)
    rule_id = rule.rule_id.lower()
    rule_tags = {tag.lower() for tag in rule.tags}

    if enabled_rules and rule_id not in enabled_rules:
        return False
    if rule_id in disabled_rules:
        return False
    if include_tags and not (rule_tags & include_tags):
        return False
    if rule_tags & exclude_tags:
        return False
    if config.min_severity is not None and SEVERITY_ORDER[rule.severity] < SEVERITY_ORDER[config.min_severity]:
        return False
    if language and rule.applicable_languages:
        normalized_language = language.lower()
        if normalized_language not in {item.lower() for item in rule.applicable_languages}:
            return False
    return True


def apply_baseline(findings: list[Finding], baseline_path: Path | None) -> list[Finding]:
    """Remove findings that already exist in a baseline report."""
    signatures = load_baseline_signatures(baseline_path)
    if not signatures:
        return findings
    return [finding for finding in findings if finding_signature(finding) not in signatures]


def load_baseline_signatures(baseline_path: Path | None) -> set[str]:
    """Load finding signatures from a baseline report JSON file."""
    if baseline_path is None or not baseline_path.exists():
        return set()

    try:
        raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    findings_payload = _extract_findings(raw)
    signatures: set[str] = set()
    for item in findings_payload:
        signature = _signature_from_payload(item)
        if signature:
            signatures.add(signature)
    return signatures


def finding_signature(finding: Finding) -> str:
    """Build a stable comparison key for a finding."""
    return "::".join(
        [
            finding.rule_id or "",
            finding.location.file_path,
            str(finding.location.line_start or 0),
            str(finding.location.line_end or finding.location.line_start or 0),
        ]
    )


def _signature_from_payload(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    rule_id = item.get("rule_id")
    location = item.get("location")
    if not isinstance(rule_id, str) or not isinstance(location, dict):
        return None

    file_path = location.get("file_path")
    line_start = location.get("line_start", 0)
    line_end = location.get("line_end", line_start)
    if not isinstance(file_path, str):
        return None
    return "::".join([rule_id, file_path, str(line_start or 0), str(line_end or line_start or 0)])


def _extract_findings(raw: Any) -> list[Any]:
    if isinstance(raw, dict):
        findings = raw.get("findings")
        if isinstance(findings, list):
            return findings
    if isinstance(raw, list):
        return raw
    return []


def _lowered_set(values: list[str] | None) -> set[str]:
    if not values:
        return set()
    return {value.lower() for value in values if value.strip()}
