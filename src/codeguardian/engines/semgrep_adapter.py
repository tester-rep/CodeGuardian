"""Semgrep JSON output → RuleHit adapter.

Converts the raw JSON produced by ``semgrep --json`` into our internal
``RuleHit`` structure so the standard ``build_finding`` pipeline can
materialize Findings.

Semgrep rule IDs are dynamic (one per upstream rule), so we synthesize
``RuleSpec`` objects on the fly instead of going through the global rule
registry. ``RulesConfig`` filters (``disabled`` / ``min_severity`` /
``exclude_tags``) are honoured locally — see ``filter_hits``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codeguardian.config.schema import RulesConfig
from codeguardian.engines.rule_helpers import RuleHit, RuleSpec
from codeguardian.engines.rule_registry import SEVERITY_ORDER
from codeguardian.models.enums import Confidence, Severity

# Semgrep severity → our Severity
_SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "EXPERIMENT": Severity.INFO,
    "INVENTORY": Severity.INFO,
}

# Semgrep impact (CVSS-like) → confidence boost when present
_SEMGREP_CONFIDENCE_MAP: dict[str, Confidence] = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}


def parse_semgrep_results(
    payload: dict[str, Any],
    project_root: Path,
) -> list[RuleHit]:
    """Convert Semgrep ``--json`` payload into a list of ``RuleHit``.

    ``payload`` is the parsed JSON produced by ``semgrep scan --json``. The
    result of each rule match is normalized to project-relative POSIX paths.
    """
    hits: list[RuleHit] = []
    results = payload.get("results")
    if not isinstance(results, list):
        return hits

    root_resolved = project_root.resolve()

    for item in results:
        if not isinstance(item, dict):
            continue
        hit = _convert_one(item, root_resolved)
        if hit is not None:
            hits.append(hit)
    return hits


def filter_hits(hits: list[RuleHit], config: RulesConfig) -> list[RuleHit]:
    """Apply ``RulesConfig`` filters that make sense for dynamically-built rules.

    Semgrep rules are not in the global registry, so we cannot use
    ``filter_rule_hits``. We re-implement only the filters that don't require
    a static catalog: ``disabled``, ``exclude_tags``, ``min_severity``.
    The ``enabled`` allow-list and ``include_tags`` are intentionally NOT
    applied — they are designed for the curated local rule catalog.
    """
    disabled = {v.lower() for v in config.disabled if v.strip()}
    exclude_tags = {v.lower() for v in config.exclude_tags if v.strip()}
    min_sev = config.min_severity

    out: list[RuleHit] = []
    for hit in hits:
        rid = hit.rule.rule_id.lower()
        if rid in disabled:
            continue
        rule_tags = {tag.lower() for tag in hit.rule.tags}
        if rule_tags & exclude_tags:
            continue
        if min_sev is not None and SEVERITY_ORDER[hit.rule.severity] < SEVERITY_ORDER[min_sev]:
            continue
        out.append(hit)
    return out


def _convert_one(item: dict[str, Any], root_resolved: Path) -> RuleHit | None:
    check_id = item.get("check_id")
    path = item.get("path")
    if not isinstance(check_id, str) or not isinstance(path, str):
        return None

    start = item.get("start") if isinstance(item.get("start"), dict) else {}
    end = item.get("end") if isinstance(item.get("end"), dict) else {}
    line_start = _safe_int(start.get("line"), 1)
    line_end = _safe_int(end.get("line"), line_start)

    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}

    rule = _build_rule_spec(check_id, extra, metadata)
    rel_path = _to_project_relative(path, root_resolved)
    message = extra.get("message") if isinstance(extra.get("message"), str) else None

    # Pull through useful semgrep-specific metadata for the evidence record.
    hit_meta: dict[str, str | list[str]] = {}
    fix = extra.get("fix")
    if isinstance(fix, str):
        hit_meta["semgrep_fix"] = fix
    references = metadata.get("references") if isinstance(metadata.get("references"), list) else None
    if references:
        hit_meta["references"] = [str(r) for r in references if r]
    technology = metadata.get("technology") if isinstance(metadata.get("technology"), list) else None
    if technology:
        hit_meta["technology"] = [str(t) for t in technology if t]

    language = _infer_language(path, technology)

    return RuleHit(
        rule=rule,
        file_path=rel_path,
        line_start=line_start,
        line_end=line_end,
        message=message,
        language=language,
        metadata=hit_meta,
    )


def _build_rule_spec(check_id: str, extra: dict[str, Any], metadata: dict[str, Any]) -> RuleSpec:
    severity_label = str(extra.get("severity", "INFO")).upper()
    severity = _SEMGREP_SEVERITY_MAP.get(severity_label, Severity.LOW)

    confidence_label = str(metadata.get("confidence", "")).upper()
    confidence = _SEMGREP_CONFIDENCE_MAP.get(confidence_label, Confidence.MEDIUM)

    cwe_ids = _extract_cwe_ids(metadata.get("cwe"))
    owasp_ids = _extract_owasp_ids(metadata.get("owasp"))
    category = _category_from_metadata(metadata)
    tags = _extract_tags(metadata, category)

    short_description = extra.get("message") if isinstance(extra.get("message"), str) else None
    title = _short_title(check_id, short_description)

    fix_suggestion = None
    fix = extra.get("fix")
    if isinstance(fix, str) and fix.strip():
        fix_suggestion = f"Semgrep 建议替换为：{fix.strip()}"

    blocks_release = severity in {Severity.CRITICAL, Severity.HIGH} and category == "security"
    risk_priority = "must-fix" if blocks_release else "should-fix"

    references = metadata.get("references") if isinstance(metadata.get("references"), list) else []
    reference_url: str | None = None
    if references:
        first_ref = next((str(r) for r in references if isinstance(r, str) and r.startswith("http")), None)
        reference_url = first_ref

    return RuleSpec(
        rule_id=check_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        fix_suggestion=fix_suggestion,
        blocks_release=blocks_release,
        risk_priority=risk_priority,
        tags=tuple(tags),
        applicable_languages=(),  # adapter does not constrain by language
        cwe_ids=tuple(cwe_ids),
        owasp=tuple(owasp_ids),
        description_zh=None,
        reference_url=reference_url,
    )


def _short_title(check_id: str, message: str | None) -> str:
    short = check_id.rsplit(".", 1)[-1] if check_id else "semgrep-finding"
    if message:
        first_line = message.strip().splitlines()[0]
        if first_line and len(first_line) <= 120:
            return f"[Semgrep] {short}: {first_line}"
    return f"[Semgrep] {short}"


def _category_from_metadata(metadata: dict[str, Any]) -> str:
    category_raw = metadata.get("category")
    if isinstance(category_raw, str):
        c = category_raw.lower()
        if c in {"security", "vulnerability", "vuln"}:
            return "security"
        if c in {"correctness", "best-practice", "maintainability"}:
            return "maintainability"
        if c == "performance":
            return "performance"
    # Fallback: presence of CWE or owasp signals "security"
    if metadata.get("cwe") or metadata.get("owasp"):
        return "security"
    return "maintainability"


def _extract_tags(metadata: dict[str, Any], category: str) -> list[str]:
    tags: list[str] = ["semgrep"]
    if category:
        tags.append(category)
    technology = metadata.get("technology")
    if isinstance(technology, list):
        for t in technology:
            if isinstance(t, str) and t.strip():
                tags.append(t.strip().lower())
    subcategory = metadata.get("subcategory")
    if isinstance(subcategory, list):
        for s in subcategory:
            if isinstance(s, str) and s.strip():
                tags.append(s.strip().lower())
    elif isinstance(subcategory, str) and subcategory.strip():
        tags.append(subcategory.strip().lower())
    # de-dup preserve order
    seen: set[str] = set()
    out: list[str] = []
    for tag in tags:
        if tag not in seen:
            seen.add(tag)
            out.append(tag)
    return out


def _extract_cwe_ids(raw: Any) -> list[str]:
    """Semgrep encodes CWE as ``"CWE-79: Improper Neutralization..."``."""
    items: list[str] = []
    if isinstance(raw, list):
        candidates = [r for r in raw if isinstance(r, str)]
    elif isinstance(raw, str):
        candidates = [raw]
    else:
        return items
    for c in candidates:
        token = c.split(":", 1)[0].strip()
        if token.upper().startswith("CWE-"):
            items.append(token.upper())
    return items


def _extract_owasp_ids(raw: Any) -> list[str]:
    items: list[str] = []
    if isinstance(raw, list):
        candidates = [r for r in raw if isinstance(r, str)]
    elif isinstance(raw, str):
        candidates = [raw]
    else:
        return items
    for c in candidates:
        items.append(c.strip())
    return items


def _infer_language(path: str, technology: list[Any] | None) -> str | None:
    if technology:
        for t in technology:
            if isinstance(t, str) and t.strip():
                return t.strip().lower()
    suffix = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rb": "ruby",
        ".rs": "rust",
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".lua": "lua",
        ".php": "php",
        ".scala": "scala",
        ".kt": "kotlin",
        ".swift": "swift",
    }.get(suffix)


def _to_project_relative(path: str, root_resolved: Path) -> str:
    """Normalize Semgrep's path to a forward-slash project-relative path."""
    p = Path(path)
    try:
        rel = p.resolve().relative_to(root_resolved)
    except (ValueError, OSError):
        # Already relative or outside the project — keep as-is, just normalize separators.
        rel = p
    return str(rel).replace("\\", "/")


def _safe_int(value: Any, default: int) -> int:
    if isinstance(value, int):
        return value if value >= 1 else default
    if isinstance(value, str) and value.isdigit():
        v = int(value)
        return v if v >= 1 else default
    return default
