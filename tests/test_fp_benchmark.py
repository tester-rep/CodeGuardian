"""Synthetic false-positive benchmark (B1).

Runs the security engine over ``benchmark/fp_corpus`` and scores it against
``labels.json`` (TP = must be reported, FP = must NOT be reported). Each
label's ``marker`` is matched against the source line of the reported finding.

The corpus deliberately lives OUTSIDE ``tests/``: anything under a path
containing ``tests``/``test`` would be suppressed by the Phase 0-2 test-path
exemption and the benchmark would see nothing.

Result is written to ``benchmark/fp_corpus/last_report.json`` so the effect of
each optimization phase can be compared against this baseline.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.defaults import default_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine
from codeguardian.engines.performance_engine import PerformanceEngine
from codeguardian.engines.security_engine import SecurityEngine

CORPUS_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "fp_corpus"
REPORT_PATH = CORPUS_DIR / "last_report.json"

# Engines exercised by the corpus (security + performance + defect rules).
_ENGINES = (SecurityEngine(), PerformanceEngine(), DefectEngine())


def _load_labels() -> list[dict]:
    return json.loads((CORPUS_DIR / "labels.json").read_text(encoding="utf-8"))


async def _run_scan() -> list[tuple[str, str, str]]:
    """Scan corpus; return (file, rule_id, line_text) for each finding."""
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources: dict[str, list[str]] = {}
        for src in CORPUS_DIR.glob("*.py"):
            text = src.read_text(encoding="utf-8")
            (root / src.name).write_text(text, encoding="utf-8")
            sources[src.name] = text.splitlines()
        ctx = ScanContext(project_root=str(root), config=default_config())
        findings = []
        for engine in _ENGINES:
            findings.extend((await engine.analyze(ctx)).findings)

        reported = []
        for f in findings:
            lines = sources.get(f.location.file_path, [])
            start = f.location.line_start - 1
            end = f.location.line_end  # inclusive line number -> slice end (exclusive)
            line_text = "\n".join(lines[start:end]) if 0 <= start < len(lines) else ""
            reported.append((f.location.file_path, f.rule_id, line_text))
    return reported


def _is_hit(reported: list[tuple[str, str, str]], file: str, rule_id: str, marker: str) -> bool:
    return any(rf == file and rid == rule_id and marker in lt for rf, rid, lt in reported)


async def test_fp_benchmark() -> None:
    labels = _load_labels()
    reported = await _run_scan()

    tp = fp = fn = 0
    misses: list[str] = []
    for e in labels:
        hit = _is_hit(reported, e["file"], e["rule_id"], e["marker"])
        if e["label"] == "TP":
            if hit:
                tp += 1
            else:
                fn += 1
                misses.append(f"FN(漏报): {e['file']} {e['rule_id']} [{e['reason']}]")
        else:  # FP — must NOT be reported
            if hit:
                fp += 1
                misses.append(f"FP(误报): {e['file']} {e['rule_id']} [{e['reason']}]")

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    REPORT_PATH.write_text(json.dumps({
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "misses": misses,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    assert not misses, (
        f"基准未通过 precision={precision:.2f} recall={recall:.2f}\n" + "\n".join(misses)
    )
