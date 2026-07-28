import asyncio
import traceback
from collections import Counter
from pathlib import Path

out = []
try:
    from codeguardian.config.defaults import default_config
    from codeguardian.core.context import ScanContext
    from codeguardian.engines.defect_engine import DefectEngine
    from codeguardian.engines.performance_engine import PerformanceEngine
    from codeguardian.engines.security_engine import SecurityEngine

    async def main() -> None:
        ctx = ScanContext(project_root="src/codeguardian", config=default_config())
        counts: Counter = Counter()
        examples: dict = {}
        for eng in (SecurityEngine(), DefectEngine(), PerformanceEngine()):
            result = await eng.analyze(ctx)
            for f in result.findings:
                counts[f.rule_id] += 1
                examples.setdefault(f.rule_id, f.location.file_path + ":" + str(f.location.line_start))
        out.append(f"total findings: {sum(counts.values())}")
        for rule_id, n in counts.most_common(40):
            out.append(f"{n:5d}  {rule_id:35s} e.g. {examples[rule_id]}")

    asyncio.run(main())
except Exception:
    out.append(traceback.format_exc())

Path("_analyze_self_out.txt").write_text("\n".join(out), encoding="utf-8")
