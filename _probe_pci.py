"""只读探测脚本：构建 benchmark-java 的 PCI，输出调用图真实统计，验证跨函数漏报根因。
不修改任何被测代码。输出写入 _probe_pci_out.txt (utf-8)。
"""
from __future__ import annotations

import traceback
from collections import Counter
from pathlib import Path

BENCH = r"E:\BenchmarkTest\benchmark-java"
out: list[str] = []


def log(*args: object) -> None:
    out.append(" ".join(str(a) for a in args))


try:
    from codeguardian.config.defaults import default_config
    from codeguardian.core.context import ScanContext
    from codeguardian.core.call_graph.pci_builder import PCIBuilder
    from codeguardian.core.call_graph.graph import CallForm

    ctx = ScanContext(project_root=BENCH, config=default_config())
    builder = PCIBuilder(use_cache=False)
    pci = builder.build(ctx)

    st = pci.symbol_table
    cg = pci.call_graph
    summaries = pci.function_summaries

    log("=== PCI 总览 ===")
    log(f"files parsed = {pci.file_count}")
    log(f"symbols = {st.size}")
    log(f"functions/methods = {len(st.all_functions())}")
    log(f"classes = {len(st.all_classes())}")
    log(f"call edges (all) = {cg.edge_count}")
    log(f"summaries = {len(summaries)}")

    # 语言分布
    lang_ct: Counter = Counter(s.language for s in st.all_symbols())
    log(f"symbol languages = {dict(lang_ct)}")

    # 所有边的 confidence 分布 + CallForm 分布
    all_edges = [e for lst in cg._forward.values() for e in lst]
    conf_buckets = Counter()
    form_conf: dict = {}
    for e in all_edges:
        c = e.confidence
        b = "<0.5" if c < 0.5 else ("0.5-0.69" if c < 0.7 else ">=0.7")
        conf_buckets[b] += 1
        form_conf.setdefault(e.call_form.value, Counter())[b] += 1

    log("\n=== 边 confidence 分布 (阈值0.7是所有跨函数检测的门槛) ===")
    for b in ("<0.5", "0.5-0.69", ">=0.7"):
        log(f"  {b:10s}: {conf_buckets.get(b,0)}")
    log("\n=== 按 CallForm 的 confidence 分布 ===")
    for form, ct in form_conf.items():
        log(f"  {form:12s}: " + ", ".join(f"{b}={ct.get(b,0)}" for b in ('<0.5','0.5-0.69','>=0.7')))

    # 关键跨函数 bug 文件
    key_files = [
        "OrderService", "CleanupService", "PaymentService", "CounterService",
        "CacheManager", "OrderFulfillService", "AsyncTaskProcessor",
        "MigrationService", "DistributedLockManager", "UserService",
    ]
    log("\n=== 关键文件的函数 & 调用边情况 ===")
    for kf in key_files:
        # 找该文件的符号
        syms = [s for s in st.all_functions() if kf in s.file_path]
        if not syms:
            log(f"\n[{kf}] 无匹配文件/函数 (未纳入符号表)")
            continue
        fpath = syms[0].file_path
        log(f"\n[{kf}] file={fpath} 函数数={len(syms)}")
        for s in syms:
            callees = cg.callees_of(s.qualified_name, depth=1, min_confidence=0.0)
            callees_hi = [e for e in callees if e.confidence >= 0.7]
            callers = cg.callers_of(s.qualified_name, depth=1, min_confidence=0.0)
            summ = summaries.get(s.qualified_name)
            flags = []
            if summ:
                if summ.may_return_null: flags.append("null")
                if summ.acquires: flags.append(f"acq({len(summ.acquires)})")
                if summ.releases: flags.append(f"rel({len(summ.releases)})")
                if summ.may_throw: flags.append(f"throw{sorted(summ.may_throw)}")
                if summ.acquires_lock: flags.append(f"lock={summ.acquires_lock}")
                if summ.has_finally: flags.append("finally")
                if summ.uses_context_manager: flags.append("ctxmgr")
                if summ.is_source: flags.append("SOURCE")
                if summ.is_sink: flags.append("SINK")
            log(f"    {s.name}() qn={s.qualified_name}")
            log(f"        callees={len(callees)} (>=0.7: {len(callees_hi)}), callers={len(callers)}, summary=[{','.join(flags)}]")
            # 展示 callee 边的 confidence
            if callees:
                sample = "; ".join(f"{e.callee.split('.')[-1]}={e.confidence:.2f}/{e.call_form.value}" for e in callees[:6])
                log(f"        callee边: {sample}")

    # dump graph.json
    dump = str(Path("_probe_graph.json"))
    pci.export_debug_json(dump)
    log(f"\ngraph dumped to {dump}")

except Exception:
    log(traceback.format_exc())

Path("_probe_pci_out.txt").write_text("\n".join(out), encoding="utf-8")
print("done, see _probe_pci_out.txt")
