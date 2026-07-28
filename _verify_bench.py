"""Benchmark 核对：manifest 期望 bug vs report.json 实际 findings。仅读取，不改任何东西。"""
import json, os, re, sys

REPORT = r"E:\BenchmarkTest\benchmark-java\reports\report.json"
MANIFEST = r"E:\BenchmarkTest\bug-manifest.yaml"


def load_findings(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    found = []
    seen = set()

    def walk(o):
        if isinstance(o, dict):
            if "rule_id" in o and isinstance(o.get("location"), dict):
                loc = o["location"]
                key = (o.get("rule_id"), loc.get("file_path"), loc.get("line_start"))
                if key not in seen:
                    seen.add(key)
                    found.append({
                        "rule_id": o.get("rule_id"),
                        "id": o.get("id"),
                        "title": o.get("title"),
                        "category": o.get("category"),
                        "severity": o.get("severity"),
                        "confidence": o.get("confidence"),
                        "file": loc.get("file_path"),
                        "line": loc.get("line_start"),
                    })
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    return found


def parse_manifest(path):
    """极简 YAML 解析，只取 bugs 列表中需要的字段。"""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    bugs = []
    cur = None
    for line in text.splitlines():
        m = re.match(r"\s*-\s+id:\s*(\S+)", line)
        if m:
            if cur:
                bugs.append(cur)
            cur = {"id": m.group(1)}
            continue
        if cur is None:
            continue
        m = re.match(r"\s+(\w+):\s*(.*)$", line)
        if m:
            k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
            if k in ("module", "rule_id", "severity", "category", "file", "line", "cross_function", "difficulty"):
                if k not in cur or k == "file":  # file 可能出现两次(files块后), 取最后一个明确的
                    cur[k] = v
    if cur:
        bugs.append(cur)
    return bugs


def basename(p):
    return os.path.basename(p.replace("\\", "/")) if p else ""


def main():
    findings = load_findings(REPORT)
    bugs = parse_manifest(MANIFEST)

    print(f"=== 总览 ===")
    print(f"期望 bug 数: {len(bugs)}")
    print(f"报告 findings 去重后: {len(findings)}")
    print()

    matched_finding_keys = set()
    tp, fn = [], []

    for b in bugs:
        bfile = basename(b.get("file", ""))
        try:
            bline = int(b.get("line", -1))
        except ValueError:
            bline = -1
        brule = b.get("rule_id", "")
        # 匹配: 同文件名 且 行号差<=5 (放宽以容忍规则定位差异)
        cands = [f for f in findings
                 if basename(f["file"]) == bfile and abs((f["line"] or -999) - bline) <= 5]
        # 优先 rule_id 名称相近的
        best = None
        for c in cands:
            key = (c["rule_id"], c["file"], c["line"])
            score = 0
            rid = (c["rule_id"] or "").upper()
            br = brule.upper()
            # 规则语义相近判定(名称包含或共享关键词)
            if rid == br:
                score = 3
            elif any(tok in rid for tok in br.split("-") if len(tok) > 3) or \
                 any(tok in br for tok in rid.split("-") if len(tok) > 3):
                score = 2
            else:
                score = 1  # 同文件同行, 可能是等价检测
            if best is None or score > best[0]:
                best = (score, c, key)
        if cands:
            tp.append((b, best[1], best[0]))
            matched_finding_keys.add(best[2])
        else:
            fn.append(b)

    fp = [f for f in findings
          if (f["rule_id"], f["file"], f["line"]) not in matched_finding_keys]

    print(f"=== 命中(TP) {len(tp)} ===")
    for b, f, score in sorted(tp, key=lambda x: x[0]["id"]):
        flag = "精确" if score == 3 else ("相近" if score == 2 else "同位置弱匹配")
        print(f"{b['id']:8} 期望[{b['rule_id']}] -> 实测[{f['rule_id']}] "
              f"sev={f['severity']}/{f['confidence']} @{basename(f['file'])}:{f['line']} ({flag})")

    print(f"\n=== 漏报(FN) {len(fn)} ===")
    for b in sorted(fn, key=lambda x: x["id"]):
        cf = b.get("cross_function", "?")
        print(f"{b['id']:8} [{b['rule_id']}] {b.get('module','')} @{basename(b.get('file',''))}:{b.get('line','')} cross_fn={cf}")

    print(f"\n=== 未匹配 findings(疑似误报/额外) {len(fp)} ===")
    from collections import Counter
    by_rule = Counter(f["rule_id"] for f in fp)
    for rule, n in by_rule.most_common():
        print(f"  {rule}: {n}")

    print(f"\n=== 全部 findings 规则分布 ===")
    allc = Counter(f["rule_id"] for f in findings)
    for rule, n in allc.most_common():
        print(f"  {rule}: {n}")

    print(f"\n=== 指标 ===")
    recall = len(tp) / len(bugs) if bugs else 0
    prec = len(tp) / len(findings) if findings else 0
    print(f"召回率 recall = {len(tp)}/{len(bugs)} = {recall:.2%}")
    print(f"精确率 precision(粗略) = {len(tp)}/{len(findings)} = {prec:.2%}")

    print(f"\n=== 逐 bug: 该文件下所有实测 findings(用于人工语义判定) ===")
    for b in sorted(bugs, key=lambda x: x["id"]):
        bfile = basename(b.get("file", ""))
        infile = [f for f in findings if basename(f["file"]) == bfile]
        infile.sort(key=lambda f: f["line"] or 0)
        tag = "命中" if any(bb["id"] == b["id"] for bb, _, _ in tp) else "漏报"
        print(f"\n[{b['id']}] {tag} 期望[{b['rule_id']}]@{bfile}:{b.get('line')} (cross_fn={b.get('cross_function','?')})")
        if not infile:
            print("    (该文件无任何 finding)")
        for f in infile:
            print(f"    实测[{f['rule_id']}] sev={f['severity']}/{f['confidence']} @L{f['line']} :: {f['title'][:40] if f['title'] else ''}")


if __name__ == "__main__":
    main()
