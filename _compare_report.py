"""Compare benchmark-v2 report.json against bug-manifest.yaml."""
import json
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")


def normalize_path(p: str) -> str:
    return p.replace("\\", "/").strip()


def main() -> None:
    report_path = r"E:\BenchmarkTest\benchmark-v2\reports\report.json"
    yaml_path = r"E:\BenchmarkTest\bug-manifest.yaml"

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    with open(yaml_path, "r", encoding="utf-8") as f:
        yaml_text = f.read()

    # Parse YAML bugs manually
    bug_pattern = re.compile(
        r"- id: (SC-\d+)\n"
        r"\s+module: (.+?)\n"
        r"\s+category: (.+?)\n"
        r"\s+difficulty: (.+?)\n"
        r"\s+cross_function: (.+?)\n"
        r"(?:\s+cross_function_depth: (.+?)\n)?"
        r"\s+file: (.+?)\n"
        r"\s+line: (\d+)\n",
        re.MULTILINE,
    )

    bugs = []
    for m in bug_pattern.finditer(yaml_text):
        bugs.append({
            "id": m.group(1),
            "module": m.group(2).strip(),
            "category": m.group(3).strip(),
            "difficulty": m.group(4).strip(),
            "file": normalize_path(m.group(7)),
            "line": int(m.group(8)),
        })

    print(f"YAML bugs parsed: {len(bugs)}")

    findings = report.get("findings", [])
    print(f"Report findings: {len(findings)}")

    # --- TP: YAML bugs found in report ---
    matched = []
    unmatched_yaml = []
    for bug in bugs:
        bf = bug["file"]
        best = None
        bdist = 999
        for f in findings:
            ff = normalize_path(f["location"]["file_path"])
            # Match by full path suffix or filename
            if bf.endswith(ff) or ff.endswith(bf) or bf.split("/")[-1] == ff.split("/")[-1]:
                d = abs(f["location"]["line_start"] - bug["line"])
                if d <= 10 and d < bdist:
                    bdist = d
                    best = f
        if best:
            matched.append({
                "yaml_id": bug["id"],
                "yaml_line": bug["line"],
                "yaml_cat": bug["category"],
                "yaml_diff": bug["difficulty"],
                "report_id": best["id"],
                "report_line": best["location"]["line_start"],
                "report_sev": best["severity"],
                "report_src": best.get("source_engine", ""),
                "dist": bdist,
            })
        else:
            unmatched_yaml.append(bug)

    print(f"\n=== MATCHED (True Positives): {len(matched)} ===")
    for m in matched:
        print(
            f"  {m['yaml_id']} L{m['yaml_line']} -> {m['report_id']} "
            f"L{m['report_line']} [{m['report_src']}] {m['report_sev']} d={m['dist']}"
        )

    print(f"\n=== UNMATCHED YAML bugs (False Negatives): {len(unmatched_yaml)} ===")
    for u in unmatched_yaml:
        print(f"  {u['id']} {u['file']}:{u['line']} [{u['difficulty']}] {u['category']}")

    # --- FP: Report findings not in YAML ---
    yaml_line_map = set()
    yaml_file_names = set()
    for bug in bugs:
        fn = bug["file"].split("/")[-1]
        yaml_file_names.add(fn)
        for delta in range(-10, 11):
            yaml_line_map.add((fn, bug["line"] + delta))

    fp_findings = []
    for f in findings:
        ff = normalize_path(f["location"]["file_path"])
        fn = ff.split("/")[-1]
        if "clean-samples" in ff:
            continue
        if fn not in yaml_file_names:
            fp_findings.append(f)
            continue
        found = False
        for delta in range(-10, 11):
            if (fn, f["location"]["line_start"] + delta) in yaml_line_map:
                found = True
                break
        if not found:
            fp_findings.append(f)

    print(f"\n=== Report findings NOT in YAML (potential FP): {len(fp_findings)} ===")
    for f in fp_findings:
        print(
            f"  {f['id']} {normalize_path(f['location']['file_path'])}:{f['location']['line_start']} "
            f"[{f.get('source_engine', '')}] {f['severity']} {f.get('title', '')[:60]}"
        )

    # --- Clean-samples findings ---
    clean_findings = [
        f for f in findings
        if "clean-samples" in normalize_path(f["location"]["file_path"])
    ]
    print(f"\n=== Clean-samples findings: {len(clean_findings)} ===")
    for f in clean_findings:
        print(
            f"  {f['id']} {normalize_path(f['location']['file_path'])}:{f['location']['line_start']} "
            f"[{f.get('source_engine', '')}] {f['severity']}"
        )

    # --- Summary ---
    print(f"\n{'='*60}")
    print(f"YAML bugs total: {len(bugs)}")
    print(f"  Detected (TP): {len(matched)}")
    print(f"  Missed (FN): {len(unmatched_yaml)}")
    print(f"  Recall: {len(matched)}/{len(bugs)} = {len(matched)/len(bugs)*100:.1f}%")
    print(f"Report findings: {len(findings)}")
    print(f"  TP: {len(matched)}")
    print(f"  FP (non-clean-samples, non-YAML): {len(fp_findings)}")
    print(f"  Clean-samples FP: {len(clean_findings)}")
    total_fp = len(fp_findings) + len(clean_findings)
    print(f"  Total FP: {total_fp}")
    if len(findings) > 0:
        print(f"  Precision: {len(matched)}/{len(findings)} = {len(matched)/len(findings)*100:.1f}%")
    print(f"Duration: {report.get('duration_seconds', 0):.1f}s")

    # Difficulty breakdown
    print(f"\n--- Recall by difficulty ---")
    for diff in ("easy", "medium", "hard"):
        total_d = sum(1 for b in bugs if b["difficulty"] == diff)
        matched_d = sum(1 for m in matched if m["yaml_diff"] == diff)
        if total_d > 0:
            print(f"  {diff}: {matched_d}/{total_d} = {matched_d/total_d*100:.1f}%")

    print(f"\n--- Recall by category ---")
    cats = set(b["category"] for b in bugs)
    for cat in sorted(cats):
        total_c = sum(1 for b in bugs if b["category"] == cat)
        matched_c = sum(1 for m in matched if m["yaml_cat"] == cat)
        if total_c > 0:
            print(f"  {cat}: {matched_c}/{total_c} = {matched_c/total_c*100:.1f}%")

    # Detection source breakdown for matched bugs
    print(f"\n--- Detection source for matched bugs ---")
    src_counts = {}
    for m in matched:
        s = m["report_src"]
        src_counts[s] = src_counts.get(s, 0) + 1
    for s, c in sorted(src_counts.items(), key=lambda x: -x[1]):
        print(f"  {s}: {c}")


if __name__ == "__main__":
    main()
