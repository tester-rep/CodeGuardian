import json
import sys

path = r"E:\code\loadTest_Code\sprRobot\sprJava\spr_robot_java\reports\report.json"
d = json.load(open(path, encoding="utf-8"))
fs = d["findings"]

want = sys.argv[1] if len(sys.argv) > 1 else None
for f in fs:
    if want and f.get("rule_id") != want:
        continue
    loc = f["location"]
    fp = loc["file_path"].split("/")[-1].split("\\")[-1]
    line = loc.get("line_start")
    msg = (f.get("title") or "").replace("\n", " ")
    detail = ""
    for ev in f.get("evidences", []):
        if ev.get("content"):
            detail = ev["content"].replace("\n", " ")[:200]
            break
    print(f"[{f.get('rule_id')}] {fp}:{line} | sev={f.get('severity')}")
    print(f"    title: {msg[:220]}")
    if detail:
        print(f"    ev: {detail}")
