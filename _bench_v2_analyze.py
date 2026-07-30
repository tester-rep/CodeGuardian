import json, yaml, os, collections

BASE = r"E:\BenchmarkTest"
rep = json.load(open(os.path.join(BASE,"benchmark-v2","reports","report.json"), encoding="utf-8"))
man = yaml.safe_load(open(os.path.join(BASE,"bug-manifest.yaml"), encoding="utf-8"))
norm=lambda p:p.replace("\\","/").strip() if p else p

findings=[]
for f in rep["findings"]:
    loc=f.get("location") or {}
    findings.append({"id":f.get("id"),"title":(f.get("title") or "")[:50],"cat":f.get("category"),
        "sev":f.get("severity"),"file":norm(loc.get("file_path")),"line":loc.get("line_start")})
bugs=[{"id":b["id"],"file":norm(b["file"]),"line":b.get("line"),"diff":b.get("difficulty"),
    "cf":bool(b.get("cross_function",False)),"depth":b.get("cross_function_depth"),"cat":b.get("category")} for b in man["bugs"]]

# index findings by file
byfile=collections.defaultdict(list)
for f in findings:
    byfile[f["file"]].append(f)

# FILE-LEVEL recall: bug's file has >=1 finding (upper bound)
file_hit=[b for b in bugs if byfile.get(b["file"])]
# LINE +-8 (loose, per earlier calibration offset up to ~6)
def near(b,tol):
    return [f for f in byfile.get(b["file"],[]) if f["line"] and b["line"] and abs(f["line"]-b["line"])<=tol]
line_hit=[b for b in bugs if near(b,8)]

print("=== SCALE ===  findings",len(findings)," bugs",len(bugs)," meta.total",man["meta"]["total_bugs"])
print(f"FILE-level recall (bug file has any finding): {len(file_hit)}/{len(bugs)} = {len(file_hit)/len(bugs)*100:.1f}%  [UPPER BOUND]")
print(f"LINE +-8 recall: {len(line_hit)}/{len(bugs)} = {len(line_hit)/len(bugs)*100:.1f}%")

# files with ZERO findings that contain bugs (hard misses - file untouched)
bugfiles=collections.Counter(b["file"] for b in bugs)
zero=[fn for fn in bugfiles if not byfile.get(fn)]
print(f"\n=== FILES with manifest bug(s) but ZERO findings: {len(zero)} files, covering {sum(bugfiles[fn] for fn in zero)} bugs ===")
for fn in sorted(zero):
    ids=[b['id'] for b in bugs if b['file']==fn]
    print(f"  {fn.split('/')[-1]:32s} bugs={ids}")

print("\n=== CROSS-FUNCTION bugs (13) — headline feature — manual verify ===")
for b in [x for x in bugs if x["cf"]]:
    fs=byfile.get(b["file"],[])
    near8=near(b,8)
    tag="HIT(line)" if near8 else ("file-touched" if fs else "FILE ZERO")
    print(f"  {b['id']} depth={b['depth']} {b['cat']} {b['file'].split('/')[-1]}:{b['line']}  -> {tag}; findings_in_file={[(f['id'],f['line'],f['title'][:22]) for f in fs]}")

print("\n=== clean-samples FP (definite) ===")
clean=[f for f in findings if "clean-samples" in (f["file"] or "")]
print("count:",len(clean))
cf_clean=[f for f in clean if f["id"].startswith("CF-")]
print("  of which cross-function-engine FP:",len(cf_clean))

print("\n=== cross-function engine findings overall ===")
cfeng=[f for f in findings if f["id"].startswith("CF-")]
print("total CF- findings:",len(cfeng))
inclean=[f for f in cfeng if "clean-samples" in f["file"]]
print("  in clean-samples (FP):",len(inclean))
# CF findings that land on a cross_function bug file
cfbugfiles=set(b["file"] for b in bugs if b["cf"])
oncfbug=[f for f in cfeng if f["file"] in cfbugfiles]
print("  landing in a cross_function-bug file:",len(oncfbug))
print("  landing elsewhere (non-cf-bug files):",len(cfeng)-len(inclean)-len(oncfbug))
