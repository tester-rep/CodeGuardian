# CodeGuardian 误报治理与检测有效性 — 分阶段改造计划

> 本文档严格基于已核实的代码事实编写；所有推断均标注证据位置或 `[未验证]`。
> 最后更新：2026-07-23

---

## 0. 背景与目标

当前误报的主因是三类系统性缺陷（均附代码证据）：

1. **单点特征判定缺语义上下文** — 见 §2 根因表。
2. **已有降误报能力未跨引擎复用（能力孤岛）** — 已在 Phase 0 修复占位符/测试豁免两项。
3. **正则/缩进近似冒充结构分析** — `SQL-IN-LOOP` 用缩进推循环边界、`MISSING-PAGINATION` 用 ±200 字符窗口猜上下文。

**总目标**：在不牺牲真实缺陷召回的前提下，系统性降低误报率，并让"优化效果"可被量化验证。

---

## 1. 效果度量前提（先于一切优化）

> 没有标注基准，"误报降低"无法被证明。这是所有阶段的前置条件。

- [ ] **建立标注基准集（labeled corpus）**：选取 2-3 个真实目标项目（含本仓库自测），对每个被改动的规则，人工标注 ≥30 条历史 finding 为 TP（真阳）/FP（假阳）。
- [ ] 基准落盘为 `tests/fixtures/fp_baseline/<rule_id>.json`：`{finding_signature, label, reason}`。
- [ ] 每个阶段完成后重跑基准，输出 **精确率 = TP/(TP+FP)** 与 **召回 = TP/(TP+FN迁移)** 的前后对比。
- 验证: 每次改造 PR 附"基准前后精确率对比表"，无基准对比不得宣称"误报降低"。

---

## 2. 误报根因分类（事实，均附代码证据）

| # | 根因 | 证据位置 | 误报风险 |
|---|------|---------|---------|
| 1 | 占位符/示例值无过滤 | `security_engine._is_string_literal` 仅判 `len>=4` | 高（Phase 0 已修） |
| 2 | 测试路径豁免未复用 | `defect_engine._is_test_file` 仅 defect 用 | 高（Phase 0 已修） |
| 3 | 无用途/场景判断 | `security_engine` 见 `hashlib.md5`/`random.random` 即报（`:539-548`） | 中 |
| 4 | 缩进近似替代结构 | `performance_engine._detect_sql_in_loop` 靠 `indent<=loop_indent`（`:405-422`） | 中 |
| 5 | 固定窗口猜上下文 | `_detect_missing_pagination` 看 `±200 字符`（`:509-512`） | 中 |
| 6 | 污点仅函数内（语句级） | `engines/python_taint.py` 标注 "intra-function" | 中 |
| 7 | 置信度静态固定 | `rule_helpers._classify_evidence` 取自 `RuleSpec` 常量（`:146-162`） | 低 |
| 8 | 纯阈值项混入缺陷流 | ASSERT-USED / PRINT-DEBUG / 复杂度指标 | 低 |

---

## 3. 已完成 — Phase 0：能力孤岛打通（占位符 + 测试豁免）

**状态：✅ 已落地并验证（13 项新测试全绿，基线对比零引入回归）。**

- 共享逻辑下沉 `rule_helpers.py`：`is_placeholder_secret()` + `is_test_file_path()`。
- `security_engine`：HARDCODED-PASSWORD 全分支（Py/JS/Java/C++/Go + 正则回退）过滤占位符/环境变量引用；测试文件抑制全部 11 条安全规则。
- `performance_engine`：测试文件抑制 `SQL-IN-LOOP`/`MISSING-PAGINATION`/`SELECT-STAR-NO-LIMIT`。
- `config_risk_engine`：改用共享 `is_placeholder_secret`（等价重构，smoke 25 passed）。
- 验证: `tests/test_false_positive_suppression.py` 13 绿；受影响套件 stash 基线对比 `20 failed,110 passed` 改动前后一致（20 失败均为预存在）。

---

## 4. Phase 1 — 修复基线（前置，否则无法验证后续改动） ✅

> 目标：让受影响测试套件回到全绿基线，否则任何新改动都无法用"测试是否变红"来验证。

**状态：✅ 已完成（209 passed，全量回归 527 passed / 6 failed 均为预存在）。**

**1.1 根因更正（实测）**：20 个失败**不是代码 bug，而是测试隔离缺陷**——这些测试用 `load_app_config(None)`，在 cwd=项目根时自动加载了项目自用的 `codeguardian.toml`（其中 `min_severity = "medium"`），把 LOW/INFO 级别规则（IDENTIFIER-TYPO/SETTER-RETURNS-VALUE/PRINT-DEBUG/UNUSED-VARIABLE/SUBPROCESS-SHELL-TRUE/EXCEPTION-SWALLOWED-NO-LOG 等，均 `Severity.LOW/INFO`）经 `filter_rule_hits`（`rule_registry.py:81`）过滤掉。修复：5 个失败测试文件改用 `default_config()`（恢复"用纯默认配置"的本意，隔离 cwd 配置污染）。
**新发现（已修复 ✅）**：`test_planner_and_reports`(5) + `test_release_gate`(1) 共 6 个失败亦为预存在（stash 基线一致）。修复方案 C 完成：3 个为 `semgrep`/`min_severity` 配置污染（改 `default_config()`）；2 个评分失败实为 `min_severity` 污染（同上）；**1 个为真实 bug**——`cross_function` 引擎在 `STANDARD/DEEP_ENABLED_ENGINES` 中但 `DIMENSION_ENGINE_MAP` 无 dimension 映射，导致 `--dimensions`（含 `all`）过滤时被丢弃，已映射到 `defects`（`planner.py`）；**1 个为测试构造错误**——release_gate 测试设 `overall_score=55` 为无效装饰（gate 用 RiskScorer 现算），改用 4 个 blocking-critical finding 使分数 <60。全量回归零引入（含 cross_function 映射影响面）。

| 任务 | 证据 / 现状 | 完成标准 | 预估 |
|------|------------|---------|------|
| 1.1 修复 20 个预存在失败 | `test_defect_engine_naming_rules`(9)、`advanced_rules`(7)、`new_rules`(1)、`phase2_opt`(1 print-debug)、`multilang_enhance`(2)；**已用 stash 基线确认为 HEAD 预存在** | 这些测试转绿，或明确标记 skip 并记录原因 | 中 |
| 1.2 修复 Go 顶层 `var` 凭据漏报 | `security_engine._scan_go_tree` 的 `var_declaration` 分支对 `var password = "aB3$..."` 不命中（已实测；短声明 `:=` 正常） | 新增失败测试 → 修复 → 转绿 | 小 |
| 1.3 清理 `defect_engine._TEST_PATH_INDICATORS` 死代码 | 该常量从未被 `_is_test_file` 引用（逻辑硬编码） | 删除或接入，二选一 | 极小 |

- 验证: `pytest tests/test_defect_engine_*` 全绿；Go var 漏报有回归测试。

---

## 5. Phase 2 — 补上下文判定（P1，中等改动）

> 目标：对"见特征即报"的高误报规则补场景上下文，预计直接削减根因 #3/#7。

### 5.1 行内豁免机制（行业标配，当前**确认缺失**） ✅

- 事实：全项目对被扫描代码无 `noqa`/`nosec` 行内豁免；`utils/ignore.py` 仅为文件路径忽略（gitignore/exclude_paths），非规则级行内豁免（已核实）。
- 改动：在 `rule_helpers` 加 `is_suppressed_by_inline_comment(rule_id, lines, line_no) -> bool`，识别上一行/同行尾的 `# codeguardian: ignore RULE-ID`（及通用 `# noqa: RULE-ID`）；三引擎在 `build_finding` 前统一调用。
- `[未验证]` 需确认各引擎 `analyze` 处 `lines` 均可及（已确认 security/defect/performance 均持有 `lines`）。
- 验证: 含豁免注释的命中不再产出 finding；无注释的仍产出。

### 5.2 WEAK-HASH / INSECURE-RANDOM 场景豁免 ✅

- 事实：`security_engine` 对 `hashlib.md5`/`random.random` 无用途判断即报。
- 实现（已完成）：按所在函数名做场景分诊——明确非安全场景（`checksum`/`cache`/`etag`/`sample`/`jitter`/`backoff` 等）抑制，安全场景（`password`/`token`/`verify` 等）或不可判定时仍报（保守）。
- **关键根因（实测）**：Python 不在 `_AST_COVERED_LANGUAGES`，WEAK-HASH/INSECURE-RANDOM 同时走 AST（有场景豁免）与正则（无豁免），正则的上下文无关命中绕过豁免 → 已让 Python 这两个规则只走 AST（`_PYTHON_AST_CONTEXT_RULES`）。
- 验证: B1 基准中校验和/缓存/采样/抖动用例不再误报，密码哈希/令牌/验证码仍报。

### 5.3 HARDCODED-PASSWORD 熵值门槛（Phase 0 占位符的补充） ✅

- 事实：占位符已过滤，但低熵短串（`admin`/`localhost`/`12345`）仍会命中（仅判 `len>=4`）。
- 实现（已完成）：`is_low_entropy_secret`——常见弱口令/默认词集合 + 短单一字符类串（纯数字、纯小写且 <8 位）判为低熵并排除；高熵值仍报。统一为 `is_non_secret_value`（占位符+低熵），作用于全语言分支与正则回退。
- 验证: B1 基准中 `admin`/`localhost`/`12345` 不再误报，高熵真实凭据仍报。

---

## 6. Phase 3 — 结构化替代近似（P2，较大改动）

> 目标：消除"缩进/窗口冒充结构分析"（根因 #4/#5），用已有 AST 通道替代。

### 6.1 SQL-IN-LOOP / MISSING-PAGINATION / SELECT-STAR 改 AST

- 事实：`performance_engine._detect_sql_in_loop` 用缩进推循环边界（`:405-422`），跨语言/多行 SQL 易错判；`_detect_missing_pagination` 用 ±200 字符窗口（`:509`）。
- 改动：Python 复用现有 `_scan_python_ast` 通道，以 `ast.For/While` 子树判断是否循环内 SQL 调用；分页判定在 AST 层看函数签名/装饰器/同函数 `limit` 调用，替代字符窗口。非 Python 复用 tree-sitter 节点。
- 验证: 基准集中"多行 SQL 字符串""装饰器分页"用例的 TP/FP 对比改善。

### 6.2 （评估后决定是否做）注入检测接通 PCI 调用图

- 事实（已核实）：**跨函数污点基础设施已存在**——`cross_function_engine._detect_taint_flow` 产出 `TAINT-CROSS-FUNCTION`，用 `is_source`/`is_sink` + `paths_between(max_depth=4, min_confidence=0.6)` + sanitizer 检查（`cross_function_engine.py:427-515`），但为**函数粒度**（整函数标记 source/sink）。`security_engine` 用 `engines/python_taint.py` 做**语句粒度** intra-procedural。两套并行、粒度不同；`defect_engine` 未消费 PCI 摘要（已核实，0 引用）。
- 改动方向（二选一，需先做小规模可行性验证）：
  - (a) security 注入命中后，用 PCI 调用图确认 source 可达性，可达→升置信度、不可达→降 needs-review（降"拼接即报"误报）。
  - (b) 将 `python_taint` 的语句级 source/sink 标记接入 `FunctionSummary.taint_flows`，复用已有跨函数传播（统一两套）。
- `[未验证]` 两方案的误报/漏报净效果、以及 `paths_between` 在大库上的性能，均未实测。**必须先出可行性报告再决定是否投入。**
- 验证: 基准集中"已参数化跨函数"（原漏报）与"常量拼接"（原误报）两类用例的净改善。

---

## 7. 阶段总览与效果预期

| 阶段 | 内容 | 改动量 | 风险 | 预期效果（需基准验证，非承诺） |
|------|------|-------|------|------|
| Phase 0 ✅ | 占位符 + 测试豁免跨引擎 | 小 | 低 | 已落地；安全/性能测试文件噪声消除 |
| Phase 1 ✅ | 修 20 失败（实为测试隔离）+ Go var 漏报 + 死代码 | 小-中 | 低 | 基线已恢复（209 passed） |
| Phase 2.1 ✅ | 行内豁免（`# codeguardian: ignore` / `# noqa`） | 小 | 低 | 用户可消除已确认误报 |
| Phase 2.2/2.3 ✅ | 场景豁免 + 熵值门槛 | 中 | 中（豁免过度→漏报） | **经 B1 合成基准验证：精确率 0.462→1.0、召回 1.0、FP 7→0** |
| Phase 3 | SQL/分页 AST 化 + 跨函数污点评估 | 大 | 高（重构回归） | 根因 #4/#5/#6，结构性降 FP |

**统一纪律**：每个阶段必须 ① 先写失败测试 ② 附 §1 标注基准的前后精确率对比 ③ stash 基线对比证明零引入回归，三者齐备才算完成。

---

## 7b. 本轮浅层检测项治理（数据驱动，2026-07-24）

> 方法：自测统计 rule_id 分布 → 抽查疑似误报 finding → **先查规则意图（docstring+既有测试）再判误报** → 扩 B1 基准量化 → 修复 → 基准+自测双重验证。

### 修复的浅层误报/漏报（均数据证实）

| 规则 | 根因（证据） | 修复 | 自测效果 |
|------|------------|------|---------|
| SELECT-STAR-NO-LIMIT | lookahead `(?!\s+WHERE/LIMIT)` 被 `\w+` 回溯绕过——`\w+` 匹配表名后回溯使后续位置非空白，WHERE/LIMIT 排除全失效（实测带 WHERE/LIMIT 也全报） | `\w+` 后加 `\b` 阻止回溯 + lookahead 改为检查**整个 SQL 字符串**内含 WHERE/LIMIT/JOIN | 3 误报→0 |
| MISSING-PAGINATION | ±200 字符窗口覆盖**邻近函数**的分页参数 → 误判当前 `find_all` 有分页（漏报） | Python 改 AST 函数级判断（调用是否传分页参 + 函数签名是否有分页参），替代字符窗口 | 1 漏报修复 |
| SQL-IN-LOOP | `_SQL_CALL_KEYWORDS` 纯正则匹配 "execute" 字样，命中字符串/message（`"never execute"`） | 要求函数调用括号 `\(` + 跳过注释行 | 13→1 |
| POSSIBLE-NONE-DEREF | ① 三元 guard（`x.attr if x else None`，`ast.IfExp`）不识别 ② `d.get(k, default)` 带默认值仍标 maybe-none | ① guard 收集接入 `ast.IfExp` ② `.get` 有 ≥2 args/keywords 时不标 | 23→9 |
| RETRY-WITHOUT-BACKOFF | 把"for 遍历+try/except 容错跳过失败元素"误判为"重试无退避" | 仅 `while` 或 `for ... in range(...)`（固定次数）才算重试候选 | 12→0 |

### 调查后**回退**（重要教训）

- **EXCEPTION-SWALLOWED-NO-LOG（×73）**：初判为高误报，但**既有测试 `test_..._with_default_assign/return` 锁定**"赋默认值/返回默认值要报"，且 docstring 明确"reports them at LOW severity since they are observability **smells rather than guaranteed bugs**"。→ 它是**有意设计的 LOW smell（检测准确，非误报）**，已回退豁免改动。**教训：高频≠误报，须先查规则意图。**

### 效果

- 自测总 findings **232 → 194（-16%）**，B1 基准（security+performance+defect）**精确率 1.0 / 召回 1.0**（TP=12 全报、FP=0、FN=0）。
- 回归：defect/security/performance/pci/cli/planner/gate 共 438 passed 零引入，lint 干净。
- ~~附带发现：`UNUSED-VARIABLE` 在 `cli/commands/config.py:87` 发现疑似真实 bug~~ **已处理（2026-07-27）**：调查证实非行为 bug——`parsed_value` 赋值后全项目零读取，TOML 类型格式化由 `_update_toml_field` 内部 `_parse_value` 完成，行为一直正确；属死代码，已删除 :87。验证：删除前后行为脚本断言一致（bool/int/float/str 写入+tomllib 回读+原地更新）、lint 干净、全量 694 passed。
- 附带发现 2（未处理，留待确认）：`config set` 在 GBK 控制台（中文 Windows 默认）下 rich 打印 `✓` 抛 `UnicodeEncodeError`——属环境编码问题，非本次范围。

---

## 8. 风险与边界（Boundary Warnings）

- **豁免过度 = 漏报**：Phase 2 的场景/熵值豁免若阈值标定不当，会把真实风险降级。必须用标注基准卡阈值。
- **AST 化重构回归**：Phase 3 改动检测路径，可能改变既有 finding 集合；需全量回归 + 基准对比。
- **跨函数污点性能**：`paths_between` 在大型项目上的复杂度未评估（`max_depth=4` 是当前上限），大库可能超时 `[未验证]`。
- **行内豁免滥用**：用户可能用 `# codeguardian: ignore` 掩盖真实问题；建议豁免需带规则 ID 且在报告中可见（计数/列表）。
- **测试路径启发式**：非常规测试目录命名（`checks/`、`verification/`）不会被豁免（Phase 0 已述边界）。

---

## 9. 未验证假设汇总 `[Contains Unverified Assumptions]`

1. §1 标注基准的构建成本与覆盖率未验证（依赖人工标注）。
2. §5.2/§5.3 的场景关键词清单与熵阈值未标定。
3. §6.2 跨函数污点的净效果与性能未实测，需先出可行性报告。
4. 20 个预存在失败的具体修复路径未逐一分析（仅确认其与本次改动无关）。
