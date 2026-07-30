<p align="center">
  <h1 align="center">CodeGuardian CLI</h1>
  <p align="center">
    <strong>多语言静态分析 · 跨函数调用图智能 · AI 深度代码审查</strong>
  </p>
  <p align="center">
    <a href="https://pypi.org/project/codeguardian/"><img src="https://img.shields.io/pypi/v/codeguardian?color=blue&label=PyPI" alt="PyPI version"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License"></a>
    <a href="https://github.com/nicq-codeguardian/CodeGuardian-CLI/actions"><img src="https://img.shields.io/github/actions/workflow/status/nicq-codeguardian/CodeGuardian-CLI/ci.yml?label=tests" alt="Tests"></a>
    <a href="https://github.com/nicq-codeguardian/CodeGuardian-CLI/stargazers"><img src="https://img.shields.io/github/stars/nicq-codeguardian/CodeGuardian-CLI?style=flat" alt="Stars"></a>
  </p>
  <p align="center">
    <a href="README.md">English</a> | <a href="README_zh.md">中文文档</a>
  </p>
</p>

---

CodeGuardian 是一款**静态代码分析 CLI 工具**，超越传统单文件 lint 检查。它构建**项目调用图索引 (PCI)** 来检测跨函数、跨文件边界的 bug — 空值传播、资源泄漏、污点流、异常安全违规 — 并可选地将高风险发现送入 **AI 验证和深度审查管线**，抑制误报并发现传统工具遗漏的架构级问题。

一条命令即可完成代码质量、安全、性能、架构、测试覆盖和演化风险的全面审计 — 每个发现都带有严重性、置信度和影响半径评分。

## 为什么选择 CodeGuardian？

| 传统 Lint 工具 | CodeGuardian |
|---|---|
| 单文件、单函数作用域 | 跨函数、跨文件调用图分析 |
| 语法模式匹配 | 数据流追踪（空值、污点、资源、异常） |
| 固定规则集 | 12 个并行引擎 + 可插拔 AI 审查 |
| 二元通过/失败 | 严重性 + 置信度 + 影响半径评分 |
| 无业务上下文 | 业务流程级分析（事务、鉴权、超时） |
| 人工分诊 | AI 驱动的误报抑制 |

---

## 目录

- [快速开始](#快速开始)
- [核心特性](#核心特性)
- [架构](#架构)
- [使用方式](#使用方式)
- [审查模式与覆盖度](#审查模式与覆盖度)
- [支持语言](#支持语言)
- [分析引擎](#分析引擎)
- [跨函数检测](#跨函数检测)
- [业务流程分析](#业务流程分析)
- [AI 功能](#ai-功能)
- [CI/CD 集成](#cicd-集成)
- [配置](#配置)
- [参与贡献](#参与贡献)
- [开源协议](#开源协议)

---

## 快速开始

```bash
# 1. 安装
pip install codeguardian

# 2. 扫描项目
codeguardian scan .

# 3. 检查发布就绪度
codeguardian gate .
```

无需配置即可使用 — CodeGuardian 自动检测语言、框架和构建系统。

### 从源码安装

```bash
git clone https://github.com/tester-rep/CodeGuardian.git
cd CodeGuardian-CLI
pip install -e ".[dev]"
codeguardian doctor   # 验证安装
```

---

## 核心特性

### 静态分析

- **12 个并行分析引擎** — 结构、度量、复杂度、缺陷、安全、性能、测试、Git演化、配置风险、面向对象设计、依赖、跨函数
- **项目调用图索引 (PCI)** — 跨文件解析调用目标，带置信度加权边，沿调用链传播函数摘要（空值/异常/资源/污点）
- **业务流程分析** — 从入口点（HTTP Handler、消息队列消费者、CLI命令）BFS遍历，检测流程级架构问题
- **影响评分** — 利用调用图计算每个发现的影响半径（受影响 caller 数量）
- **增量缓存** — 基于内容哈希的 PCI 缓存，大型代码库重复扫描速度大幅提升

### AI 智能层

- **AI 验证器** — 两轮误报重检，带严重性分级上下文窗口和调用图证据收集
- **AI 深度审查** — LLM 驱动的代码审查，两种模式：standard（单轮）和 ultra（3 个并行探索者 + 1 个验证者）
- **规则系统** — 可配置规则注册表，支持启用/禁用列表、标签过滤、严重性阈值、基线抑制

### 开发者体验

- **多格式输出** — Rich 终端、JSON、HTML、SARIF（CI集成）、PDF
- **质量门禁** — 基于 YAML 的发布门禁评估，支持 fail/warn 条件
- **自动检测** — 语言、框架、构建系统、测试框架自动识别
- **Semgrep 集成** — 可选的额外 SAST 覆盖（通过外部 Semgrep CLI）

---

## 架构

```
                                    codeguardian scan .
                                           |
                                           v
+---------------------------------------------------------------------------+
|                              CLI (Typer + Rich)                            |
+-------------------------------------+-------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------+
|                             Orchestrator                                   |
|                                                                           |
|  +--------------+  +---------+  +------------+  +-----------------------+ |
|  |   项目探测   |  | 规划器  |  | PCI构建器  |  |      调度器           | |
|  |   Detector   |->| Planner |->| (调用图)   |->| (异步并发)            | |
|  +--------------+  +---------+  +------------+  +-----------+-----------+ |
|                                                             |             |
|  +----------------------------------------------------------v----------+  |
|  |                   12 个分析引擎 (并行执行)                           |  |
|  |  structure | metrics | complexity | defect | security | performance |  |
|  |  testing | git_evolution | config_risk | oo_design | dependency     |  |
|  |  cross_function                                                     |  |
|  +----------------------------------------------------------+----------+  |
|                                                             |             |
|  +------------+  +----------+  +-------------+  +----------v---------+   |
|  | 标准化器   |->| 本地校验 |->| 优先级排序  |->|  影响评分器        |   |
|  +------------+  +----------+  +-------------+  +----------+---------+   |
|                                                             |             |
|  +-------------------+  +---------------------+  +----------v---------+   |
|  | 流程上下文注入    |->|    AI 验证器        |->|  AI 深度审查       |   |
|  | (业务流程关联)    |  | (两轮误报过滤)      |  | (LLM代码审查)      |   |
|  +-------------------+  +---------------------+  +----------+---------+   |
|                                                             |             |
|  +----------------------------------------------------------v----------+  |
|  |        报告器: Terminal | JSON | HTML | SARIF | PDF                  |  |
|  +---------------------------------------------------------------------+  |
+---------------------------------------------------------------------------+
```

---

## 使用方式

### 基础扫描

```bash
# 扫描当前目录（默认 standard 深度）
codeguardian scan .

# 扫描指定路径
codeguardian scan /path/to/project
```

### 进阶选项

```bash
# 全量扫描 + AI审查 + 多格式输出
codeguardian scan . --review-mode standard --report terminal,json,html

# 增量扫描（仅变更文件；调用图仍构建全量，保证跨函数分析完整）
codeguardian scan . --incremental --since HEAD~1

# Ultra 审查模式（3探索者 + 1验证者）
codeguardian scan . --review-mode ultra

# 完全禁用 AI（静态引擎仍全量运行）
codeguardian scan . --review-mode ai_off

# 丢弃AI确认的误报
codeguardian scan . --review-mode standard --drop-false-positives

# 跳过缓存，全量重新分析
codeguardian scan . --no-cache
```

### 质量门禁

```bash
codeguardian gate .
```

输出示例：

```
 GATE RESULT: FAIL

  x critical_findings <= 0          actual: 2    FAIL
  x high_findings <= 5              actual: 8    FAIL
  . test_coverage >= 60%            actual: 73%  PASS
  . security_score >= 70            actual: 82   PASS
```

### 其他命令

```bash
codeguardian doctor                          # 检查环境和依赖
codeguardian init                            # 初始化 codeguardian.toml
codeguardian explain NULL-PROP-UNCHECKED     # 解释某条规则
codeguardian diff main..feature-branch       # 差异分析
codeguardian watch .                         # 监听模式
codeguardian baseline .                      # 设置基线
codeguardian trend .                         # 查看趋势
```

---

## 审查模式与覆盖度

用两个正交维度取代旧的单一 `--depth`：

**AI 审查模式**（`--review-mode` 或 `scan.review_mode`）——唯一的 AI 开关：

| 模式 | 静态引擎 | PCI | AI 深度审查 | 适用场景 |
|------|----------|-----|-------------|----------|
| `ai_off` | 全部11个 | 是 | 否 | 快速、离线、无 API Key |
| `standard` | 全部11个 | 是 | 单-pass | CI 管线日常扫描（默认） |
| `ultra` | 全部11个 | 是 | 多探索者 + 验证者 | 发版候选审查 |

**覆盖度**（`--incremental` / `--since`）——与审查模式独立：

| 参数 | 分析文件 | 说明 |
|------|----------|------|
| _（无）_ | 全量项目 | 默认 |
| `--incremental [--since REV]` | 仅变更文件 | 调用图(PCI)仍按**全量**项目构建以保证跨函数分析完整；跨函数发现随后收敛到变更文件 |

```bash
codeguardian scan . --review-mode ai_off              # 仅静态
codeguardian scan . --review-mode standard            # 默认
codeguardian scan . --review-mode ultra --incremental # 对 diff 做深度 AI
```

---

## 支持语言

| 语言 | AST 解析 | 跨函数分析 | 导入解析 | 成熟度 |
|------|---------|-----------|---------|--------|
| C++ | tree-sitter | 是 | 头文件包含 | 稳定 |
| Java | tree-sitter | 是 | 包导入 | 稳定 |
| Go | tree-sitter | 是 | 模块导入 | 稳定 |
| Python | tree-sitter | 是 | 模块导入 | 稳定 |
| JavaScript | tree-sitter | 是 | ES/CommonJS | 稳定 |
| TypeScript | tree-sitter | 是 | ES导入+类型 | 稳定 |
| Lua | tree-sitter | 是 | require() | 稳定 |
| C# | tree-sitter | 是 | using/namespace | 稳定 |
| Rust | tree-sitter | 部分 | use/mod | Beta |

---

## 分析引擎

| 引擎 | 聚焦领域 | 关键发现 |
|------|---------|----------|
| **structure** | 代码组织 | 模块耦合、循环依赖、上帝类 |
| **metrics** | 度量指标 | 代码行数、函数数、嵌套深度、认知复杂度 |
| **complexity** | 复杂度 | 过度复杂函数、深层嵌套逻辑 |
| **defect** | 常见缺陷 | 空指针解引用、偏差一错误、死代码、类型混淆 |
| **security** | 安全漏洞 | 注入、硬编码密钥、不安全反序列化 |
| **performance** | 运行效率 | N+1查询、无界分配、异步中的阻塞IO |
| **testing** | 测试质量 | 低覆盖率指示、边界用例缺失、不稳定测试模式 |
| **git_evolution** | 变更风险 | 热点文件、代码流转相关性、最近故障区域 |
| **config_risk** | 配置问题 | 暴露的密钥、不安全默认值、缺失验证 |
| **oo_design** | 设计质量 | SOLID违反、贫血模型、过深继承 |
| **dependency** | 供应链 | 过期依赖、已知CVE、许可证冲突 |
| **cross_function** | 过程间缺陷 | 空值传播、资源泄漏、污点流（见下文） |

---

## 跨函数检测

跨函数引擎使用**项目调用图索引 (PCI)** 检测跨越多个函数和文件的 bug — 这类 bug 是单文件 lint 工具从根本上无法发现的。

### PCI 工作原理

```
1. 解析所有文件        -> 提取结构 (tree-sitter AST)，含类的 extends/implements
2. 构建符号表          -> 所有函数/方法/类 + 继承层级，O(1) 查找
3. 解析导入            -> 语言特定的导入解析器
4. 提取调用点          -> 从所有函数体中提取
5. 解析目标            -> 构建带置信度权重边的调用图（利用继承层级解析父类/接口的虚方法调用）
6. 计算摘要            -> 每个函数的 null/throw/resource/taint 行为
7. 传播                -> 沿调用边定点传播 (最多3轮)
```

> 继承信息（`extends`/`implements`）由解析器抽取并登记到符号表，使 `self.method()` / `this.method()` 等能解析到父类中定义的方法（虚调用解析）。当前抽取覆盖 Python / Java / JavaScript / TypeScript / Go / C++。其中 Go 无 `extends` 概念，结构体与接口的**嵌入类型**（embedding）被视为基类；C++ 支持多重继承，`base_class_clause` 中的所有基类均登记为基类。

### 调试导出调用图

设置环境变量 `CODEGUARDIAN_PCI_DUMP=<路径>` 后扫描，会将调用图导出为 JSON（节点、`call_edges`、`type_edges`（inherits/implements）），用于排查跨函数解析问题。默认关闭，不影响扫描性能。

```bash
CODEGUARDIAN_PCI_DUMP=graph.json codeguardian scan ./src
```

### 检测规则

| 规则 ID | 类别 | 检测内容 |
|---------|------|---------|
| `NULL-PROP-UNCHECKED` | 空值安全 | 被调函数可能返回null，调用方未检查直接使用 |
| `RESOURCE-NEVER-CLOSED-XFUNC` | 资源泄漏 | 资源获取后在可达调用链中无释放路径 |
| `RESOURCE-LEAK-ON-EXCEPTION` | 异常安全 | 资源获取后被调方可能抛异常，无finally/defer/with保护 |
| `TAINT-CROSS-FUNCTION` | 注入 | 用户输入经调用链到达危险接收端且无净化 |
| `UNCAUGHT-EXCEPTION-PROPAGATION` | 异常安全 | 异常沿调用链逃逸到入口点无任何捕获 |
| `LOCK-LEAKED-ON-CALLEE-THROW` | 并发 | 持锁时被调方可能抛异常，无finally保护释放 |
| `ERROR-RETURN-IGNORED` | API契约 | 错误返回类型（Go error、Optional）被调用方忽略 |

### 示例

```java
// FileA.java
public Connection getConnection() {
    return pool.acquire();  // 连接池耗尽时可能返回null
}

// FileB.java - 调用链深度3层
public void processOrder(String orderId) {
    Connection conn = service.getConnection();
    conn.execute(query);  // <- NULL-PROP-UNCHECKED: conn可能为null
}
```

CodeGuardian 通过调用图追踪并报告：

```
CRITICAL  NULL-PROP-UNCHECKED  FileB.java:42
  FileA.getConnection() 返回的null在 FileB.processOrder() 中未经检查即使用
  调用链: processOrder -> service.getConnection -> pool.acquire [may-return-null]
  影响: 7个调用方受影响 (影响半径: 高)
```

---

## 业务流程分析

CodeGuardian 从检测到的入口点（HTTP Handler、消息队列消费者、CLI命令、定时任务）进行 BFS 遍历，分析完整业务流程中的架构级问题。

### 检测规则

| 规则 ID | 类别 | 检测内容 |
|---------|------|---------|
| `BIZ-NO-TRANSACTION-BOUNDARY` | 一致性 | 多步写操作流程无事务边界 |
| `BIZ-PARTIAL-FAILURE-RISK` | 一致性 | 顺序操作中间失败导致数据不一致 |
| `BIZ-CASCADING-TIMEOUT` | 性能 | 链式服务调用无超时传播 |
| `BIZ-SENSITIVE-NO-AUDIT` | 安全 | 敏感操作（支付、删除）无审计日志 |
| `BIZ-MULTI-ENTRY-NO-AUTH` | 安全 | 多入口可达的业务逻辑部分缺少鉴权 |
| `BIZ-NOT-IDEMPOTENT` | 重试安全 | 非幂等操作暴露于重试/重放 |
| `BIZ-ERROR-SWALLOWED-MIDFLOW` | 错误处理 | 流程中间吞没错误，下游假定成功 |
| `BIZ-READ-WRITE-NO-LOCK` | 并发 | 先读后写模式无并发控制 |
| `BIZ-IO-IN-LOOP` | 性能 | 循环内执行数据库/网络调用（N+1模式） |
| `BIZ-SENSITIVE-DATA-LEAK` | 安全 | PII/凭证流向日志、响应或外部服务 |

发现附带**完整业务流程路径**，让你清楚看到哪个操作流程受到影响。

---

## AI 功能

AI 功能**可选**，需要 OpenAI 兼容的 API 端点。CodeGuardian 完全可以离线工作 — 12个引擎和 PCI 分析是纯静态分析。

### 配置

```toml
# codeguardian.toml
[scan]
review_mode = "standard"               # ai_off | standard | ultra（唯一 AI 开关）

[ai]
# ai.enabled 由 scan.review_mode 派生，无需手动设置
provider = "openai"                    # 任何 OpenAI 兼容端点
model = "gpt-4o"
api_key_env = "CODEGUARDIAN_API_KEY"
# base_url = "https://api.openai.com/v1"  # 自定义端点
```

```bash
# .env
CODEGUARDIAN_API_KEY=sk-...
```

### AI 验证器（两轮误报过滤）

在优先级排序后运行，典型代码库误报率降低 40-60%。

**第一轮** (轻量)：最小上下文 (±10行)，轻量模型 — 快速分诊。

**第二轮** (重量)：对不确定、严重或高优先级发现触发。包含：
- 完整函数体（按严重性分级：critical 最多400行）
- 文件导入和类型上下文
- 跨文件 caller/callee（critical 最多2跳）
- 高误报规则的增强证据（共享状态使用、catch体、生命周期令牌）

### AI 深度审查 (review_mode=standard/ultra)

7步管线执行 LLM 驱动的代码审查：

1. **索引** — 构建项目索引（函数/类签名）
2. **分块** — 将源码拆分为可审查单元
3. **过滤** — 按发现数、最近变更、复杂度优先排序
4. **预算** — 跨分块分配 token 预算
5. **上下文** — 打包签名、本地发现、自定义规则
6. **审查** — AI 审查（带重试和并发控制）
7. **合并** — 合并为主要 + 补充发现

**Ultra 模式** (`--review-mode ultra`)：
- 3个探索者并行运行，各聚焦一个维度（安全/逻辑/资源错误）
- 1个验证者验证合并发现，过滤 ~60-70% 误报

```bash
codeguardian scan . --review-mode ultra
```

---

## CI/CD 集成

### SARIF 输出

导出 [SARIF](https://sarifweb.azurewebsites.net/) 格式用于 GitHub Code Scanning、Azure DevOps 等平台集成：

```bash
codeguardian scan . --report sarif --output results.sarif
```

### GitHub Actions

```yaml
# .github/workflows/codeguardian.yml
name: CodeGuardian Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install CodeGuardian
        run: pip install codeguardian

      - name: Run Analysis
        run: codeguardian scan . --report sarif --output results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Quality Gate
        run: codeguardian gate .
```

### 质量门禁

在 `gate.yaml` 中定义通过/失败条件：

```yaml
rules:
  - metric: critical_findings
    operator: "<="
    threshold: 0
    action: fail

  - metric: high_findings
    operator: "<="
    threshold: 5
    action: fail

  - metric: security_score
    operator: ">="
    threshold: 70
    action: warn
```

### 基线抑制

渐进式采用 — 将现有发现设为基线，只有新增问题阻断 CI：

```bash
codeguardian baseline .    # 记录当前发现为基线
codeguardian scan .        # 之后只报告新增发现
```

### 静态误报抑制

在基线与 AI 验证之前，扫描器内置四层确定性的误报削减（无需配置）：

- **占位符 / 环境变量凭据过滤** — `HARDCODED-PASSWORD` 只报告真实凭据。`changeme`、`your_password_here`、`xxx` 等占位符值，以及 `$VAR` / `${VAR}` / `%VAR%` 环境变量引用不命中（跨 Python / Java / JavaScript / Go / C++ 及正则回退路径统一生效）。
- **低熵凭据过滤** — `HARDCODED-PASSWORD` 进一步排除低熵值：常见弱口令 / 默认词（`admin`、`localhost`、`123456` 等），以及短单一字符类串（纯数字、纯小写字母且 <8 位）—— 这些几乎不可能是真实凭据，高熵值仍报。
- **测试路径豁免** — 测试文件（`tests/`、`test/`、`spec/`、`__tests__/` 目录，及 `test_*`、`*_test.go`、`*.spec.ts` 等命名）不属于部署攻击面：其中的安全规则（硬编码密钥、注入类等）与性能启发式规则（`SQL-IN-LOOP`、`MISSING-PAGINATION`、`SELECT-STAR-NO-LIMIT`）自动抑制，避免测试夹具 / mock 淹没报告。
- **场景感知豁免（Python）** — `WEAK-HASH` 与 `INSECURE-RANDOM` 依据所在函数名判断用途：处于明确非安全场景（`checksum`/`cache`/`etag`/`sample`/`shuffle`/`jitter`/`backoff` 等）时不报；处于安全场景（`password`/`token`/`secret`/`verify` 等）或无法判定时仍报（保守）。Python 这两个规则统一走 AST 路径，避免无上下文的正则重复命中。

以上削减的净效果由 `benchmark/fp_corpus`（合成误报语料 + 标注）持续度量，跑 `pytest tests/test_fp_benchmark.py` 输出精确率 / 召回。

---

## 配置

### `codeguardian.toml`

```toml
[scan]
review_mode = "standard"              # ai_off | standard | ultra（唯一 AI 开关）
languages = ["java", "go", "python"]  # 不填则自动检测
exclude = ["vendor/", "generated/"]

[rules]
min_severity = "low"
# enabled = ["NULL-*", "BIZ-*"]
# disabled = ["STYLE-*"]

[ai]
# ai.enabled 由 scan.review_mode 派生，无需手动设置
provider = "openai"
model = "gpt-4o"
api_key_env = "CODEGUARDIAN_API_KEY"

[ai.deep_review]
# review_mode 由 scan.review_mode 派生（standard/ultra），无需在此设置

[ai.ai_verify]
enabled = true

[risk]
default_threshold = 60

[gate]
config_path = "gate.yaml"
```

### 配置优先级

```
CLI 参数  >  环境变量  >  codeguardian.toml  >  内置默认值
```

---

## 参与贡献

欢迎贡献！快速开始：

```bash
git clone https://github.com/tester-rep/CodeGuardian.git
cd CodeGuardian-CLI
pip install -e ".[dev]"

pytest                   # 运行测试
ruff check src tests     # 代码检查
mypy src                 # 类型检查
```

### 项目结构

```
src/codeguardian/
├── cli/            # Typer 命令和输出格式化
├── core/           # Orchestrator, ScanContext, Planner, Scheduler
│   └── call_graph/ # PCI: SymbolTable, CallGraph, FunctionSummary, PCIBuilder
├── engines/        # 12 个分析引擎 (AnalyzerEngine 协议)
├── parsers/        # Tree-sitter 多语言 AST 解析
├── ai/             # AI 路由器、验证器、深度审查管线
│   ├── verifier/   # 两轮误报过滤 + 证据收集器
│   └── deep_review/# 7步 LLM 审查管线
├── risk/           # 风险评分、优先级排序、发布门禁
├── models/         # Pydantic v2 数据模型
├── reporters/      # 输出格式化器 (Terminal, JSON, HTML, SARIF, PDF)
├── config/         # TOML 配置加载和 schema
├── detectors/      # 自动检测 (语言、框架、构建、测试)
└── utils/          # 工具函数
```

### 添加新引擎

实现 `AnalyzerEngine` 协议：

```python
class MyEngine:
    @property
    def name(self) -> str:
        return "my_engine"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        findings = []
        # ... 分析逻辑 ...
        return EngineResult(findings=findings)
```

在 Planner 中注册即可与内置引擎一起调度。

---

## 对比

| 特性 | CodeGuardian | SonarQube | Semgrep | CodeQL |
|------|-------------|-----------|---------|--------|
| 跨函数调用图 | 是 (PCI) | 有限 | 否 | 是 |
| 业务流程分析 | 是 | 否 | 否 | 否 |
| AI 误报过滤 | 是 | 否 | 否 | 否 |
| AI 深度审查 | 是 | 否 | 否 | 否 |
| 影响/爆炸半径评分 | 是 | 否 | 否 | 否 |
| 安装复杂度 | `pip install` | 服务器+数据库 | `pip install` | 需要构建 |
| 离线可用 | 是 | 是 | 是 | 是 |
| 语言支持 | 9 | 30+ | 30+ | 15+ |
| SARIF 导出 | 是 | 否 | 是 | 是 |
| 质量门禁 | YAML 配置 | 内置 | CLI 标志 | Actions |

---

## 开源协议

[Apache License 2.0](LICENSE) — 可自由用于商业和开源项目。

---

<p align="center">
  <sub>为交付可靠软件的工程师而构建。</sub>
</p>
