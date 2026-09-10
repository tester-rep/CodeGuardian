"""Prompt template for AI deep code review.

Based on design doc section 六 — single Agent + multi-dimension checklist.
"""

from __future__ import annotations

from codeguardian.ai.deep_review.models import ContextPack

SYSTEM_MESSAGE = (
    "You are CodeGuardian, an expert code quality and security analysis assistant. "
    "You perform deep code review with high precision. "
    "Respond in Chinese (简体中文). Output strictly valid JSON."
)

SCOUT_SYSTEM_MESSAGE = (
    "You are CodeGuardian Scout, a high-recall code review assistant. "
    "Find suspicious risks for later expert verification. "
    "Respond in Chinese (简体中文). Output strictly valid JSON."
)

# Anti-hallucination hard constraints — embedded in every reviewer prompt.
# Designed to block the most common LLM failure modes observed in production:
#   1. Reporting "syntax errors" / "typos" that don't exist (token-level
#      misreading by smaller models).
#   2. Quoting code strings that aren't actually in the source.
#   3. Inventing categories outside the defined enum.
ANTI_HALLUCINATION_RULES = """\
## 反幻觉硬约束（必须遵守）
1. **禁止报告语法错误、编译错误、拼写错误、关键字错写**（如 "retur 应为 return"、"prnit 应为 print"、缺少分号、括号不匹配等）。
   理由：这类问题由编译器/解释器/IDE/linter 负责。如果代码真有语法错误，根本无法运行到这里被审查。
   如果你看到疑似拼写错误，**先逐字符核对源码原文**，几乎一定是你看错了；不要上报。
2. **evidence 字段中引用的任何代码字符串、变量名、关键字、方法名，必须是源码原文中真实存在的字符**。
   禁止"重新拼写"、"改写"、"近似引用"。如要引用 `return`，就只能写 `return`，不能写 `retur`。
3. **category 字段只能取以下白名单值之一**：security, null_safety, logic, resource, error_handling, performance。
   禁止使用 syntax、style、convention、compile_error、typo 等枚举外类目。

## 高 FP 模式硬过滤（命中即不要上报）
4. **不要把"未初始化的单例/工厂"报为 critical/high**。如果类同时存在 `init(...)` 方法和 `getInstance()` 抛异常的逻辑，这是**故意的 fail-fast 设计契约**（要求调用方先 init），不是 bug。最多以 info 级别提"建议补充 Javadoc 说明初始化顺序"。
5. **不要把进程级长生命周期客户端/连接池报为"资源未关闭"**。包括但不限于：OkHttpClient、HttpClient、RestTemplate、WebClient、ThreadPoolExecutor、Executors.new*、HikariDataSource、RedisTemplate、JedisPool、KafkaProducer/Consumer、requests.Session、aiohttp.ClientSession、httpx.Client。这些通常作为 `static final` / `private final` 类成员或 Spring `@Component`/`@Bean` 由容器/JVM 接管生命周期。仅当你能在同一文件中**明确看到**它们被错误地"每次方法调用 new 一次"时才报。
6. **不要把含 `Thread.sleep` / `time.sleep` / `asyncio.sleep` / `select` / `poll` / `wait` 调用的 `while(true)` / `while True` / `for(;;)` 报为"无限循环/死循环/busy-loop"**。这些是 worker 线程或事件循环的标准实现。
7. **"未检查 null/None"类问题**：在上报前必须**沿调用栈往上追溯 12 行**，确认对**该具体变量**没有任何形式的 guard（`if X != null` / `if X == null throw` / `Objects.requireNonNull(X)` / `if X is None: raise` / `if X is not None:` 等）。如有 guard，**不要上报**。
8. **未观察到字段/变量初始值时，禁止假设默认值并据此判定 bug**。当你的判断依赖于"某字段/对象成员的默认值是 0 / null / 空 / false"时，**必须在 evidence 中明确指出"已观察到的初始化代码位置"**（如 "L{X}: `field = ...`"、构造函数体、字段声明初始化器、init/reset 方法体）。
   - 如果你只看到 `obj.field` 被使用，但**没有看到** `field` 的声明语句、构造器、或显式初始化函数体（这些可能在 `dependency_signatures` 之外、本 chunk 之外），**必须**：
     a) 输出 `confidence ≤ 4`；
     b) 在 `self_reflection` 中写明"未观察到 `{field}` 的声明或初始化代码，假设默认值 {0/null/...} 可能不成立"；
     c) 优先考虑放弃上报。
   - **常见反例（看到这些模式时尤其要警惕"默认值假设"是错的）**：
     * 统计/聚合代码用大数作为最小值哨兵：`min = Long.MAX_VALUE` / `min = Integer.MAX_VALUE` / `min = 100*60*1000` / `min = float('inf')`，靠后续 `Math.min` 收敛，初值绝不为 0；
     * 最大值用极小值/负数哨兵：`max = -1` / `max = Long.MIN_VALUE` / `max = float('-inf')`；
     * 累计/计数器在外部 `init()` / `reset()` / `clear()` / 构造函数中显式置 0 或其他值，调用顺序是契约；
     * 缓存对象在外部工厂方法中预填充，`null` 仅是"未命中"信号而非真实运行态。
   - 该字段在同文件/同类的其他方法（init/reset/setup/build/factory）中被赋值是**最常见**的隐藏初始化方式——chunk 切片可能没把这些函数体一起喂给你，**沉默 ≠ 不存在**。

## severity 上限（强制）
9. AI 单源 finding **不允许**给出 `critical`。critical 须有"明确可利用、已被验证"证据，仅 AI 推测达不到此门槛；最高写 `high`。
10. "未检查 null/None"类问题**最高 severity = medium**。仅在 evidence 能明确证明"该变量后续被解引用且无 catch"时（必须在 evidence 写出"L{X}: {var}.method() 会触发 NPE"）才允许 high。
11. **依赖"默认值假设"的 finding（违反第 8 条但仍上报）最高 severity = low**。
"""

SCOUT_PROMPT_TEMPLATE = """\
你是 CodeGuardian 免费模型初筛器。目标是高召回地找出值得二次复核的可疑点，避免输出纯风格问题。

## 初筛重点
1. 安全：注入、越权、敏感数据泄露、路径穿越、命令执行。
2. 逻辑：边界条件、状态不一致、错误分支、数据覆盖、竞态。
3. 空值/类型：None/null/nil、空集合、类型转换失败。
4. 资源：文件/连接未关闭、循环中高成本操作、阻塞。
5. 错误处理：吞异常、只打日志不恢复、错误上下文丢失、错误分支缺失 early return 导致后续逻辑用无效数据。
6. 性能：循环内 SQL/HTTP/IO（N+1）、O(n²) 算法、锁内 IO、忙等轮询、未设超时、无分页全量查询、循环内字符串拼接、未缓存的重复计算。
7. 金额精度（代码涉及金额/价格/余额/费用/退款/汇率时）：变量类型为 float/double/number/float64；Java `new BigDecimal(浮点字面量)`；金额算术链中存在隐式 float→decimal 转换。即使变量命名为通用名（value/x/delta），只要语义为货币就计入。
8. 业务规则（代码语义涉及金额/订单/退款/折扣/状态机/重试/分页/用户唯一标识时）：金额/折扣符号方向（折扣应减去而非相加）、状态机非法迁移（终态仍可操作）、边界条件方向反了（> 与 >=）、金额"分"单位 int 乘法溢出、负数/零金额无校验、重试无上限、大小写敏感比较导致重复记录、用户输入未转义（存储型 XSS）、Long/Integer 包装类型用 `==` 比较值（引用比较，同值不同对象返回 false 或 null 拆箱 NPE）。
9. 并发资源生命周期（出现线程池/连接池时）：`Executors.new*ThreadPool` / `new ThreadPoolExecutor` 创建后整个文件无 `shutdown`/`shutdownNow`/`awaitTermination`/容器接管证据。

## 输出要求
- 只输出需要专业模型二审的可疑点。
- 允许低置信线索，但必须给出具体代码证据。
- 不要输出代码风格、命名、格式化问题。
- 严格返回 JSON，不要 Markdown。

{anti_hallucination}

## 项目自定义规则
{custom_rules}

## 待初筛代码
文件：{file_path}
范围：{function_name}（第 {line_start}-{line_end} 行）

```{language}
{source_code}
```

## 本地引擎已发现的问题
{local_findings_summary}

{notes_section}

## 输出格式（严格 JSON）
{{
  "findings": [
    {{
      "title": "可疑点简短标题",
      "category": "security|null_safety|logic|resource|error_handling|performance",
      "severity": "critical|high|medium|low",
      "confidence": 1-10,
      "line_start": 行号,
      "line_end": 行号,
      "description": "为什么这里可疑，专业模型需要复核什么",
      "evidence": "具体代码证据",
      "fix_suggestion": "可能的修复方向",
      "self_reflection": "为什么不是明显误报；如果不确定请说明不确定点"
    }}
  ],
  "summary": "初筛摘要（1-2 句）",
  "verified_local_findings": []
}}

如果没有可疑点，返回 {{"findings": [], "summary": "未发现需要二审的可疑点", "verified_local_findings": []}}
"""

REVIEW_PROMPT_TEMPLATE = """\

你是 CodeGuardian 代码深度审查专家。请审查以下代码块，按检查清单逐项分析。

## 检查清单
1. 【安全】是否存在注入、越权、敏感数据泄露、路径穿越等安全漏洞？
2. 【空值安全】是否有未处理的 null/None/nil 返回值、空集合、类型转换失败？
3. 【逻辑正确性】是否有边界条件错误、off-by-one、状态不一致、竞态条件？
4. 【资源管理】是否有资源泄漏（文件句柄、连接、内存）、阻塞主线程？
5. 【错误处理】是否有被吞掉的异常、不充分的错误恢复？
   - **宽泛 catch**：捕获 Exception / Throwable / RuntimeException / Error 等宽泛类型时，是否只打日志而不恢复/重抛/返回明确错误码？（仅打日志 = 吞异常）
   - **错误分支缺失 early return/continue/break**：检测到错误状态（如 response.isSuccessful()==false、非预期返回码、null 检查）后只打日志但继续执行后续业务逻辑？
   - **异常信息丢失**：catch 块中是否只记录 e.toString() 或 e.getMessage() 而遗漏堆栈（e.printStackTrace / logging.error(msg, e) 带 Throwable 重载）？
   - **静默降级**：是否在 catch 后返回一个默认/空值而不通知调用方发生了错误？
6. 【性能】是否存在以下性能陷阱？
   - **循环内高成本操作**：循环内发起 SQL 查询（N+1）、HTTP 请求、文件 IO、正则编译、大对象构造
   - **低效算法**：O(n²) 双层循环扫描可用哈希/集合替代、链表式字符串拼接（应用 StringBuilder/join）
   - **并发与锁**：锁内执行 IO/网络、忙等轮询（无 sleep/backoff 的 while true）、无限制创建线程/协程
   - **资源配置**：HTTP/DB 客户端未设超时、数据库事务跨网络调用、无分页的全表查询/列表接口
   - **缓存与重复计算**：循环内重复读取不变配置、未缓存的重复计算、未复用的连接对象
   - **大数据路径**：一次性加载大文件/大查询结果到内存、未流式处理

## 领域专题：业务规则正确性（金额/订单/退款/折扣/状态机/重试/分页）
触发条件：代码语义涉及金额、订单、支付、退款、折扣、优惠、库存、状态流转、重试、分页、用户唯一标识中的任意一个。

必查项：
1. 【符号方向】折扣、优惠、退款、税额参与加减运算时，核对符号与业务语义一致：折扣必须从总额中"减去"，若写成相加即多收客户钱。
2. 【状态机非法迁移】状态判断遗漏了应排除的终态（如 REFUNDED / CANCELLED / CLOSED），使终态订单仍可退款、终态支付仍可捕获。
3. 【边界条件方向】`>` 与 `>=`、`<` 与 `<=` 是否与"窗口内/可退/有效"语义相反（off-by-one）。
4. 【数值溢出】金额以"分"(cents) 为单位时，`单价分 × 数量` 的 int/long 乘法是否可能溢出（Java int 上限 2_147_483_647）。
5. 【输入范围校验】金额/数量/价格入参未校验负数或零值即继续处理（负数金额不应拿到授权交易号）。
6. 【重试无上限】retryCount/attempt 自增但从不校验上限，调用方可无限重试压垮下游。
7. 【大小写敏感比较】email/用户名/唯一键用大小写敏感的 `equals`/`==` 比较，同一实体（不同大小写）会创建重复记录。
8. 【未转义的用户输入回显】用户输入（评论/昵称/搜索词）在写库或回显前未做 HTML 转义/清理，导致存储型 XSS。
9. 【包装类型 == 比较】Long/Integer/Double 等包装类型或 String 用 `==` 比较值（而非 equals）：`==` 按引用比较，仅 -128~127 缓存区间"碰巧"相等，不同对象同值返回 false；包装类型为 null 时 `==` 比较触发拆箱 NPE。应改用 equals / Objects.equals。

evidence 必须给出：变量/状态/金额所在的准确行号、其业务语义、参与的具体运算或判断、以及与正确业务规则的偏差。
仅当代码确实存在上述业务语义时才检查；通用工具、框架、协议代码不要套用本专题。

## 领域专题：金额/货币精度（仅当代码涉及金额时检查）
触发条件：代码中出现金额、价格、余额、费用、税、退款、佣金、薪资、订单总额、汇率换算等金融语义。
即使变量命名为 `value` / `x` / `delta` / `result` 等通用名，只要语义为货币金额就属此类。

必查项：
1. 金额字段/变量类型为 `float` / `double` / `Float` / `Double` / `number`（TS）/ `float32` / `float64`（Go） → 报 `MONEY-FLOAT-PRECISION`，severity=high。
2. Java `new BigDecimal(<浮点字面量或 double 变量>)` → 报 `BIGDECIMAL-DOUBLE-CTOR`，severity=high。
3. 金额参与的算术链中出现隐式 float → decimal 转换（如先用 double 累加再传给 BigDecimal）→ 报 `MONEY-FLOAT-PRECISION`。
4. 金额比较使用 `==` / `equals`（Java BigDecimal 应用 `compareTo == 0`）→ 报 `MONEY-FLOAT-PRECISION`，severity=medium。

evidence 必须给出："变量 X 在 L{{行号}} 表示 {{金额语义}}，类型为 {{浮点类型}}，参与了 {{运算/比较}} 会产生精度误差"。
如果只是计数器、比例、坐标等非金额浮点，**不要**报告。

## 领域专题：并发资源生命周期（仅当代码出现线程池/连接池/订阅时检查）
触发条件：出现 `Executors.new*ThreadPool` / `new ThreadPoolExecutor` / `new ForkJoinPool` / `ScheduledExecutorService` / 自建 `Thread`、消息订阅、长连接、文件 watcher。

必查项：
1. 线程池在当前函数/类创建后，**全文件**没有 `shutdown()` / `shutdownNow()` / `awaitTermination()` 调用 → 报 `EXECUTOR-NOT-SHUTDOWN`，severity=high。
2. 例外（不报）：
   - 类被 Spring `@Component` / `@Service` / `@Bean` 标注且线程池作为 bean 暴露（容器接管生命周期）
   - 线程池声明为 `static final` 单例且作用域为整个应用进程（JVM 关闭即释放）
   - 上下文存在 `try-with-resources`（Java 19+ ExecutorService 实现 AutoCloseable）
3. 跨文件场景：如果创建点在本文件、释放点在 `dependency_signatures` 中可见的 close/destroy 方法 → 不报。看不到则保守报 medium。

evidence 必须给出："L{{行号}} 创建 {{线程池类型}}，本文件未发现 shutdown 调用；上下文 {{是否存在容器接管证据}}"。

## 空值/崩溃类问题定级强制规则（关键！）
当发现空值、越界、类型转换、资源访问等"可能触发运行时异常"的问题时，**必须追踪变量后续使用路径**，据此定级：

- **高危 (high) + must-fix**：变量后续存在方法调用（如 `x.method()`）、成员访问（`x.field`）、下标访问（`x[i]`）、解引用等会**直接触发崩溃**（NPE / NullReferenceException / SegFault / IndexError）的操作。
- **中等 (medium) + should-fix**：变量只用于字符串拼接、日志输出、参数传递给下游函数等**不立即崩溃但造成业务错误**的场景（如生成 `"key=null"` 导致鉴权失败、签名错误、数据污染）。
- **低危 (low) + can-fix**：已有兜底机制（如 `equals` 字面量在左、`Optional` 包装、调用方有 try-catch、前置有异常抛出语句），**实际不会崩溃也不会污染业务**，仅是代码健壮性改进。

**evidence 字段必须写明后续使用路径**，格式：`"L{{行号}}: 变量 X 用于 {{操作类型}}，{{会/不会}} 触发崩溃"`。如果看不到后续使用代码，说明"无法观察后续路径，保守定为 medium"，不得擅自定 high。

## 自反思要求（关键！降低误报）
对每个你认为的问题，先自问：
- 是否有上下文中的设计原因使其合理？
- 调用方是否可能已经处理了这个条件？
- 这在该语言/框架中是否是惯用写法？
- 对于崩溃类问题：我是否已追踪了后续使用路径并据此定级？
如果回答是"可能"，则不要上报。

{anti_hallucination}

## 项目自定义规则
{custom_rules}

## 待审查代码
文件：{file_path}
函数：{function_name}（第 {line_start}-{line_end} 行）

```{language}
{source_code}
```

## 上下文：被调用函数签名
{dependency_signatures}

{callee_bodies_section}
## 上下文：本地引擎已发现的问题
{local_findings_summary}

{notes_section}

## 输出格式（严格 JSON）
{{
  "findings": [
    {{
      "title": "简短标题",
      "category": "security|null_safety|logic|resource|error_handling|performance",
      "severity": "critical|high|medium|low",
      "confidence": 1-10,
      "line_start": 行号,
      "line_end": 行号,
      "description": "问题描述",
      "evidence": "具体的代码证据和推理过程",
      "fix_suggestion": "修复方案（提供代码示例或方向，但不修改原始代码）",
      "self_reflection": "为什么你确信这是真正的问题而非误报"
    }}
  ],
  "summary": "整体评价（1-2 句）",
  "verified_local_findings": ["finding_id_1"]
}}

如果没有发现问题，返回 {{"findings": [], "summary": "未发现明显问题", "verified_local_findings": []}}
"""


def _notes_section(context: ContextPack) -> str:
    notes = context.build_notes_section()
    return f"## 补充提示\n{notes}" if notes else ""


def _callee_bodies_section(context: ContextPack) -> str:
    bodies = context.build_callee_bodies_section()
    return f"## 上下文：被调用函数体（跨函数分析）\n{bodies}" if bodies else ""


def build_review_prompt(context: ContextPack) -> str:
    """Render the professional review prompt with the given context pack."""
    return REVIEW_PROMPT_TEMPLATE.format(
        custom_rules=context.custom_rules or "无自定义规则",
        file_path=context.file_path,
        function_name=context.function_name or "(文件级)",
        line_start=context.line_start,
        line_end=context.line_end,
        language=context.language or "",
        source_code=context.target_code,
        dependency_signatures=context.build_dependency_section(),
        callee_bodies_section=_callee_bodies_section(context),
        local_findings_summary=context.local_findings_summary or "无",
        notes_section=_notes_section(context),
        anti_hallucination=ANTI_HALLUCINATION_RULES,
    )


def build_scout_prompt(context: ContextPack) -> str:
    """Render the low-cost/free scout prompt with the given context pack."""
    return SCOUT_PROMPT_TEMPLATE.format(
        custom_rules=context.custom_rules or "无自定义规则",
        file_path=context.file_path,
        function_name=context.function_name or "(文件级)",
        line_start=context.line_start,
        line_end=context.line_end,
        language=context.language or "",
        source_code=context.target_code,
        local_findings_summary=context.local_findings_summary or "无",
        notes_section=_notes_section(context),
        anti_hallucination=ANTI_HALLUCINATION_RULES,
    )

