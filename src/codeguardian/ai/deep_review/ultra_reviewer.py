"""UltraReviewer — multi-dimensional exploration + critic verification.

Inspired by the "Ultra Review" pattern:
  - 3 Explorer passes run in parallel, each focused on a specific dimension
  - 1 Critic pass validates combined findings, filtering ~60-70% false positives
  - Result: higher precision than single-pass review at similar total token cost

Architecture:
  Explorer(Security) ──┐
  Explorer(Logic)    ──├─→ Merge → Critic → Final findings
  Explorer(Resource) ──┘
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import TYPE_CHECKING

from codeguardian.ai.deep_review.budget import TokenBudgetManager
from codeguardian.ai.deep_review.context_builder import ContextPackBuilder
from codeguardian.ai.deep_review.models import AIFindingRaw, CodeChunk, ContextPack, ReviewResult
from codeguardian.ai.models import TokenUsage
from codeguardian.ai.prompts.deep_review import ANTI_HALLUCINATION_RULES, SYSTEM_MESSAGE, build_review_prompt

if TYPE_CHECKING:
    from codeguardian.ai.base import AIProvider

logger = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)

# ─── Explorer Dimension Definitions ───────────────────────────────────────────

EXPLORER_DIMENSIONS = {
    "security": {
        "name": "安全性探索器",
        "focus": [
            "注入漏洞（SQL/命令/路径/SSRF/XSS）",
            "认证/授权绕过",
            "敏感数据泄露（日志/错误消息/硬编码凭据）",
            "密码学误用（弱哈希、不安全随机数）",
            "反序列化/模板注入",
        ],
        "ignore": "不要报告代码风格、命名规范、或非安全类性能问题。",
    },
    "logic": {
        "name": "逻辑正确性探索器",
        "focus": [
            "空值/None/null 未处理导致运行时异常",
            "边界条件错误（off-by-one、空集合、整数溢出）",
            "状态不一致（竞态条件、TOCTOU）",
            "逻辑分支遗漏（未处理的枚举值、默认分支缺失）",
            "类型转换失败（强转异常、精度丢失）",
        ],
        "ignore": "不要报告安全问题（由安全探索器负责），不要报告资源泄露。",
    },
    "resource": {
        "name": "资源与性能探索器",
        "focus": [
            "资源泄漏（文件/连接/锁/内存 未关闭/释放）",
            "异常处理缺陷（空 catch、吞异常、错误上下文丢失）",
            "阻塞主线程/事件循环",
            "循环内高成本操作：SQL 查询（N+1）、HTTP 请求、文件 IO、正则编译、大对象构造",
            "低效算法：O(n²) 双层循环扫描可用哈希替代、循环内字符串拼接",
            "并发与锁：锁内执行 IO/网络、忙等轮询（无 sleep/backoff）、无限制创建线程/协程",
            "超时与配置：HTTP/RPC/DB 调用无超时、事务跨网络调用、无分页的全量查询/列表接口",
            "缓存与重复计算：循环内重复读取不变配置、未缓存的重复计算",
            "大数据路径：一次性加载大文件/大结果集到内存、未流式处理",
        ],
        "ignore": "不要报告安全漏洞或纯逻辑错误（由其他探索器负责）。",
    },
}

# ─── Prompt Templates ─────────────────────────────────────────────────────────

EXPLORER_PROMPT_TEMPLATE = """\
你是 CodeGuardian {dimension_name}。专注分析以下代码的 **{dimension_id}** 维度问题。

## 你的职责范围
{focus_list}

## 不在你的范围
{ignore_instruction}

## 自反思要求（降低误报）
对每个你认为的问题，必须自问：
- 这在该语言/框架中是否是惯用写法？
- 调用方或上层是否可能已经处理了这个条件？
- 是否有明确的代码证据证明这确实是问题？
如果证据不充分，不要上报。宁可漏报，不要误报。

{anti_hallucination}

## 待审查代码
文件：{file_path}
函数：{function_name}（第 {line_start}-{line_end} 行）

```{language}
{source_code}
```

## 上下文：被调用函数签名
{dependency_signatures}

## 上下文：本地引擎已发现的问题
{local_findings_summary}

{notes_section}

## 输出格式（严格 JSON，不要 Markdown 包装）
{{
  "findings": [
    {{
      "title": "简短标题",
      "category": "{category_enum}",
      "severity": "critical|high|medium|low",
      "confidence": 1-10,
      "line_start": 行号,
      "line_end": 行号,
      "description": "问题描述",
      "evidence": "具体的代码行和推理过程",
      "fix_suggestion": "修复方向",
      "self_reflection": "为什么确信这不是误报"
    }}
  ]
}}

如果此维度没有问题，返回 {{"findings": []}}
"""

CRITIC_PROMPT_TEMPLATE = """\
你是 CodeGuardian 审查验证官（Critic）。你的任务是对以下由多个探索器提出的候选问题进行 **独立验证**。

## 你的职责
1. 对每个候选问题，独立判断是否为真正的 bug/漏洞
2. 过滤掉误报：框架保护、上下文已处理、惯用写法、理论风险但实际不可达
3. 保留确认的真实问题，可以调整 severity/confidence
4. **不要补充探索器没有提到的新问题**——你的角色是验证官，不是探索器；新增 finding 容易引入新幻觉

## 过滤标准（必须按顺序执行）
将候选标记为 "reject" 如果命中以下任一条：

**【优先级最高 — 幻觉过滤】**
- **该候选属于"语法错误/编译错误/拼写错误/关键字错写"类**（如声称 `retur` 应为 `return`、缺分号、括号不匹配）→ 一律 reject，理由 `"hallucinated_syntax_error"`。语法错误由编译器/IDE 负责，根本不应进入代码审查报告。
- **候选 evidence/description/fix_suggestion 中引用的代码字符串（用引号、反引号、或"关键字 X"句式包裹的标识符）在 source_code 对应行号 ±5 行内逐字找不到** → reject，理由 `"hallucinated_evidence"`。这说明探索器看错了源码或编造了引用。
- **候选 category 不在白名单 [security, null_safety, logic, resource, error_handling, performance] 中** → reject，理由 `"invalid_category"`。

**【高 FP 模式硬过滤 — 必须 reject】**
- **"未初始化的单例/工厂"且类中存在 init() + getInstance() 抛异常的 fail-fast 设计** → reject，理由 `"intentional_fail_fast_design"`。getInstance 抛异常是故意契约，不是 bug。
- **"资源未关闭"指控的对象类型为 OkHttpClient / HttpClient / RestTemplate / WebClient / 各类 ThreadPool / DataSource / RedisTemplate / KafkaProducer/Consumer / requests.Session / aiohttp.ClientSession 等长生命周期客户端**，且声明在类成员或 static 块 → reject，理由 `"long_lived_resource"`。这些对象按设计就是进程级单例。
- **"无限循环 / 死循环 / busy-loop"指控**，但循环体内存在 `Thread.sleep` / `time.sleep` / `asyncio.sleep` / `select` / `poll` / `wait` 调用 → reject，理由 `"intentional_event_loop"`。这是 worker/事件循环的标准实现。
- **"未检查 null/None"类指控**，但 source_code 中**该具体变量**前 12 行内存在显式 guard（`if X != null` / `if X == null throw` / `Objects.requireNonNull(X)` / `if X is None: raise` / `if X is not None:` 等） → reject，理由 `"explicit_null_guard"`。注意：必须是针对**该特定变量名**的 guard，不能是别的变量的检查。

**【severity 强制上限】**
- AI 单源 finding（无本地规则佐证）**严禁**给出 `critical`。如果探索器报了 critical 但你确认问题真实存在，必须降级为 `high`。理由：critical 须有"明确可利用、已被验证"的证据，单 AI 推测达不到此门槛。
- "未检查 null/None"类问题，**最高 severity = medium**。仅在 evidence 明确证明"该变量后续会被解引用且无 catch"时才允许 high。

**【常规过滤】**
- 该问题在当前框架/语言中已有内置保护
- 上下文代码已经处理了该条件
- 只是理论可能但实际执行路径不可达
- 属于代码风格/最佳实践而非真正的 bug

## 验证流程要求
对每个候选：
1. 先在 source_code 中**逐字符核对** evidence 引用的标识符是否真实存在；找不到的必须 reject。
2. 再按上述【高 FP 模式硬过滤】五条逐项匹配；命中即 reject，不要"善意保留"。
3. 通过前两轮的，按【severity 强制上限】调整定级。
4. 剩余的才是 verified_findings。

宁可漏报，不要误报。这一轮最差结果是漏掉真问题（人类下次扫描会再看），但保留一堆 FP 会让用户彻底丧失对工具的信任。

## 待验证代码
文件：{file_path}
函数：{function_name}（第 {line_start}-{line_end} 行）

```{language}
{source_code}
```

## 候选问题列表（来自多维度探索器）
{candidate_findings_json}

## 输出格式（严格 JSON）
{{
  "verified_findings": [
    {{
      "title": "原标题或修正后标题",
      "category": "security|null_safety|logic|resource|error_handling|performance",
      "severity": "critical|high|medium|low",
      "confidence": 1-10,
      "line_start": 行号,
      "line_end": 行号,
      "description": "验证后的问题描述",
      "evidence": "关键代码证据（必须是 source_code 中的原文片段）",
      "fix_suggestion": "修复建议",
      "self_reflection": "为什么确认这是真问题",
      "verdict": "confirm"
    }}
  ],
  "rejected": [
    {{
      "title": "被拒绝的问题标题",
      "reason": "拒绝原因（如：hallucinated_syntax_error / hallucinated_evidence / invalid_category / 框架已处理 / 不可达路径 / 惯用写法）"
    }}
  ],
  "summary": "验证摘要"
}}
"""


class UltraReviewer:
    """Multi-dimensional explorer + critic AI reviewer.

    Compared to standard single-pass:
      - Higher precision (critic filters 50-70% false positives)
      - Better recall per dimension (focused prompts)
      - Similar total token cost (explorers use lighter prompts)
    """

    def __init__(
        self,
        provider: AIProvider,
        context_builder: ContextPackBuilder,
        budget: TokenBudgetManager,
        max_concurrent: int = 3,
        critic_provider: AIProvider | None = None,
    ) -> None:
        self._provider = provider
        self._critic_provider = critic_provider or provider
        self._ctx_builder = context_builder
        self._budget = budget
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._total_usage = TokenUsage()

    @property
    def total_usage(self) -> TokenUsage:
        return self._total_usage

    async def review_chunks(self, chunks: list[CodeChunk]) -> list[ReviewResult]:
        """Review chunks using ultra mode: parallel explorers + critic."""
        total = len(chunks)
        logger.info(
            "Ultra Review starting: %d chunks × %d explorers + critic (concurrency=%d)",
            total, len(EXPLORER_DIMENSIONS), self._max_concurrent,
        )
        tasks = [self._review_chunk_ultra(chunk) for chunk in chunks]
        return await asyncio.gather(*tasks)

    async def _review_chunk_ultra(self, chunk: CodeChunk) -> ReviewResult:
        """Full ultra review for one chunk: explore → merge → critique."""
        async with self._semaphore:
            if self._budget.exhausted:
                return ReviewResult.skipped(chunk.file_path, "budget_exhausted")

            context_pack = self._ctx_builder.build(chunk)
            tokens_before = self._total_usage.total_tokens

            # Phase 1: Parallel dimensional exploration
            explorer_findings = await self._run_explorers(context_pack)

            if not explorer_findings:
                tokens_used = self._total_usage.total_tokens - tokens_before
                return ReviewResult(
                    chunk_file_path=chunk.file_path,
                    chunk_qualified_name=chunk.qualified_name,
                    findings=[],
                    summary="Ultra Review: 各维度探索器均未发现问题",
                    status="done",
                    tokens_used=tokens_used,
                )

            # Phase 2: Critic verification
            verified = await self._run_critic(context_pack, explorer_findings)
            tokens_used = self._total_usage.total_tokens - tokens_before

            return ReviewResult(
                chunk_file_path=chunk.file_path,
                chunk_qualified_name=chunk.qualified_name,
                findings=verified,
                summary=f"Ultra Review: {len(explorer_findings)} 候选 → {len(verified)} 确认",
                status="done",
                tokens_used=tokens_used,
            )

    async def _run_explorers(self, context: ContextPack) -> list[AIFindingRaw]:
        """Run all dimensional explorers in parallel, return merged candidates."""
        tasks = [
            self._run_single_explorer(dim_id, dim_def, context)
            for dim_id, dim_def in EXPLORER_DIMENSIONS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[AIFindingRaw] = []
        for result in results:
            if isinstance(result, Exception):
                logger.warning("Explorer failed: %s", result)
                continue
            all_findings.extend(result)

        return all_findings

    async def _run_single_explorer(
        self, dim_id: str, dim_def: dict, context: ContextPack,
    ) -> list[AIFindingRaw]:
        """Execute one dimensional explorer."""
        focus_list = "\n".join(f"- {item}" for item in dim_def["focus"])
        # resource 维度合并了资源与性能，允许输出两个类别之一
        category_enum = "resource|performance" if dim_id == "resource" else dim_id
        prompt = EXPLORER_PROMPT_TEMPLATE.format(
            dimension_name=dim_def["name"],
            dimension_id=dim_id,
            category_enum=category_enum,
            focus_list=focus_list,
            ignore_instruction=dim_def["ignore"],
            file_path=context.file_path,
            function_name=context.function_name or "(文件级)",
            line_start=context.line_start,
            line_end=context.line_end,
            language=context.language or "",
            source_code=context.target_code,
            dependency_signatures=context.build_dependency_section(),
            local_findings_summary=context.local_findings_summary or "无",
            notes_section=context.build_notes_section(),
            anti_hallucination=ANTI_HALLUCINATION_RULES,
        )

        max_retries = 2  # initial call + 1 retry for transient failures
        for attempt in range(max_retries):
            try:
                gen_result = await self._provider.generate_with_usage(
                    prompt,
                    system_message=f"你是 CodeGuardian {dim_def['name']}，专注{dim_id}维度的代码审查。严格返回 JSON。",
                )

                tokens = gen_result.usage.total_tokens
                if tokens == 0:
                    tokens = (len(prompt) + len(gen_result.text)) // 4
                self._budget.consume(tokens)
                self._total_usage.prompt_tokens += gen_result.usage.prompt_tokens
                self._total_usage.completion_tokens += gen_result.usage.completion_tokens
                self._total_usage.total_tokens += gen_result.usage.total_tokens

                return self._parse_explorer_response(gen_result.text, dim_id)

            except Exception as exc:
                exc_str = str(exc).lower()
                is_rate_limit = "429" in exc_str or "rate" in exc_str
                is_timeout = "timeout" in exc_str

                # Extract server-provided Retry-After when available.
                wait_s = 5
                if exc.__cause__ is not None and hasattr(exc.__cause__, "wait_seconds"):
                    wait_s = exc.__cause__.wait_seconds
                elif is_timeout:
                    wait_s = 10

                if (is_rate_limit or is_timeout) and attempt < max_retries - 1:
                    logger.info(
                        "Explorer [%s] transient error, retrying after %ds (attempt %d/%d)",
                        dim_id, wait_s, attempt + 1, max_retries,
                    )
                    await asyncio.sleep(wait_s)
                    continue

                logger.warning("Explorer [%s] error: %s", dim_id, exc)
                return []

    async def _run_critic(
        self, context: ContextPack, candidates: list[AIFindingRaw],
    ) -> list[AIFindingRaw]:
        """Run critic to verify/filter explorer findings."""
        candidates_json = json.dumps(
            [
                {
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "description": f.description,
                    "evidence": f.evidence,
                    "self_reflection": f.self_reflection,
                }
                for f in candidates
            ],
            ensure_ascii=False,
            indent=2,
        )

        prompt = CRITIC_PROMPT_TEMPLATE.format(
            file_path=context.file_path,
            function_name=context.function_name or "(文件级)",
            line_start=context.line_start,
            line_end=context.line_end,
            language=context.language or "",
            source_code=context.target_code,
            candidate_findings_json=candidates_json,
        )

        try:
            gen_result = await self._critic_provider.generate_with_usage(
                prompt,
                system_message=(
                    "你是 CodeGuardian 审查验证官。你的职责是验证候选问题，"
                    "过滤误报，保留真实 bug。严格返回 JSON。"
                ),
            )

            tokens = gen_result.usage.total_tokens
            if tokens == 0:
                tokens = (len(prompt) + len(gen_result.text)) // 4
            self._budget.consume(tokens)
            self._total_usage.prompt_tokens += gen_result.usage.prompt_tokens
            self._total_usage.completion_tokens += gen_result.usage.completion_tokens
            self._total_usage.total_tokens += gen_result.usage.total_tokens

            return self._parse_critic_response(gen_result.text, candidates)

        except Exception as exc:
            logger.warning("Critic error: %s — falling back to all candidates", exc)
            # On critic failure, return all candidates (degrade gracefully)
            return candidates

    def _parse_explorer_response(self, raw: str, dim_id: str) -> list[AIFindingRaw]:
        """Parse explorer JSON output."""
        json_str = _extract_json(raw)
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Explorer [%s] returned invalid JSON", dim_id)
            return []

        findings: list[AIFindingRaw] = []
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            findings.append(AIFindingRaw(
                title=item.get("title", ""),
                category=_normalize_category(item.get("category", dim_id)),
                severity=item.get("severity", "medium"),
                confidence=int(item.get("confidence", 5)),
                line_start=int(item.get("line_start", 0)),
                line_end=int(item.get("line_end", 0)),
                description=item.get("description", ""),
                evidence=item.get("evidence", ""),
                fix_suggestion=item.get("fix_suggestion", ""),
                self_reflection=item.get("self_reflection", ""),
            ))
        return findings

    def _parse_critic_response(
        self, raw: str, original_candidates: list[AIFindingRaw],
    ) -> list[AIFindingRaw]:
        """Parse critic JSON output — returns only verified findings."""
        json_str = _extract_json(raw)
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Critic returned invalid JSON — keeping all candidates")
            return original_candidates

        verified: list[AIFindingRaw] = []
        for item in data.get("verified_findings", []):
            if not isinstance(item, dict):
                continue
            if item.get("verdict", "confirm") == "reject":
                continue
            verified.append(AIFindingRaw(
                title=item.get("title", ""),
                category=_normalize_category(item.get("category", "defect")),
                severity=item.get("severity", "medium"),
                confidence=int(item.get("confidence", 7)),
                line_start=int(item.get("line_start", 0)),
                line_end=int(item.get("line_end", 0)),
                description=item.get("description", ""),
                evidence=item.get("evidence", ""),
                fix_suggestion=item.get("fix_suggestion", ""),
                self_reflection=item.get("self_reflection", ""),
            ))

        rejected_count = len(data.get("rejected", []))
        if rejected_count > 0:
            logger.info(
                "Critic verified %d / %d (rejected %d, %.0f%% FP rate)",
                len(verified),
                len(original_candidates),
                rejected_count,
                rejected_count / max(1, len(original_candidates)) * 100,
            )

        return verified


# ─── Utility ──────────────────────────────────────────────────────────────────

def _extract_json(raw: str) -> str:
    """Extract JSON from AI response."""
    match = _JSON_BLOCK_RE.search(raw)
    if match:
        return match.group(1).strip()
    stripped = raw.strip()
    if stripped.startswith("{"):
        return stripped
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        return stripped[start : end + 1]
    return stripped


_CATEGORY_NORMALIZE: dict[str, str] = {
    "security": "security",
    "logic": "logic",
    "null_safety": "null_safety",
    "resource": "resource",
    "error_handling": "error_handling",
    "performance": "performance",
    # Explorer dimension IDs map to standard categories
    "安全": "security",
    "逻辑": "logic",
    "资源": "resource",
    "性能": "performance",
}

# Final whitelist of categories accepted downstream by the merger.
# Anything not in this set will be tagged "unknown" so the merger drops it.
_VALID_CATEGORIES: frozenset[str] = frozenset({
    "security", "logic", "null_safety", "resource", "error_handling", "performance",
})


def _normalize_category(raw: str) -> str:
    """Normalize category string from AI output.

    Maps Chinese aliases to canonical category names. If the result is not
    in the downstream whitelist, returns 'unknown' instead of letting an
    arbitrary string through (defense against hallucinated categories like
    'syntax', 'compile_error', 'style'). The merger drops 'unknown'.
    """
    normalized = _CATEGORY_NORMALIZE.get(raw.lower(), raw.lower())
    if normalized not in _VALID_CATEGORIES:
        logger.warning(
            "AI returned invalid category=%r (normalized=%r); marking as 'unknown'",
            raw, normalized,
        )
        return "unknown"
    return normalized
