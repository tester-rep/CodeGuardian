"""PerformanceEngine — detects static performance, concurrency, and API misuse patterns.

Dimension 9: Performance Analyzer
Supports Python (via stdlib ast) and Java, Go, JavaScript, TypeScript, C++ (via tree-sitter).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from codeguardian.core.context import ScanContext
from codeguardian.engines.rule_helpers import RuleHit, RuleSpec, build_finding
from codeguardian.engines.rule_registry import filter_rule_hits, register_rules
from codeguardian.languages import (
    EXTENSION_LANGUAGE_MAP,
    is_language_enabled,
    sort_paths_by_language_priority,
)
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.scan import EngineResult
from codeguardian.parsers.tree_sitter_support import TreeSitterDocument, get_tree_sitter_document
from codeguardian.utils.ignore import should_ignore

if TYPE_CHECKING:
    from tree_sitter import Node
else:
    Node = Any

# ── Supported languages ─────────────────────────────────────────────────
SUPPORTED_PERFORMANCE_LANGUAGES = {
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "cpp",
}
LANGUAGE_BY_SUFFIX = {
    suffix: language
    for suffix, language in EXTENSION_LANGUAGE_MAP.items()
    if language in SUPPORTED_PERFORMANCE_LANGUAGES
}
SUPPORTED_EXTENSIONS = set(LANGUAGE_BY_SUFFIX)

# ── Rule definitions ────────────────────────────────────────────────────
HTTP_NO_TIMEOUT = RuleSpec(
    rule_id="HTTP-NO-TIMEOUT",
    title="HTTP 客户端调用未设置超时 (HTTP call without timeout)",
    category="performance",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="为所有出站 HTTP 调用设置显式超时，避免工作线程挂死或请求风暴。",
    risk_priority="should-fix",
    tags=("performance", "api-misuse", "network", "timeout"),
    applicable_languages=("python", "java", "go", "javascript", "typescript"),
    description_zh="检测到 HTTP 客户端调用未设置超时。缺少超时会导致线程/协程永久阻塞，在高并发场景下引发级联故障。",
)
BUSY_WAIT = RuleSpec(
    rule_id="BUSY-WAIT",
    title="检测到忙等待循环 (Busy-wait loop)",
    category="performance",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="用阻塞原语、sleep/yield 或事件/条件变量替代自旋等待。",
    risk_priority="must-fix",
    tags=("performance", "concurrency", "busy-wait"),
    applicable_languages=("python", "java", "go", "cpp"),
    description_zh="检测到忙等待循环（空 while/for 循环无 sleep 或阻塞调用）。忙等待会浪费 CPU 资源并可能导致其他线程饥饿。",
)
RETRY_WITHOUT_BACKOFF = RuleSpec(
    rule_id="RETRY-WITHOUT-BACKOFF",
    title="检测到无退避的重试循环 (Retry without backoff)",
    category="performance",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="增加有上限的重试次数，并加入 sleep 或指数退避，避免放大下游故障。",
    risk_priority="should-fix",
    tags=("performance", "api-misuse", "retry", "resilience"),
    applicable_languages=("python", "java", "go", "javascript", "typescript"),
    description_zh="检测到无退避策略的重试循环（循环中 catch/except 异常后立即重试但无 sleep）。这会放大下游服务压力，形成重试风暴。",
)
BLOCKING_CALL_IN_ASYNC = RuleSpec(
    rule_id="BLOCKING-CALL-IN-ASYNC",
    title="async 函数中使用了阻塞调用 (Blocking call in async)",
    category="performance",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="在 async 函数中使用非阻塞异步 API，例如 asyncio.sleep 或异步 HTTP 客户端。",
    risk_priority="must-fix",
    tags=("performance", "api-misuse", "async", "blocking-io"),
    applicable_languages=("python", "javascript", "typescript"),
    description_zh="在 async 函数中调用了阻塞 API。阻塞调用会占据事件循环线程，导致所有并发任务被阻塞。",
)
UNBOUNDED_GOROUTINE = RuleSpec(
    rule_id="UNBOUNDED-GOROUTINE",
    title="循环中无限制启动 goroutine (Unbounded goroutine)",
    category="performance",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="使用 worker pool、信号量或有界 channel 限制并发 goroutine 数量，并用 sync.WaitGroup 等待完成。",
    risk_priority="must-fix",
    tags=("performance", "concurrency", "goroutine", "go"),
    applicable_languages=("go",),
    description_zh="在循环中无限制地启动 goroutine 而没有使用 WaitGroup 或信号量限流。这会导致内存暴涨和 goroutine 泄漏。",
)
MUTEX_LOCK_NO_UNLOCK = RuleSpec(
    rule_id="MUTEX-LOCK-NO-UNLOCK",
    title="互斥锁加锁后缺少解锁 (Mutex lock without unlock)",
    category="performance",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="确保 Lock() 与 defer Unlock() 成对出现（Go），或在 C++ 中使用 RAII lock guard 自动释放锁。",
    risk_priority="must-fix",
    tags=("performance", "concurrency", "mutex", "deadlock"),
    applicable_languages=("go", "cpp"),
    description_zh="检测到获取互斥锁后缺少对应的解锁操作。未释放的锁会导致死锁，使整个程序挂起。",
)

# ── New rules: Database query, ReDoS, transaction scope ────────────────
SELECT_STAR_NO_LIMIT = RuleSpec(
    rule_id="SELECT-STAR-NO-LIMIT",
    title="SELECT * 无 WHERE/LIMIT 限制 (Unbounded SELECT * query)",
    category="performance",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="指定具体字段代替 SELECT *，并添加 WHERE 条件或 LIMIT 限制返回行数。",
    risk_priority="should-fix",
    tags=("performance", "database", "query", "full-table-scan"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp"),
    description_zh="SELECT * 且无 WHERE/LIMIT 条件可能导致全表扫描，大表时引发内存溢出或锁表。",
)

SQL_IN_LOOP = RuleSpec(
    rule_id="SQL-IN-LOOP",
    title="循环内执行 SQL 查询 (SQL query inside loop — potential N+1)",
    category="performance",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="将循环内逐条查询改为批量查询（IN 子句或 JOIN），减少网络往返次数。",
    risk_priority="must-fix",
    tags=("performance", "database", "n-plus-one", "loop"),
    applicable_languages=("python", "java", "javascript", "typescript", "go"),
    description_zh="在循环内逐条执行 SQL 查询（N+1 模式），每次迭代都产生一次数据库网络往返，严重拖慢接口性能。",
)

REDOS_RISK = RuleSpec(
    rule_id="REDOS-RISK",
    title="正则表达式存在 ReDoS 风险 (Regex with catastrophic backtracking)",
    category="performance",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="重写正则避免嵌套量词（如 (a+)+ 改为 a+），或使用 possessive quantifier / atomic group。",
    risk_priority="must-fix",
    tags=("performance", "security", "redos", "regex"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp"),
    cwe_ids=("CWE-1333",),
    description_zh="检测到可能引发指数级回溯的正则表达式（ReDoS）。恶意输入可使单次匹配耗时数秒至数分钟，导致 CPU 100%。",
)

TRANSACTION_SCOPE_TOO_LARGE = RuleSpec(
    rule_id="TRANSACTION-SCOPE-TOO-LARGE",
    title="事务范围过大：包含网络/IO 调用 (Transaction wraps network/IO calls)",
    category="performance",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="将网络调用/文件 IO 移出事务范围，仅在数据库操作周围使用事务。",
    risk_priority="should-fix",
    tags=("performance", "database", "transaction", "long-lock"),
    applicable_languages=("python", "java"),
    description_zh="@Transactional 或 with transaction 块内包含 HTTP 调用/文件操作，导致数据库连接长时间持锁。",
)

MISSING_PAGINATION = RuleSpec(
    rule_id="MISSING-PAGINATION",
    title="列表接口无分页限制 (List endpoint without pagination)",
    category="performance",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="为列表查询添加 LIMIT/OFFSET 或 page/size 参数，避免一次返回全量数据。",
    risk_priority="should-fix",
    tags=("performance", "database", "pagination", "api"),
    applicable_languages=("python", "java", "javascript", "typescript", "go"),
    description_zh="SQL 查询或 API 接口返回列表数据时缺少分页（无 LIMIT/page_size），可能返回数万行导致前端卡死或 OOM。",
)

IO_IN_LOCK = RuleSpec(
    rule_id="IO-IN-LOCK",
    title="锁内执行 I/O：阻塞所有等待者 (blocking I/O performed while holding a lock)",
    category="performance",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="把 I/O 调用移出锁的临界区；只在锁内做内存操作，I/O 前后释放锁。",
    risk_priority="must-fix",
    tags=("performance", "concurrency", "lock-contention"),
    applicable_languages=("python",),
    description_zh="在 with lock: 块内执行 HTTP 请求 / 文件 I/O / time.sleep / subprocess 等阻塞调用，会让所有等锁的线程一起被这些 I/O 拖慢，等价于把 I/O 时延乘以并发数。",
)

PERFORMANCE_RULES = register_rules(
    "performance",
    (
        HTTP_NO_TIMEOUT,
        BUSY_WAIT,
        RETRY_WITHOUT_BACKOFF,
        BLOCKING_CALL_IN_ASYNC,
        UNBOUNDED_GOROUTINE,
        MUTEX_LOCK_NO_UNLOCK,
        SELECT_STAR_NO_LIMIT,
        SQL_IN_LOOP,
        REDOS_RISK,
        TRANSACTION_SCOPE_TOO_LARGE,
        MISSING_PAGINATION,
        IO_IN_LOCK,
    ),
)

# ── Python-specific call sets ───────────────────────────────────────────
_HTTP_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.request",
    "requests.head",
    "requests.options",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.request",
    "httpx.head",
    "httpx.options",
    "urllib.request.urlopen",
}
_BLOCKING_ASYNC_CALLS = _HTTP_CALLS | {"time.sleep", "subprocess.run", "subprocess.call", "subprocess.check_output"}
_SLEEP_CALLS = {"time.sleep", "asyncio.sleep", "sleep"}
_LOGGING_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "print"}

# ── Java HTTP call patterns ─────────────────────────────────────────────
_JAVA_HTTP_NO_TIMEOUT_TYPES = frozenset({
    "HttpURLConnection", "HttpsURLConnection", "URL",
})
_JAVA_HTTP_CLIENT_METHODS = frozenset({
    "newHttpClient", "newBuilder",
})

# ── Go HTTP call patterns ───────────────────────────────────────────────
_GO_HTTP_NO_TIMEOUT_CALLS = frozenset({
    "http.Get", "http.Post", "http.PostForm", "http.Head",
})

# ── JS/TS blocking-in-async patterns ────────────────────────────────────
_JS_BLOCKING_SYNC_CALLS = frozenset({
    "readFileSync", "writeFileSync", "appendFileSync", "mkdirSync",
    "readdirSync", "statSync", "existsSync", "unlinkSync",
    "renameSync", "copyFileSync", "accessSync",
    "execSync", "execFileSync", "spawnSync",
})


class PerformanceEngine:
    """Detect deterministic static performance and API-misuse patterns."""

    name = "performance"

    # ── Main entry point ────────────────────────────────────────────────

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        root = Path(ctx.project_root)
        findings = []
        counter = 0
        candidate_files = [
            src_file
            for src_file in ctx.collect_candidate_files(root, suffixes=SUPPORTED_EXTENSIONS)
            if not should_ignore(src_file) and src_file.is_file() and src_file.suffix.lower() in SUPPORTED_EXTENSIONS
        ]

        for src_file in sort_paths_by_language_priority(candidate_files):
            suffix = src_file.suffix.lower()
            language = LANGUAGE_BY_SUFFIX.get(suffix)
            if language is None or not is_language_enabled(language, ctx.languages):
                continue

            try:
                content = src_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = str(src_file.relative_to(root)).replace("\\", "/")
            lines = content.splitlines()
            hits = self._scan_file(src_file, root, rel_path, content, language)
            hits = filter_rule_hits(hits, ctx.config.rules)

            seen: set[tuple[str, str, int, int]] = set()
            for hit in hits:
                key = (hit.rule.rule_id, hit.file_path, hit.line_start, hit.line_end)
                if key in seen:
                    continue
                seen.add(key)
                counter += 1
                findings.append(build_finding(hit, lines, f"PERF-{counter:03d}", self.name, context_radius=1))

        return EngineResult(engine_name=self.name, findings=findings)

    # ── Language routing ────────────────────────────────────────────────

    def _scan_file(
        self,
        src_file: Path,
        root: Path,
        rel_path: str,
        content: str,
        language: str,
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []

        # Cross-language pattern detection (new rules)
        hits.extend(self._detect_select_star(content, rel_path, language))
        hits.extend(self._detect_sql_in_loop(content, rel_path, language))
        hits.extend(self._detect_redos(content, rel_path, language))
        hits.extend(self._detect_transaction_scope(content, rel_path, language))
        hits.extend(self._detect_missing_pagination(content, rel_path, language))

        # Language-specific deep detection
        if language == "python":
            hits.extend(self._scan_python_ast(content, rel_path))
            return hits

        if language not in {"java", "javascript", "typescript", "go", "cpp", "csharp"}:
            return hits

        document = get_tree_sitter_document(src_file, root, language)
        if document is None:
            return hits

        if language == "java":
            hits.extend(self._scan_java_tree(document, language))
        elif language in {"javascript", "typescript"}:
            hits.extend(self._scan_javascript_tree(document, language))
        elif language == "go":
            hits.extend(self._scan_go_tree(document, language))
        elif language == "cpp":
            hits.extend(self._scan_cpp_tree(document, language))
        elif language == "csharp":
            hits.extend(self._scan_csharp_tree(document, language))
        return hits

    # ── Cross-language pattern detectors (new) ─────────────────────────

    _SELECT_STAR_RE = re.compile(
        r"""(?ix)
        (?:execute|query|raw|sql|cursor\.execute|db\.query|prepare)\s*\(\s*
        (?:f?['"`])?\s*SELECT\s+\*\s+FROM\s+\w+
        (?!\s+WHERE)(?!\s+LIMIT)(?!\s+JOIN)
        """,
    )

    _SQL_CALL_KEYWORDS = re.compile(
        r"""(?i)(?:execute|query|cursor\.execute|db\.query|prepare|rawQuery|execSQL|\.sql\()""",
    )

    _LOOP_START_RE = re.compile(r"""(?:^\s*(?:for|while|forEach|\.each|\.map)\b)""", re.MULTILINE)

    _REDOS_PATTERNS = [
        # Nested quantifiers: (a+)+, (a*)+, (a+)*, (.+)+
        re.compile(r"""\([^)]*[+*][^)]*\)[+*]"""),
        # Overlapping alternation with quantifier: (a|a)+
        re.compile(r"""\([^)]*\|[^)]*\)[+*]"""),
        # Common dangerous patterns
        re.compile(r"""(\.\*){2,}"""),
        re.compile(r"""\([^)]+\+\)\+"""),
    ]

    _TRANSACTION_DECORATORS = re.compile(
        r"""(?i)@Transactional|@transaction\.atomic|with\s+(?:transaction|atomic|conn\.begin)""",
    )
    _NETWORK_IO_IN_CODE = re.compile(
        r"""(?i)(?:requests?\.|httpx\.|urlopen|fetch\(|HttpClient|RestTemplate|WebClient|\.get\(|\.post\()""",
    )

    def _detect_select_star(self, content: str, rel_path: str, language: str) -> list[RuleHit]:
        """Detect SELECT * FROM table without WHERE/LIMIT."""
        hits: list[RuleHit] = []
        for match in self._SELECT_STAR_RE.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            hits.append(RuleHit(
                rule=SELECT_STAR_NO_LIMIT,
                file_path=rel_path,
                line_start=line_no,
                line_end=line_no,
                language=language,
                message="SELECT * without WHERE/LIMIT — risk of full table scan",
            ))
        return hits

    def _detect_sql_in_loop(self, content: str, rel_path: str, language: str) -> list[RuleHit]:
        """Detect SQL execution calls inside loops (N+1 pattern)."""
        hits: list[RuleHit] = []
        lines = content.splitlines()
        in_loop = False
        loop_indent = 0
        loop_start_line = 0

        for line_no, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if self._LOOP_START_RE.match(stripped):
                in_loop = True
                loop_indent = indent
                loop_start_line = line_no
                continue

            if in_loop:
                # Exited loop (dedent or end)
                if stripped and indent <= loop_indent and not stripped.startswith(("}", ")")):
                    in_loop = False
                    continue
                # Check for SQL call inside loop
                if self._SQL_CALL_KEYWORDS.search(stripped):
                    hits.append(RuleHit(
                        rule=SQL_IN_LOOP,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        language=language,
                        message=f"SQL query inside loop (started at line {loop_start_line}) — N+1 risk",
                    ))
        return hits

    def _detect_redos(self, content: str, rel_path: str, language: str) -> list[RuleHit]:
        """Detect regex patterns vulnerable to catastrophic backtracking (ReDoS)."""
        hits: list[RuleHit] = []
        # Find regex literals/compile calls
        regex_defs = re.finditer(
            r"""(?:re\.compile|Pattern\.compile|new\s+RegExp|regex!)\s*\(\s*[r]?['"`/]([^'"`/]+)['"`/]""",
            content,
        )
        for match in regex_defs:
            pattern_str = match.group(1)
            for redos_re in self._REDOS_PATTERNS:
                if redos_re.search(pattern_str):
                    line_no = content[:match.start()].count("\n") + 1
                    hits.append(RuleHit(
                        rule=REDOS_RISK,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        language=language,
                        message=f"Regex with potential catastrophic backtracking: {pattern_str[:60]}",
                    ))
                    break  # One hit per regex
        return hits

    def _detect_transaction_scope(self, content: str, rel_path: str, language: str) -> list[RuleHit]:
        """Detect transactions that wrap network/IO calls."""
        hits: list[RuleHit] = []
        if language not in {"python", "java"}:
            return hits

        lines = content.splitlines()
        in_transaction = False
        tx_start_line = 0
        tx_indent = 0

        for line_no, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if self._TRANSACTION_DECORATORS.search(stripped):
                in_transaction = True
                tx_start_line = line_no
                tx_indent = indent
                continue

            if in_transaction:
                if stripped and indent <= tx_indent and line_no > tx_start_line + 1:
                    in_transaction = False
                    continue
                if self._NETWORK_IO_IN_CODE.search(stripped):
                    hits.append(RuleHit(
                        rule=TRANSACTION_SCOPE_TOO_LARGE,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        language=language,
                        message=f"Network/IO call inside transaction (started at line {tx_start_line})",
                    ))
                    in_transaction = False  # One hit per transaction block
        return hits

    def _detect_missing_pagination(self, content: str, rel_path: str, language: str) -> list[RuleHit]:
        """Detect queries returning lists without LIMIT/pagination."""
        hits: list[RuleHit] = []
        # Look for .findAll() / .find_all() / .all() / .fetchall() without limit
        pagination_missing_re = re.compile(
            r"""(?i)(?:\.findAll|\.find_all|\.getAll|\.get_all|\.fetchall|\.list\(\))\s*\(?\s*\)?"""
        )
        limit_indicators = re.compile(r"""(?i)(?:limit|page|pageable|offset|per_page|page_size|Pageable|PageRequest)""")

        for match in pagination_missing_re.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            # Check surrounding lines for pagination context
            start = max(0, match.start() - 200)
            end = min(len(content), match.end() + 200)
            context = content[start:end]
            if not limit_indicators.search(context):
                hits.append(RuleHit(
                    rule=MISSING_PAGINATION,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    language=language,
                    message="List query without pagination (no LIMIT/page_size in context)",
                ))
        return hits

    # ════════════════════════════════════════════════════════════════════
    # Python analysis (unchanged from original)
    # ════════════════════════════════════════════════════════════════════

    def _scan_python_ast(self, content: str, rel_path: str) -> list[RuleHit]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                hits.extend(self._scan_http_timeout(node, rel_path))
            elif isinstance(node, ast.AsyncFunctionDef):
                hits.extend(self._scan_async_blocking_calls(node, rel_path))
            elif isinstance(node, ast.While):
                if self._is_busy_wait_loop(node):
                    hits.append(
                        RuleHit(
                            BUSY_WAIT,
                            rel_path,
                            node.lineno,
                            getattr(node, "end_lineno", node.lineno),
                            language="python",
                            message="Loop keeps spinning without sleep/yield or blocking coordination.",
                        )
                    )
                if self._is_retry_without_backoff(node):
                    hits.append(
                        RuleHit(
                            RETRY_WITHOUT_BACKOFF,
                            rel_path,
                            node.lineno,
                            getattr(node, "end_lineno", node.lineno),
                            language="python",
                            message="Retry loop catches failures but has no sleep or backoff between attempts.",
                        )
                    )
            elif isinstance(node, ast.For) and self._is_retry_without_backoff(node):
                hits.append(
                    RuleHit(
                        RETRY_WITHOUT_BACKOFF,
                        rel_path,
                        node.lineno,
                        getattr(node, "end_lineno", node.lineno),
                        language="python",
                        message="Retry loop catches failures but has no sleep or backoff between attempts.",
                    )
                )
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                hits.extend(self._scan_io_in_lock(node, rel_path))

        return hits

    # ── IO-IN-LOCK ─────────────────────────────────────────────────────
    # 在 with lock: 块内执行阻塞 I/O：HTTP / 文件 / time.sleep / subprocess。
    # 触发条件：
    #   1) with 语句的上下文表达式名最后一段含 "lock" 或 "mutex"
    #      （或 with lock.acquire() 这种形式）
    #   2) 块内出现对 _BLOCKING_ASYNC_CALLS（HTTP/sleep/subprocess）的直接调用
    #      或 SQL 类调用（.execute / .query / .commit）
    # 注：不递归进入嵌套的 def/async def/lambda（那些是延迟执行）。
    _IO_IN_LOCK_DB_CALLS = frozenset({
        "execute", "executemany", "query", "fetchall", "fetchone", "fetchmany",
        "commit", "rollback",
    })

    def _scan_io_in_lock(
        self, with_node: ast.With | ast.AsyncWith, rel_path: str
    ) -> list[RuleHit]:
        # 是否至少一个 with item 看起来像锁
        if not self._with_locks_a_lock(with_node):
            return []

        hits: list[RuleHit] = []
        # 自己做 BFS，遇到嵌套 def/lambda 就剪枝（不进入函数体）。
        # ast.walk 不尊重函数边界，所以这里手动控制。
        stack: list[ast.AST] = list(with_node.body)
        while stack:
            child = stack.pop()
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue  # 不递归进嵌套函数：那是延迟执行
            if isinstance(child, ast.Call):
                call_name = self._python_call_name(child.func)
                last_seg = call_name.rsplit(".", 1)[-1]

                is_blocking_io = call_name in _BLOCKING_ASYNC_CALLS
                is_db_io = last_seg in self._IO_IN_LOCK_DB_CALLS
                if is_blocking_io or is_db_io:
                    kind = "HTTP/sleep/subprocess" if is_blocking_io else "database"
                    hits.append(
                        RuleHit(
                            IO_IN_LOCK,
                            rel_path,
                            child.lineno,
                            getattr(child, "end_lineno", child.lineno),
                            language="python",
                            message=(
                                f"`{call_name}` ({kind} I/O) is invoked while a lock is held; "
                                f"all waiters are blocked for the entire I/O duration."
                            ),
                            metadata={"call": call_name},
                        )
                    )
            stack.extend(ast.iter_child_nodes(child))
        return hits

    @staticmethod
    def _with_locks_a_lock(with_node: ast.With | ast.AsyncWith) -> bool:
        for item in with_node.items:
            expr = item.context_expr
            # `with lock.acquire():` —— 取 attribute 的 value
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "acquire":
                expr = expr.func.value
            key = PerformanceEngine._python_call_name(expr) if isinstance(expr, (ast.Name, ast.Attribute)) else ""
            last = key.rsplit(".", 1)[-1].lower()
            if "lock" in last or "mutex" in last:
                return True
        return False

    def _scan_http_timeout(self, node: ast.Call, rel_path: str) -> list[RuleHit]:
        call_name = self._python_call_name(node.func)
        if call_name not in _HTTP_CALLS:
            return []
        if self._has_explicit_timeout(node):
            return []
        return [
            RuleHit(
                HTTP_NO_TIMEOUT,
                rel_path,
                node.lineno,
                getattr(node, "end_lineno", node.lineno),
                language="python",
                message=f"`{call_name}` is called without an explicit timeout.",
                metadata={"call": call_name},
            )
        ]

    def _scan_async_blocking_calls(self, node: ast.AsyncFunctionDef, rel_path: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for child in ast.walk(node):
            if child is not node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if not isinstance(child, ast.Call):
                continue
            call_name = self._python_call_name(child.func)
            if call_name not in _BLOCKING_ASYNC_CALLS:
                continue
            if call_name in _HTTP_CALLS and self._has_explicit_timeout(child):
                detail = f"Async function `{node.name}` performs blocking HTTP via `{call_name}`. Prefer an async client."
            else:
                detail = f"Async function `{node.name}` calls blocking API `{call_name}`."
            hits.append(
                RuleHit(
                    BLOCKING_CALL_IN_ASYNC,
                    rel_path,
                    child.lineno,
                    getattr(child, "end_lineno", child.lineno),
                    language="python",
                    message=detail,
                    metadata={"call": call_name, "function": node.name},
                )
            )
        return hits

    def _is_busy_wait_loop(self, node: ast.While) -> bool:
        if self._loop_contains_sleep(node):
            return False
        return self._body_is_trivial(node.body)

    def _is_retry_without_backoff(self, node: ast.For | ast.While) -> bool:
        if self._loop_contains_sleep(node):
            return False
        for child in ast.walk(node):
            if not isinstance(child, ast.Try):
                continue
            if any(self._handler_swallows(handler) for handler in child.handlers):
                return True
        return False

    def _loop_contains_sleep(self, node: ast.For | ast.While) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self._python_call_name(child.func) in _SLEEP_CALLS:
                return True
            if isinstance(child, ast.Await) and isinstance(child.value, ast.Call) and self._python_call_name(child.value.func) in _SLEEP_CALLS:
                return True

        return False

    def _handler_swallows(self, handler: ast.ExceptHandler) -> bool:
        if not handler.body:
            return True
        return all(self._is_log_or_control_statement(stmt) for stmt in handler.body)

    def _body_is_trivial(self, statements: list[ast.stmt]) -> bool:
        if not statements:
            return False
        for stmt in statements:
            if isinstance(stmt, (ast.Pass, ast.Continue)):
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value in {Ellipsis, None}:
                continue
            if isinstance(stmt, ast.If):
                if not self._body_is_trivial(stmt.body):
                    return False
                if stmt.orelse and not self._body_is_trivial(stmt.orelse):
                    return False
                continue
            return False
        return True

    def _is_log_or_control_statement(self, stmt: ast.stmt) -> bool:
        if isinstance(stmt, (ast.Pass, ast.Continue)):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call_name = self._python_call_name(stmt.value.func)
            if call_name == "print":
                return True
            if isinstance(stmt.value.func, ast.Attribute) and stmt.value.func.attr.lower() in _LOGGING_METHODS:
                return True
        return False

    @staticmethod
    def _has_explicit_timeout(node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg is None:
                return True
            if keyword.arg == "timeout":
                return True
        return False

    @staticmethod
    def _python_call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = PerformanceEngine._python_call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    # ════════════════════════════════════════════════════════════════════
    # Java tree-sitter analysis
    # ════════════════════════════════════════════════════════════════════

    def _scan_java_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        hits.extend(self._scan_java_http_no_timeout(document, language))
        hits.extend(self._scan_java_busy_wait(document, language))
        hits.extend(self._scan_java_retry_without_backoff(document, language))
        return hits

    def _scan_java_http_no_timeout(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Java HTTP calls without timeout configuration.

        Patterns:
        - new URL(...).openConnection() without setConnectTimeout/setReadTimeout
        - HttpClient.newHttpClient() without .connectTimeout()
        - new OkHttpClient() without .connectTimeout()
        """
        hits: list[RuleHit] = []
        source = document.source
        rel = document.relative_path

        # Pattern 1: URL.openConnection without timeout
        for match in re.finditer(r"\bopenConnection\s*\(", source):
            line_no = source[:match.start()].count("\n") + 1
            # Look ahead ~15 lines for setConnectTimeout or setReadTimeout
            region_end = min(len(source), match.end() + 800)
            region = source[match.end():region_end]
            if "setConnectTimeout" not in region and "setReadTimeout" not in region:
                hits.append(RuleHit(
                    HTTP_NO_TIMEOUT, rel, line_no, line_no, language=language,
                    message="`openConnection()` called without `setConnectTimeout`/`setReadTimeout`.",
                ))

        # Pattern 2: HttpClient.newHttpClient() — no connectTimeout in builder
        for match in re.finditer(r"HttpClient\s*\.\s*newHttpClient\s*\(", source):
            line_no = source[:match.start()].count("\n") + 1
            hits.append(RuleHit(
                HTTP_NO_TIMEOUT, rel, line_no, line_no, language=language,
                message="`HttpClient.newHttpClient()` creates client with default (infinite) timeout. Use `HttpClient.newBuilder().connectTimeout(...)` instead.",
            ))

        # Pattern 3: new OkHttpClient() without timeout builder
        for match in re.finditer(r"new\s+OkHttpClient\s*\(\s*\)", source):
            line_no = source[:match.start()].count("\n") + 1
            hits.append(RuleHit(
                HTTP_NO_TIMEOUT, rel, line_no, line_no, language=language,
                message="`new OkHttpClient()` with default config — set `.connectTimeout()` and `.readTimeout()`.",
            ))

        return hits

    def _scan_java_busy_wait(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Java busy-wait patterns: while(true){} or while(cond){} with trivial body."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "while_statement":
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            if self._ts_loop_contains_sleep(body, document):
                continue
            if self._ts_body_is_trivial(body, document):
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    BUSY_WAIT, document.relative_path, line_start, line_end,
                    language=language,
                    message="Busy-wait loop without sleep or blocking call — wastes CPU cycles.",
                ))
        return hits

    def _scan_java_retry_without_backoff(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Java retry loops: for/while with catch that has no Thread.sleep."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"while_statement", "for_statement"}:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            if self._ts_loop_contains_sleep(body, document):
                continue
            if self._ts_has_catch_that_swallows(body, document):
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    RETRY_WITHOUT_BACKOFF, document.relative_path, line_start, line_end,
                    language=language,
                    message="Retry loop catches exceptions but has no Thread.sleep or backoff between attempts.",
                ))
        return hits

    # ════════════════════════════════════════════════════════════════════
    # Go tree-sitter analysis
    # ════════════════════════════════════════════════════════════════════

    def _scan_go_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        hits.extend(self._scan_go_http_no_timeout(document, language))
        hits.extend(self._scan_go_busy_wait(document, language))
        hits.extend(self._scan_go_unbounded_goroutine(document, language))
        hits.extend(self._scan_go_mutex_lock_no_unlock(document, language))
        return hits

    def _scan_go_http_no_timeout(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Go http.Get/Post/etc (default client, no timeout)."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "call_expression":
                continue
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                continue
            fn_text = document.text_for(fn_node).strip()
            if fn_text in _GO_HTTP_NO_TIMEOUT_CALLS:
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    HTTP_NO_TIMEOUT, document.relative_path, line_start, line_end,
                    language=language,
                    message=f"`{fn_text}` uses the default HTTP client which has no timeout. Create a custom `&http.Client{{Timeout: ...}}`.",
                    metadata={"call": fn_text},
                ))
        return hits

    def _scan_go_busy_wait(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Go busy-wait: for {} or for cond {} with empty/trivial body."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "for_statement":
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            if self._ts_loop_contains_sleep(body, document):
                continue
            if self._ts_body_is_trivial(body, document):
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    BUSY_WAIT, document.relative_path, line_start, line_end,
                    language=language,
                    message="Busy-wait loop without time.Sleep or channel receive — wastes CPU cycles.",
                ))
        return hits

    def _scan_go_unbounded_goroutine(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect `go func()` launched inside a for loop without WaitGroup or semaphore."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "for_statement":
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            # Check if loop body contains go statement
            has_go = False
            for child in self._walk_nodes(body):
                if child.type == "go_statement":
                    has_go = True
                    break
            if not has_go:
                continue

            # Check if the enclosing function scope has WaitGroup or semaphore usage
            body_text = document.text_for(body)
            has_bound = any(marker in body_text for marker in (
                "WaitGroup", "wg.Add", "wg.Done", "wg.Wait",
                "semaphore", "Semaphore",
                "<-sem", "sem <-", "sem<-",
                "make(chan", "errgroup",
            ))
            if not has_bound:
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    UNBOUNDED_GOROUTINE, document.relative_path, line_start, line_end,
                    language=language,
                    message="Goroutine launched in loop without WaitGroup, semaphore, or bounded channel — may cause goroutine leak.",
                ))
        return hits

    def _scan_go_mutex_lock_no_unlock(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect mu.Lock() without defer mu.Unlock() in the same function."""
        hits: list[RuleHit] = []
        func_types = {"function_declaration", "method_declaration", "func_literal"}
        for node in self._walk_nodes(document.root_node):
            if node.type not in func_types:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            body_text = document.text_for(body)
            # Find all .Lock() calls
            lock_pattern = re.compile(r"(\w+)\.(?:Lock|RLock)\s*\(\s*\)")
            unlock_pattern_template = r"{name}\.(?:Unlock|RUnlock)\s*\(\s*\)"
            for lock_match in lock_pattern.finditer(body_text):
                var_name = lock_match.group(1)
                unlock_re = re.compile(unlock_pattern_template.format(name=re.escape(var_name)))
                if not unlock_re.search(body_text):
                    abs_offset = body.start_byte + lock_match.start()
                    line_no = document.source[:abs_offset].count("\n") + 1
                    hits.append(RuleHit(
                        MUTEX_LOCK_NO_UNLOCK, document.relative_path, line_no, line_no,
                        language=language,
                        message=f"`{var_name}.Lock()` called without corresponding `{var_name}.Unlock()` — use `defer {var_name}.Unlock()`.",
                    ))
        return hits

    # ════════════════════════════════════════════════════════════════════
    # JavaScript / TypeScript tree-sitter analysis
    # ════════════════════════════════════════════════════════════════════

    def _scan_javascript_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        hits.extend(self._scan_js_http_no_timeout(document, language))
        hits.extend(self._scan_js_blocking_in_async(document, language))
        hits.extend(self._scan_js_retry_without_backoff(document, language))
        return hits

    def _scan_js_http_no_timeout(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect fetch() without AbortController/signal/timeout and axios without timeout."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "call_expression":
                continue
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                continue
            fn_text = document.text_for(fn_node).strip()

            if fn_text == "fetch":
                call_text = document.text_for(node)
                if "signal" not in call_text and "timeout" not in call_text and "AbortController" not in call_text:
                    line_start, line_end = document.line_range(node)
                    hits.append(RuleHit(
                        HTTP_NO_TIMEOUT, document.relative_path, line_start, line_end,
                        language=language,
                        message="`fetch()` called without `signal` (AbortController) or timeout option.",
                        metadata={"call": "fetch"},
                    ))

            elif fn_text in {"axios.get", "axios.post", "axios.put", "axios.patch", "axios.delete", "axios.request"}:
                call_text = document.text_for(node)
                if "timeout" not in call_text:
                    line_start, line_end = document.line_range(node)
                    hits.append(RuleHit(
                        HTTP_NO_TIMEOUT, document.relative_path, line_start, line_end,
                        language=language,
                        message=f"`{fn_text}()` called without a `timeout` option.",
                        metadata={"call": fn_text},
                    ))

        return hits

    def _scan_js_blocking_in_async(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect synchronous Node.js APIs inside async functions (e.g. readFileSync in async fn)."""
        hits: list[RuleHit] = []
        async_func_types = {"arrow_function", "function_declaration", "function", "method_definition"}
        for node in self._walk_nodes(document.root_node):
            if node.type not in async_func_types:
                continue
            # Check if function is async
            node_text_start = document.source[node.start_byte:min(node.start_byte + 30, node.end_byte)]
            if "async" not in node_text_start:
                continue
            # Scan body for blocking sync calls
            body = node.child_by_field_name("body")
            if body is None:
                continue
            for child in self._walk_nodes(body):
                if child.type not in {"call_expression", "member_expression"}:
                    continue
                child_text = document.text_for(child).strip()
                for sync_call in _JS_BLOCKING_SYNC_CALLS:
                    if sync_call in child_text:
                        line_start, line_end = document.line_range(child)
                        # Extract function name for the message
                        fn_name = self._ts_function_name(node, document) or "<async>"
                        hits.append(RuleHit(
                            BLOCKING_CALL_IN_ASYNC, document.relative_path, line_start, line_end,
                            language=language,
                            message=f"Async function `{fn_name}` calls synchronous API `{sync_call}` — use the async version instead.",
                            metadata={"call": sync_call, "function": fn_name},
                        ))
                        break  # One hit per call node
        return hits

    def _scan_js_retry_without_backoff(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect retry loops with try/catch but no setTimeout/sleep/delay."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"while_statement", "for_statement", "for_in_statement"}:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            body_text = document.text_for(body)
            # Must contain try/catch
            if "catch" not in body_text:
                continue
            # Should not contain sleep/delay/setTimeout/await
            has_backoff = any(kw in body_text for kw in (
                "setTimeout", "sleep", "delay", "await", "backoff",
            ))
            if not has_backoff:
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    RETRY_WITHOUT_BACKOFF, document.relative_path, line_start, line_end,
                    language=language,
                    message="Retry loop catches errors but has no sleep, delay, or backoff between attempts.",
                ))
        return hits

    # ════════════════════════════════════════════════════════════════════
    # C++ tree-sitter analysis
    # ════════════════════════════════════════════════════════════════════

    def _scan_cpp_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        hits.extend(self._scan_cpp_busy_wait(document, language))
        hits.extend(self._scan_cpp_mutex_lock_no_unlock(document, language))
        return hits

    def _scan_cpp_busy_wait(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect C++ busy-wait: while(true){} or while(cond){} with trivial body."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "while_statement":
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            if self._ts_loop_contains_sleep(body, document):
                continue
            if self._ts_body_is_trivial(body, document):
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    BUSY_WAIT, document.relative_path, line_start, line_end,
                    language=language,
                    message="Busy-wait loop without sleep or condition variable — wastes CPU cycles.",
                ))
        return hits

    def _scan_cpp_mutex_lock_no_unlock(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect raw mutex.lock() without corresponding unlock() — prefer lock_guard/unique_lock."""
        hits: list[RuleHit] = []
        func_types = {"function_definition", "lambda_expression"}
        for node in self._walk_nodes(document.root_node):
            if node.type not in func_types:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            body_text = document.text_for(body)

            # Check for raw .lock() calls
            lock_pattern = re.compile(r"(\w+)\s*\.\s*lock\s*\(\s*\)")
            unlock_pattern_template = r"{name}\s*\.\s*unlock\s*\(\s*\)"
            # Also check for RAII guards
            has_raii = any(guard in body_text for guard in (
                "lock_guard", "unique_lock", "scoped_lock", "shared_lock",
            ))
            if has_raii:
                continue

            for lock_match in lock_pattern.finditer(body_text):
                var_name = lock_match.group(1)
                unlock_re = re.compile(unlock_pattern_template.format(name=re.escape(var_name)))
                if not unlock_re.search(body_text):
                    abs_offset = body.start_byte + lock_match.start()
                    line_no = document.source[:abs_offset].count("\n") + 1
                    hits.append(RuleHit(
                        MUTEX_LOCK_NO_UNLOCK, document.relative_path, line_no, line_no,
                        language=language,
                        message=f"`{var_name}.lock()` without `{var_name}.unlock()` — use `std::lock_guard` or `std::unique_lock`.",
                    ))
        return hits

    # ════════════════════════════════════════════════════════════════════
    # C# tree-sitter analysis
    # ════════════════════════════════════════════════════════════════════

    def _scan_csharp_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        hits.extend(self._scan_csharp_blocking_in_async(document, language))
        hits.extend(self._scan_csharp_http_no_timeout(document, language))
        return hits

    def _scan_csharp_blocking_in_async(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect .Result / .Wait() / .GetAwaiter().GetResult() in async methods — deadlock risk."""
        hits: list[RuleHit] = []
        source = document.source

        for node in self._walk_nodes(document.root_node):
            if node.type != "method_declaration":
                continue
            # Check if method is async
            text = document.text_for(node)
            first_line = text.split("\n")[0] if text else ""
            if "async" not in first_line:
                continue

            # Look for .Result, .Wait(), .GetAwaiter().GetResult() in body
            body = node.child_by_field_name("body")
            if not body:
                continue
            body_text = document.text_for(body)

            blocking_patterns = [
                (r"\.Result\b", ".Result"),
                (r"\.Wait\s*\(\s*\)", ".Wait()"),
                (r"\.GetAwaiter\s*\(\s*\)\s*\.GetResult\s*\(\s*\)", ".GetAwaiter().GetResult()"),
            ]

            for pattern, label in blocking_patterns:
                for match in re.finditer(pattern, body_text):
                    abs_offset = body.start_byte + match.start()
                    line_no = source[:abs_offset].count("\n") + 1
                    hits.append(RuleHit(
                        BLOCKING_CALL_IN_ASYNC, document.relative_path, line_no, line_no,
                        language=language,
                        message=f"Blocking call `{label}` inside async method — can cause deadlock. Use `await` instead.",
                    ))
                    break  # One hit per pattern per method

        return hits

    def _scan_csharp_http_no_timeout(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect new HttpClient() without Timeout setting."""
        hits: list[RuleHit] = []
        source = document.source

        for match in re.finditer(r"new\s+HttpClient\s*\(\s*\)", source):
            # Check if Timeout is set nearby (within 5 lines)
            line_no = source[:match.start()].count("\n") + 1
            lines = source.splitlines()
            end_check = min(len(lines), line_no + 5)
            following = "\n".join(lines[line_no:end_check])
            if ".Timeout" in following or "Timeout =" in following:
                continue
            hits.append(RuleHit(
                HTTP_NO_TIMEOUT, document.relative_path, line_no, line_no,
                language=language,
                message="`new HttpClient()` without setting `.Timeout` — defaults to 100 seconds. Set explicit timeout for production use.",
            ))

        return hits

    # ════════════════════════════════════════════════════════════════════
    # Shared tree-sitter helpers
    # ════════════════════════════════════════════════════════════════════

    @staticmethod
    def _walk_nodes(node: Node):  # type: ignore[override]
        """Recursively yield all descendant nodes."""
        yield node
        for child in node.children:
            yield from PerformanceEngine._walk_nodes(child)

    @staticmethod
    def _ts_loop_contains_sleep(body_node: Node, document: TreeSitterDocument) -> bool:
        """Check if a loop body contains a sleep/delay call."""
        body_text = document.text_for(body_node)
        sleep_markers = (
            # Python
            "time.sleep", "asyncio.sleep",
            # Java
            "Thread.sleep", "TimeUnit.",
            # Go
            "time.Sleep",
            # JS/TS
            "setTimeout", "sleep(", "delay(",
            # C++
            "std::this_thread::sleep_for", "sleep(", "usleep(", "nanosleep(",
            # Generic
            "backoff",
        )
        return any(marker in body_text for marker in sleep_markers)

    @staticmethod
    def _ts_body_is_trivial(body_node: Node, document: TreeSitterDocument) -> bool:
        """Check if a block body is trivial (empty, only comments, or only continue/break)."""
        meaningful_children = [
            child for child in body_node.named_children
            if child.type not in {"comment", "line_comment", "block_comment"}
        ]
        if not meaningful_children:
            return True
        # Check if all statements are trivial (continue, break, empty expression)
        for child in meaningful_children:
            if child.type in {"continue_statement", "break_statement"}:
                continue
            text = document.text_for(child).strip()
            if text in {"continue", "break", "continue;", "break;", "pass", ";"}:
                continue
            return False
        return True

    @staticmethod
    def _ts_has_catch_that_swallows(body_node: Node, document: TreeSitterDocument) -> bool:
        """Check if a block contains a try-catch where catch swallows the exception."""
        for child in PerformanceEngine._walk_nodes(body_node):
            if child.type not in {"catch_clause", "catch_body"}:
                continue
            catch_body = child.child_by_field_name("body")
            if catch_body is None:
                # Try to find block child
                for sub in child.named_children:
                    if sub.type in {"block", "statement_block", "compound_statement"}:
                        catch_body = sub
                        break
            if catch_body is None:
                return True  # Empty catch
            meaningful = [
                c for c in catch_body.named_children
                if c.type not in {"comment", "line_comment", "block_comment"}
            ]
            if not meaningful:
                return True
            # All are logging calls — swallowed
            all_log = True
            for stmt in meaningful:
                text = document.text_for(stmt).strip()
                if not any(log_kw in text for log_kw in (
                    "log.", "Log.", "LOG.", "logger.", "Logger.",
                    "System.out.", "System.err.", "console.",
                    "println", "printf", "print(",
                    "continue", "continue;",
                )):
                    all_log = False
                    break
            if all_log:
                return True
        return False

    @staticmethod
    def _ts_function_name(node: Node, document: TreeSitterDocument) -> str | None:
        """Extract function name from a function declaration/expression node."""
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return document.text_for(name_node).strip()
        # For arrow functions assigned to variables: const fn = async () => {}
        parent = node.parent
        if parent is not None and parent.type in {"variable_declarator", "assignment_expression"}:
            name_node = parent.child_by_field_name("name") or parent.child_by_field_name("left")
            if name_node is not None:
                return document.text_for(name_node).strip()
        return None
