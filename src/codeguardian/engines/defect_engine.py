"""DefectEngine — detects code defects using AST-enhanced rules.

Dimension 5: Quality & Defect Analyzer
Combines AST precision with regex coverage for comment-style and legacy cases.
"""

from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from codeguardian.core.context import ScanContext
from codeguardian.engines.rule_helpers import (
    RuleHit,
    RuleSpec,
    build_finding,
    is_suppressed_by_inline_comment,
    is_test_file_path,
)
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


SUPPORTED_DEFECT_LANGUAGES = {
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "cpp",
    "csharp",
    "lua",
    "rust",
}
LANGUAGE_BY_SUFFIX = {
    suffix: language
    for suffix, language in EXTENSION_LANGUAGE_MAP.items()
    if language in SUPPORTED_DEFECT_LANGUAGES
}
SUPPORTED_EXTENSIONS = set(LANGUAGE_BY_SUFFIX)

# Sentinel for non-constant / non-hashable dict keys
_UNHASHABLE: object = object()


DEAD_CODE = RuleSpec(
    rule_id="DEAD-CODE",
    title="检测到死代码或待清理标记 (Dead code marker)",
    category="defect",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    fix_suggestion="删除死代码，或将清理标记替换为可追踪的 issue 并补充明确说明。",
    risk_priority="can-fix",
    tags=("defect", "cleanup"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp", "lua", "rust"),
    description_zh="检测到死代码标记或待清理注释（如 TODO、FIXME、HACK 等）。遗留的死代码会增加维护负担，容易让后续开发者产生误解。",
)
EMPTY_EXCEPT = RuleSpec(
    rule_id="EMPTY-EXCEPT",
    title="检测到空异常处理块 (Empty exception handler)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="添加日志、恢复逻辑，或在处理后重新抛出异常。",
    risk_priority="should-fix",
    tags=("defect", "exceptions"),
    applicable_languages=("python", "java", "javascript", "typescript", "cpp", "csharp", "go"),
    description_zh="检测到空的异常处理块（except/catch 中没有任何逻辑）。这会「吞掉」异常，导致错误被静默忽略，运行时问题极难排查。",
)
PRINT_DEBUG = RuleSpec(
    rule_id="PRINT-DEBUG",
    title="源码中存在调试打印/日志 (Debug print/log)",
    category="defect",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    fix_suggestion="用结构化日志替代临时打印，并移除残留调试语句。",
    risk_priority="can-fix",
    tags=("defect", "logging"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp", "lua", "rust"),
    description_zh="检测到残留的调试打印语句（如 print()）。生产代码中的调试输出会暴露内部信息，也会产生无意义的日志噪音。",
)
ASSERT_USED = RuleSpec(
    rule_id="ASSERT-USED",
    title="生产代码中使用了 assert (Assert in production code)",
    category="defect",
    severity=Severity.INFO,
    confidence=Confidence.MEDIUM,
    fix_suggestion="不要依赖 assert 做业务校验或生产路径中的安全检查。",
    risk_priority="can-fix",
    tags=("defect", "assert"),
    applicable_languages=("python", "java", "javascript", "typescript", "cpp", "csharp", "lua", "rust"),
    description_zh="在生产代码中使用了 assert 语句。Python 在 -O 优化模式下会移除所有 assert，因此不能依赖它做业务校验或安全检查。",
)
BROAD_EXCEPT = RuleSpec(
    rule_id="BROAD-EXCEPT",
    title="检测到过宽泛的异常捕获 (Broad exception catch)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="捕获具体异常类型，避免直接捕获 Exception/BaseException/Throwable。",
    risk_priority="should-fix",
    tags=("defect", "exceptions"),
    applicable_languages=("python", "java", "javascript", "typescript", "csharp", "cpp"),
    description_zh="检测到过于宽泛的异常捕获（如 except Exception）。这会隐藏本不应被忽略的错误（如 KeyboardInterrupt、SystemExit），使程序行为不可预测。",
)
BARE_EXCEPT = RuleSpec(
    rule_id="BARE-EXCEPT",
    title="裸 except 捕获所有异常 (Bare except)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="捕获具体异常类型，避免吞掉系统退出和中断信号。",
    risk_priority="must-fix",
    tags=("defect", "exceptions"),
    applicable_languages=("python", "cpp"),
    description_zh="检测到裸 except（except: 不指定异常类型）。这是最危险的异常捕获方式，会吞掉包括 SystemExit 和 KeyboardInterrupt 在内的所有异常。",
)
SYNTAX_ERROR = RuleSpec(
    rule_id="SYNTAX-ERROR",
    title="源码文件包含语法错误 (Syntax error)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="先修复语法错误，确保后续分析流水线可以可靠检查该文件。",
    risk_priority="must-fix",
    tags=("defect", "syntax"),
    applicable_languages=("python", "java", "javascript", "typescript"),
    description_zh="源代码文件包含语法错误（Syntax Error），无法被正确解析。这意味着代码无法运行，也无法被其他分析引擎检查。",
)
LOG_ONLY_EXCEPT = RuleSpec(
    rule_id="LOG-ONLY-EXCEPT",
    title="异常处理仅记录日志后吞掉错误 (Log-only exception handler)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="记录日志后重新抛出异常、返回明确兜底值，或添加显式恢复逻辑。",
    risk_priority="should-fix",
    tags=("defect", "exceptions", "logging"),
    applicable_languages=("python", "java", "javascript", "typescript", "cpp", "go"),
    cwe_ids=("CWE-755",),
    description_zh="异常处理块仅记录日志后就静默忽略了错误（log and swallow）。调用方无法感知异常发生，可能在错误状态下继续执行，引发更严重的连锁故障。",
    reference_url="https://cwe.mitre.org/data/definitions/755.html",
)
RESOURCE_LEAK = RuleSpec(
    rule_id="RESOURCE-LEAK",
    title="资源获取后缺少确定性清理 (Resource leak)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="优先使用 `with` / try-with-resources / `defer`，或确保资源在作用域退出前于 `finally` 中关闭。",
    risk_priority="should-fix",
    tags=("defect", "resource", "lifecycle"),
    applicable_languages=("python", "java", "cpp", "go", "javascript", "typescript"),
    cwe_ids=("CWE-772", "CWE-404"),
    description_zh="打开了文件、数据库连接或网络套接字等资源，但没有使用 with 语句或 try/finally 来确保释放。资源泄漏会导致文件句柄耗尽、连接池溢出等运行时故障。",
    reference_url="https://cwe.mitre.org/data/definitions/772.html",
)
GO_ERROR_IGNORED = RuleSpec(
    rule_id="GO-ERROR-IGNORED",
    title="Go error 返回值被空白标识符丢弃 (Ignored Go error)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="显式处理 error：检查 `if err != nil` 并返回/记录，或说明为什么可以安全忽略。",
    risk_priority="must-fix",
    tags=("defect", "error-handling", "go"),
    applicable_languages=("go",),
    cwe_ids=("CWE-252",),
    description_zh="Go 函数返回的 error 值被 `_` 丢弃。忽略错误会导致程序在异常状态下继续执行，后续操作可能产生不可预测的结果甚至崩溃。",
    reference_url="https://cwe.mitre.org/data/definitions/252.html",
)
GO_DEFER_IN_LOOP = RuleSpec(
    rule_id="GO-DEFER-IN-LOOP",
    title="循环中使用 defer 导致延迟调用累积 (Defer in loop)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="将资源处理移入辅助函数，或在循环体内显式调用 Close()，避免使用 defer 累积资源。",
    risk_priority="must-fix",
    tags=("defect", "resource", "go", "loop"),
    applicable_languages=("go",),
    cwe_ids=("CWE-772",),
    description_zh="在循环体内使用了 defer 语句。Go 的 defer 在函数返回时才执行，在循环中 defer 会导致资源（如文件句柄）不断累积而不被释放，最终耗尽系统资源。",
    reference_url="https://go.dev/doc/effective_go#defer",
)
JS_UNHANDLED_PROMISE = RuleSpec(
    rule_id="JS-UNHANDLED-PROMISE",
    title="Promise 未 await 或 .catch() 处理 (Unhandled Promise)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在异步调用前添加 `await`，或链式调用 `.catch(handler)` 处理拒绝。",
    risk_priority="should-fix",
    tags=("defect", "async", "promise", "javascript", "typescript"),
    applicable_languages=("javascript", "typescript"),
    cwe_ids=("CWE-755",),
    description_zh="异步函数的返回值（Promise）既没有被 await 也没有通过 .catch() 处理错误。未处理的 Promise 拒绝会导致 UnhandledPromiseRejection 错误。",
    reference_url="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise",
)

# ── New bug-detection rules ──────────────────────────────────────────────
UNREACHABLE_CODE = RuleSpec(
    rule_id="UNREACHABLE-CODE",
    title="控制流终止后存在不可达代码 (Unreachable code)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="删除或重构 return/raise/break/continue 等控制流终止语句之后的不可达代码。",
    risk_priority="should-fix",
    tags=("defect", "logic", "dead-code"),
    applicable_languages=("python", "java", "javascript", "typescript", "cpp", "go", "lua"),
    cwe_ids=("CWE-561",),
    description_zh="在 return/raise/break/continue 之后存在无法执行到的代码。这通常是逻辑错误或重构遗留，会误导代码读者。",
    reference_url="https://cwe.mitre.org/data/definitions/561.html",
)
POSSIBLE_NONE_DEREF = RuleSpec(
    rule_id="POSSIBLE-NONE-DEREF",
    title="可能发生 None 空指针解引用 (Possible None dereference)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在访问属性或调用方法前增加 None 检查。",
    risk_priority="must-fix",
    tags=("defect", "null-safety", "crash"),
    applicable_languages=("python", "java", "cpp", "go", "javascript", "typescript"),
    cwe_ids=("CWE-476",),
    description_zh="变量可能为 None（例如函数可能返回 None），但后续代码直接对其访问属性或调用方法。运行时会抛出 AttributeError/TypeError 导致崩溃。",
    reference_url="https://cwe.mitre.org/data/definitions/476.html",
)
SUSPICIOUS_BOOLEAN_BITWISE = RuleSpec(
    rule_id="SUSPICIOUS-BOOLEAN-BITWISE",
    title="布尔条件中疑似误用按位运算符 (Suspicious boolean bitwise operator)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="在布尔条件中优先使用短路逻辑运算符 `&&` / `||`；只有确实需要两侧都执行时才保留 `&` / `|` 并添加注释。",
    risk_priority="should-fix",
    tags=("defect", "logic", "boolean", "java"),
    applicable_languages=("java",),
    cwe_ids=("CWE-480",),
    description_zh="Java 布尔表达式中使用单个 `&` 或 `|` 时不会短路求值，可能导致右侧表达式在左侧已经足以决定结果时仍被执行。多数业务条件应使用 `&&` / `||`，否则容易引入空指针或副作用问题。",
    reference_url="https://cwe.mitre.org/data/definitions/480.html",
)
DIVISION_BY_ZERO_RISK = RuleSpec(
    rule_id="DIVISION-BY-ZERO-RISK",
    title="除数缺少零值保护 (Division by zero risk)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在除法或取模前显式校验分母不为 0，或为外部输入/配置值提供安全默认值。",
    risk_priority="should-fix",
    tags=("defect", "logic", "arithmetic", "java"),
    applicable_languages=("python", "java", "cpp", "go"),
    cwe_ids=("CWE-369",),

    description_zh="除法或取模使用了可能来自外部输入/配置解析的值作为分母，但未看到零值保护。分母为 0 会在运行时抛出 ArithmeticException 或产生无效结果。",
    reference_url="https://cwe.mitre.org/data/definitions/369.html",
)
COLLECTION_INDEX_OUT_OF_BOUNDS = RuleSpec(
    rule_id="COLLECTION-INDEX-OUT-OF-BOUNDS",
    title="集合或数组索引可能越界 (Collection index out of bounds)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="遍历集合/数组时使用 `< size()` 或 `< length`，避免 `<=` 访问最后一个非法索引。",
    risk_priority="must-fix",
    tags=("defect", "logic", "bounds", "java"),
    applicable_languages=("python", "java", "cpp", "go"),
    cwe_ids=("CWE-193", "CWE-129"),

    description_zh="循环边界使用 `<= size()` 或 `<= length` 时，最后一次迭代会访问等于长度的索引，导致 IndexOutOfBoundsException 或 ArrayIndexOutOfBoundsException。",
    reference_url="https://cwe.mitre.org/data/definitions/193.html",
)
SWALLOWED_EXCEPTION_FLOW = RuleSpec(
    rule_id="SWALLOWED-EXCEPTION-FLOW",
    title="异常被记录后以默认控制流吞掉 (Swallowed exception flow)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="记录异常后应重新抛出、返回显式错误结果，或补充可验证的恢复逻辑，避免调用方误以为操作成功。",
    risk_priority="should-fix",
    tags=("defect", "exceptions", "error-handling", "java"),
    applicable_languages=("python", "java", "cpp", "go"),
    cwe_ids=("CWE-755",),

    description_zh="catch 块记录异常后直接返回默认值、跳出循环或继续执行，会隐藏失败状态，使调用方无法感知错误，容易引发后续连锁故障。",
    reference_url="https://cwe.mitre.org/data/definitions/755.html",
)
STATIC_MUTABLE_SHARED_STATE = RuleSpec(
    rule_id="STATIC-MUTABLE-SHARED-STATE",
    title="静态可变共享状态可能引发并发问题 (Static mutable shared state)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="避免使用可变 static 集合/配置对象作为全局共享状态；如确有必要，使用不可变对象、并发集合或明确的同步边界。",
    risk_priority="should-fix",
    tags=("defect", "concurrency", "shared-state", "java"),
    applicable_languages=("java",),
    cwe_ids=("CWE-362",),
    description_zh="非 final 的 static 可变集合/配置对象会在多个线程之间共享，若缺少清晰同步策略，容易导致竞态、脏读或测试间状态污染。",
    reference_url="https://cwe.mitre.org/data/definitions/362.html",
)
RESOURCE_CLOSE_NOT_GUARANTEED = RuleSpec(
    rule_id="RESOURCE-CLOSE-NOT-GUARANTEED",
    title="资源关闭路径不完整 (Resource close not guaranteed)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="使用 try-with-resources，或把 close() 放入 finally，确保读取、解析或业务处理异常时资源也能释放。",
    risk_priority="should-fix",
    tags=("defect", "resource", "lifecycle", "java"),
    applicable_languages=("python", "java", "cpp", "go"),
    cwe_ids=("CWE-772", "CWE-404"),

    description_zh="资源虽然调用了 close()，但未放在 try-with-resources 或 finally 中。中途抛出异常时 close() 可能不会执行，导致文件句柄、连接等资源泄漏。",
    reference_url="https://cwe.mitre.org/data/definitions/772.html",
)
UNUSED_VARIABLE = RuleSpec(


    rule_id="UNUSED-VARIABLE",
    title="变量被赋值但从未使用 (Unused variable)",
    category="defect",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    fix_suggestion="删除未使用变量，或在后续逻辑中正确使用它。",
    risk_priority="can-fix",
    tags=("defect", "cleanup", "unused"),
    applicable_languages=("python", "java", "cpp", "go", "javascript", "typescript", "lua"),
    cwe_ids=("CWE-563",),
    description_zh="变量被赋值但后续从未被读取或使用。这通常是重构残留或逻辑遗漏（本应使用该变量但忘记了）。",
    reference_url="https://cwe.mitre.org/data/definitions/563.html",
)
ALWAYS_TRUE_FALSE = RuleSpec(
    rule_id="ALWAYS-TRUE-FALSE",
    title="条件恒真或恒假 (Always true/false condition)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="该条件是编译期常量；如为有意设计请补充注释，否则应修正逻辑。",
    risk_priority="should-fix",
    tags=("defect", "logic", "dead-branch"),
    applicable_languages=("python",),
    cwe_ids=("CWE-570", "CWE-571"),
    description_zh="条件表达式的结果在编译期就已确定（恒为 True 或恒为 False），意味着某个分支永远不会执行。这通常是条件写错或逻辑重构不完整。",
    reference_url="https://cwe.mitre.org/data/definitions/570.html",
)
EXCEPTION_NOT_RAISED = RuleSpec(
    rule_id="EXCEPTION-NOT-RAISED",
    title="创建了异常对象但未抛出 (Exception not raised)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="在异常构造调用前添加 `raise`，确保错误真正被抛出。",
    risk_priority="must-fix",
    tags=("defect", "logic", "exception"),
    applicable_languages=("python",),
    cwe_ids=("CWE-390",),
    description_zh="创建了异常对象（如 ValueError(...)）但忘记用 raise 抛出。代码看起来像在做错误处理，实际上异常被静默丢弃，程序会在错误状态下继续执行。",
    reference_url="https://cwe.mitre.org/data/definitions/390.html",
)
MUTABLE_DEFAULT_ARG = RuleSpec(
    rule_id="MUTABLE-DEFAULT-ARG",
    title="函数定义中使用可变默认参数 (Mutable default argument)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="使用 `None` 作为默认值，并在函数体内创建可变对象。",
    risk_priority="should-fix",
    tags=("defect", "logic", "mutable-default"),
    applicable_languages=("python",),
    cwe_ids=("CWE-665",),
    description_zh="函数参数使用了可变对象（如 list、dict、set）作为默认值。Python 中默认值只在函数定义时创建一次，后续调用会共享同一个对象，导致意外的状态串扰（mutable default argument trap）。",
    reference_url="https://cwe.mitre.org/data/definitions/665.html",
)
EXCEPTION_SWALLOWED_NO_LOG = RuleSpec(
    rule_id="EXCEPTION-SWALLOWED-NO-LOG",
    title="异常被吞掉且没有日志 (Exception swallowed without logging)",
    category="defect",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在 except 块内至少记录一条 log（含 traceback），或重新抛出异常；不要静默吞掉错误。",
    risk_priority="can-fix",
    tags=("defect", "exceptions", "observability"),
    applicable_languages=("python",),
    cwe_ids=("CWE-390", "CWE-755"),
    description_zh="except 块内既没有 raise 也没有任何日志调用，异常被静默吞掉（如 except: x = default、except Exception: return None）。这会让线上问题极难排查 —— 看到的只有最终的默认值，根因丢失。注意：严格的 `except: pass` 由 EMPTY-EXCEPT 覆盖；只 log 不 raise 由 LOG-ONLY-EXCEPT 覆盖；本规则补齐两者之间的盲区。",
    reference_url="https://cwe.mitre.org/data/definitions/755.html",
)
SUBPROCESS_SHELL_TRUE = RuleSpec(
    rule_id="SUBPROCESS-SHELL-TRUE",
    title="subprocess 调用使用 shell=True (Subprocess invoked with shell=True)",
    category="defect",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    fix_suggestion="尽量使用参数列表（如 subprocess.run([\"git\", \"status\"]) 不带 shell=True）；如确需 shell 特性，确保命令不含任何外部输入。",
    risk_priority="can-fix",
    tags=("defect", "subprocess", "shell"),
    applicable_languages=("python",),
    cwe_ids=("CWE-78",),
    description_zh="subprocess.run / Popen / call / check_output 显式传入 shell=True。即使本次调用的命令是字面量、当前没有命令注入风险，shell=True 也会让任何后续修改（拼接变量、读取配置、接受参数）极易引入命令注入。安全侧的 COMMAND-INJECTION-RISK 仅在检测到外部输入流入时报 CRITICAL，本规则作为更宽松的静态兜底，提示团队尽量避免该写法。",
    reference_url="https://docs.python.org/3/library/subprocess.html#security-considerations",
)
SELF_ASSIGNMENT = RuleSpec(
    rule_id="SELF-ASSIGNMENT",
    title="变量被赋值为自身，疑似复制粘贴错误 (Self assignment)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="修正赋值右侧表达式，或删除该无效语句。",
    risk_priority="should-fix",
    tags=("defect", "logic", "copy-paste"),
    applicable_languages=("python", "java", "cpp", "go", "javascript", "typescript", "lua"),
    cwe_ids=("CWE-682",),
    description_zh="变量被赋值为它自身（如 x = x），这是典型的复制粘贴错误。赋值操作没有实际效果，右侧可能写错了变量名。",
    reference_url="https://cwe.mitre.org/data/definitions/682.html",
)
REDEFINE_IN_LOOP = RuleSpec(
    rule_id="REDEFINE-IN-LOOP",
    title="循环内重复定义函数或类，疑似 bug (Redefinition in loop)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="将定义移到循环外，或使用闭包/lambda 显式捕获循环变量。",
    risk_priority="should-fix",
    tags=("defect", "logic", "scoping"),
    applicable_languages=("python",),
    cwe_ids=("CWE-710",),
    description_zh="在循环体内重复定义了函数或类。每次迭代都会覆盖前一次的定义，通常是作用域理解错误或 late-binding closure 陷阱。",
    reference_url="https://cwe.mitre.org/data/definitions/710.html",
)
EXCEPTION_LOST_CONTEXT = RuleSpec(
    rule_id="EXCEPTION-LOST-CONTEXT",
    title="except 中重新抛出异常丢失原始 traceback (Lost exception context)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="使用 `raise NewException(...) from err` 保留原始异常链。",
    risk_priority="should-fix",
    tags=("defect", "exception", "traceback"),
    applicable_languages=("python",),
    cwe_ids=("CWE-755",),
    description_zh="在 except 块中抛出新异常时没有使用 `from err` 语法，导致原始异常的 traceback 丢失。排查问题时无法追溯到真正的错误源头（exception chaining lost）。",
    reference_url="https://cwe.mitre.org/data/definitions/755.html",
)
INFINITE_RECURSION_RISK = RuleSpec(
    rule_id="INFINITE-RECURSION-RISK",
    title="函数无条件调用自身，疑似无限递归 (Infinite recursion risk)",
    category="defect",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    fix_suggestion="添加 base case 或终止条件，避免栈溢出。",
    risk_priority="must-fix",
    tags=("defect", "logic", "recursion", "crash"),
    applicable_languages=("python", "java", "cpp", "go", "javascript", "typescript", "lua"),
    cwe_ids=("CWE-674",),
    description_zh="函数无条件地调用自身，没有任何终止条件（base case）。运行时会导致无限递归，最终 RecursionError / StackOverflow 崩溃。",
    reference_url="https://cwe.mitre.org/data/definitions/674.html",
)
INFINITE_LOOP_RISK = RuleSpec(
    rule_id="INFINITE-LOOP-RISK",
    title="无退出条件的无限循环 (Infinite loop without exit condition)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="确保 while(true)/for(;;) 循环内有 break/return/throw 退出路径，或添加终止条件。",
    risk_priority="must-fix",
    tags=("defect", "logic", "infinite-loop", "hang"),
    applicable_languages=("python", "java", "cpp", "go", "javascript", "typescript"),
    cwe_ids=("CWE-835",),
    description_zh="检测到 while(true)/for(;;) 循环体内无 break/return/throw 语句，运行时将永远不会退出，导致 CPU 100% 或程序挂死。",
    reference_url="https://cwe.mitre.org/data/definitions/835.html",
)
MISSING_SUPER_INIT = RuleSpec(
    rule_id="MISSING-SUPER-INIT",
    title="子类 __init__ 未调用 super().__init__ (Missing super init)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在子类 __init__ 中调用 `super().__init__(...)`，确保父类初始化逻辑被执行。",
    risk_priority="should-fix",
    tags=("defect", "oop", "initialization"),
    applicable_languages=("python", "java", "cpp"),
    cwe_ids=("CWE-665",),
    description_zh="子类的 __init__ 方法中没有调用 super().__init__()。父类的初始化逻辑被跳过，可能导致父类属性未设置、MRO（方法解析顺序）链断裂等隐蔽 bug。",
    reference_url="https://cwe.mitre.org/data/definitions/665.html",
)
IDENTIFIER_TYPO = RuleSpec(
    rule_id="IDENTIFIER-TYPO",
    title="标识符名称疑似拼写错误 (Identifier typo)",
    category="defect",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    fix_suggestion="修正标识符拼写，提升可读性并避免混淆。",
    risk_priority="can-fix",
    tags=("defect", "naming", "typo"),
    applicable_languages=("python",),
    cwe_ids=("CWE-710",),
    description_zh="标识符（变量名/函数名/类名/参数名）中包含常见的英文拼写错误。拼写错误会降低代码可读性，也会导致 API 不一致、自动补全失效等连锁问题。",
    reference_url="https://cwe.mitre.org/data/definitions/710.html",
)
BOOL_PREFIX_NO_BOOL_RETURN = RuleSpec(
    rule_id="BOOL-PREFIX-NO-BOOL-RETURN",
    title="布尔前缀函数未返回 bool (Boolean prefix without bool return)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="重命名函数，或改为稳定返回 True/False。",
    risk_priority="should-fix",
    tags=("defect", "naming", "convention"),
    applicable_languages=("python",),
    cwe_ids=("CWE-710",),
    description_zh="函数名以 is_/has_/can_/should_ 等布尔前缀开头，但实际返回的不是布尔值。调用方按照命名约定会以 if is_xxx() 方式使用，非 bool 返回值可能导致 truthiness 判断错误。",
    reference_url="https://cwe.mitre.org/data/definitions/710.html",
)
GETTER_HAS_SIDE_EFFECT = RuleSpec(
    rule_id="GETTER-HAS-SIDE-EFFECT",
    title="get_* 函数包含写入/删除等副作用 (Getter has side effects)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="重命名为能体现副作用的动词（如 fetch_and_delete、ensure_*），或移除副作用。",
    risk_priority="should-fix",
    tags=("defect", "naming", "convention", "side-effect"),
    applicable_languages=("python",),
    cwe_ids=("CWE-710",),
    description_zh="以 get_ 开头的函数按照命名约定应该是纯读取操作（无副作用），但函数体内包含了 delete/save/commit/send 等写操作。命名与行为不符会导致调用方误判安全性（Command-Query Separation 违反）。",
    reference_url="https://en.wikipedia.org/wiki/Command%E2%80%93query_separation",
)
SETTER_RETURNS_VALUE = RuleSpec(
    rule_id="SETTER-RETURNS-VALUE",
    title="set_* 函数返回了非 None 值 (Setter returns value)",
    category="defect",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    fix_suggestion="setter 应返回 None；如果需要返回值，建议重命名为 update_* 或 with_*。",
    risk_priority="can-fix",
    tags=("defect", "naming", "convention"),
    applicable_languages=("python",),
    cwe_ids=("CWE-710",),
    description_zh="以 set_ 开头的函数按照命名约定应该是纯写入操作（返回 None），但实际返回了非 None 值。命名与行为不一致会让调用方困惑，建议重命名为 update_/with_ 或去掉返回值。",
    reference_url="https://cwe.mitre.org/data/definitions/710.html",
)
_DEAD_CODE_MARKERS_RE = r"(?:TODO|FIXME|HACK|XXX)\b"
_DEAD_CODE_ACTIONS_RE = r"(?:remove|delete|unused|dead|cleanup)"

_PYTHON_RESOURCE_FACTORY_CALLS = {

    "open",
    "sqlite3.connect",
    "socket.socket",
    "tarfile.open",
    "tempfile.NamedTemporaryFile",
    "tempfile.TemporaryDirectory",
    "zipfile.ZipFile",
    "requests.Session",
    "aiohttp.ClientSession",
    "httpx.Client",
}
_PYTHON_RESOURCE_CLOSE_METHODS = {"close", "cleanup", "aclose"}

ASYNC_VOID = RuleSpec(
    rule_id="ASYNC-VOID",
    title="async void 方法：异常不可观察 (async void method)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="将返回类型改为 async Task，确保调用方可以 await 并观察异常。",
    risk_priority="should-fix",
    tags=("csharp", "async", "exception"),
    applicable_languages=("csharp",),
    description_zh="async void 方法中未处理的异常会直接崩溃进程（不可被 try-catch 捕获），且调用方无法 await。",
)

STUB_IN_PROD = RuleSpec(
    rule_id="STUB-IN-PROD",
    title="占位/未实现代码可能进入生产路径 (stub / not-implemented in production path)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="在合并前把占位实现替换为真实逻辑；若必须保留，使用 feature flag 或显式禁用入口。",
    risk_priority="must-fix",
    tags=("stub", "todo", "release-risk"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "csharp", "rust", "cpp"),
    description_zh="函数体只抛 NotImplementedError / panic(\"TODO\") / throw NotImplementedException 等占位异常；这意味着功能没实现就上线，调用方在生产路径上会直接崩溃或报错。",
)

PYTHON_LOCK_NO_RELEASE = RuleSpec(
    rule_id="PYTHON-LOCK-NO-RELEASE",
    title="Python 锁未配对释放：死锁/资源泄露风险 (python lock acquired without guaranteed release)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="使用 `with lock:` 上下文管理器；或在 try/finally 中调用 release()，保证异常路径也能释放锁。",
    risk_priority="must-fix",
    tags=("python", "concurrency", "deadlock"),
    applicable_languages=("python",),
    description_zh="检测到 lock.acquire() 调用，但同函数内既未使用 with 语句，也没有 try/finally 中的 release() 配对；一旦中间抛异常，锁不会被释放，等价于死锁。",
)

HTTP_NO_STATUS_CHECK = RuleSpec(
    rule_id="HTTP-NO-STATUS-CHECK",
    title="HTTP 响应未检查状态码 (HTTP response status not checked)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="调用 `response.raise_for_status()`，或显式检查 `response.status_code`/`response.ok`，再使用 .json()/.text。",
    risk_priority="should-fix",
    tags=("python", "http", "error-handling"),
    applicable_languages=("python",),
    description_zh="`requests.get/post/...` 拿到 response 后直接使用 .json() / .text / .content，但完全没有检查 HTTP 状态码（无 raise_for_status / status_code / ok 引用）；4xx/5xx 时会拿到错误页 HTML 当成数据处理，导致难以排查的下游错误。",
)

DICT_ITERATE_MUTATE = RuleSpec(
    rule_id="DICT-ITERATE-MUTATE",
    title="迭代时修改容器：RuntimeError 或静默漏元素 (Iterate-while-mutate)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="先用 `list(d)` / `list(d.keys())` 做快照再迭代，或改用字典/列表推导生成新容器。",
    risk_priority="must-fix",
    tags=("defect", "logic", "iteration", "runtime-crash"),
    applicable_languages=("python",),
    cwe_ids=("CWE-664",),
    description_zh="在 for 循环内对正在迭代的 dict/list/set 调用 del/pop/clear/add/赋值新键，dict 会抛 `RuntimeError: dictionary changed size during iteration`；list 会跳过下一个元素造成静默漏处理。本机小数据集常常碰巧不命中，线上数据多了才挂。",
    reference_url="https://docs.python.org/3/library/stdtypes.html#dictionary-view-objects",
)

DUPLICATE_DICT_KEY = RuleSpec(
    rule_id="DUPLICATE-DICT-KEY",
    title="dict 字面量包含重复键，后者覆盖前者 (Duplicate dict key)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="检查重复键是否为复制粘贴遗留；保留期望的那个值并删除其他。",
    risk_priority="must-fix",
    tags=("defect", "logic", "copy-paste"),
    applicable_languages=("python",),
    cwe_ids=("CWE-561",),
    description_zh="dict 字面量 `{...}` 中出现完全相同的键（包括 1 与 1.0、True 与 1 这类 hash-equal 的等价键），后定义的值会无声覆盖前者。几乎一定是复制粘贴失误，建议人眼复核。",
)

JAVA_STRING_EQ_OPERATOR = RuleSpec(
    rule_id="JAVA-STRING-EQ-OPERATOR",
    title="使用 == / != 比较 String，应使用 .equals() (String compared with ==)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="用 `Objects.equals(a, b)` 或 `a != null && a.equals(b)` 比较字符串内容。",
    risk_priority="must-fix",
    tags=("defect", "java", "logic", "equality"),
    applicable_languages=("java",),
    cwe_ids=("CWE-595",),
    description_zh="Java 中 == 比较的是引用相等（同一对象），不是字符串内容；字面量因常量池常侥幸为真，但 new String / 来自 IO 的字符串就会失败。这是 Java 经典坑。",
    reference_url="https://cwe.mitre.org/data/definitions/595.html",
)

FOREACH_COLLECTION_MUTATE = RuleSpec(
    rule_id="FOREACH-COLLECTION-MUTATE",
    title="foreach 内修改正在遍历的集合 (foreach mutates collection)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="改用 Iterator.remove()、收集到临时列表后批量修改，或先复制集合再迭代。",
    risk_priority="must-fix",
    tags=("defect", "logic", "iteration", "runtime-crash"),
    applicable_languages=("java", "csharp"),
    cwe_ids=("CWE-664",),
    description_zh="Java/C# 在 for-each / foreach 体内对正在遍历的集合调用 add/remove/clear，运行时抛 ConcurrentModificationException / InvalidOperationException，直接崩溃。",
)

GO_RANGE_LOOP_VAR_ADDR = RuleSpec(
    rule_id="GO-RANGE-LOOP-VAR-ADDR",
    title="对 range 循环变量取地址 (Go<1.22 共享同一变量) (Loop var address aliased)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="在循环体内重新声明 `v := v` 局部副本，或改为按下标 `&xs[i]` 取地址。Go 1.22+ 已修正该陷阱。",
    risk_priority="must-fix",
    tags=("defect", "go", "loop", "alias"),
    applicable_languages=("go",),
    cwe_ids=("CWE-664",),
    description_zh="Go<1.22 中 `for _, v := range xs` 的 `v` 在每次迭代复用同一地址；将 `&v` 存入 slice、闭包或启动 goroutine 时全部指向最后一次的 v，导致全是同一个值。",
    reference_url="https://go.dev/blog/loopvar-preview",
)

GO_CHANNEL_SEND_AFTER_CLOSE = RuleSpec(
    rule_id="GO-CHANNEL-SEND-AFTER-CLOSE",
    title="向已 close 的 channel 发送数据，运行时 panic (Send on closed channel)",
    category="defect",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    fix_suggestion="将 close(ch) 移到所有发送方完成之后；或由专门的写方负责 close，读方仅 range/接收。",
    risk_priority="must-fix",
    tags=("defect", "go", "concurrency", "runtime-crash"),
    applicable_languages=("go",),
    cwe_ids=("CWE-672",),
    description_zh="同一函数内 `close(ch)` 之后仍出现 `ch <- x`，运行时直接 panic: send on closed channel。Go channel 设计要求由写方决定关闭时机。",
    reference_url="https://go.dev/ref/spec#Close",
)

CPP_USE_AFTER_FREE = RuleSpec(
    rule_id="CPP-USE-AFTER-FREE",
    title="C/C++ 释放后继续使用指针 (Use-after-free)",
    category="defect",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在 delete/free 之后将指针置为 nullptr/NULL；或改用 unique_ptr/shared_ptr 让所有权管理释放时机。",
    risk_priority="must-fix",
    tags=("defect", "cpp", "memory", "use-after-free"),
    applicable_languages=("cpp",),
    cwe_ids=("CWE-416",),
    description_zh="同函数内 `delete p` / `free(p)` 之后再次出现 `p->x` / `*p` / 把 p 传给其它函数，且未把 p 重置为 nullptr，存在悬空指针访问，是 C/C++ 最常见的内存安全漏洞之一。",
    reference_url="https://cwe.mitre.org/data/definitions/416.html",
)

CPP_DOUBLE_FREE = RuleSpec(
    rule_id="CPP-DOUBLE-FREE",
    title="C/C++ 同一指针被释放两次 (Double-free)",
    category="defect",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    fix_suggestion="释放后立即置 nullptr，或使用 smart pointer 让所有权管理生命周期。",
    risk_priority="must-fix",
    tags=("defect", "cpp", "memory", "double-free"),
    applicable_languages=("cpp",),
    cwe_ids=("CWE-415",),
    description_zh="同函数内同一个指针被 `delete` / `free` 两次，且中间未重赋值或置空 → heap corruption / 崩溃。",
    reference_url="https://cwe.mitre.org/data/definitions/415.html",
)

CPP_DELETE_MISMATCH = RuleSpec(
    rule_id="CPP-DELETE-MISMATCH",
    title="C++ new/delete 与 new[]/delete[] 不匹配",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="`new[]` 必须用 `delete[]` 释放；`new` 必须用 `delete` 释放。",
    risk_priority="must-fix",
    tags=("defect", "cpp", "memory"),
    applicable_languages=("cpp",),
    cwe_ids=("CWE-762",),
    description_zh="在同函数内 `T* p = new T[...]` 但用 `delete p` 释放（或反之）→ 未定义行为，实际会泄漏或破坏堆结构。",
    reference_url="https://cwe.mitre.org/data/definitions/762.html",
)

JAVA_HASHCODE_EQUALS_MISMATCH = RuleSpec(
    rule_id="JAVA-HASHCODE-EQUALS-MISMATCH",
    title="Java equals/hashCode 未成对重写",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="override equals 时必须同时 override hashCode（反之亦然），以保持契约一致。",
    risk_priority="must-fix",
    tags=("defect", "java", "contract"),
    applicable_languages=("java",),
    cwe_ids=("CWE-581",),
    description_zh="Java 类只 override 了 `equals(Object)` 或 `hashCode()` 其中之一，违反 Object 契约 → 放入 HashMap/HashSet 时行为错乱。",
    reference_url="https://cwe.mitre.org/data/definitions/581.html",
)

JAVA_EQUALS_ON_ARRAY = RuleSpec(
    rule_id="JAVA-EQUALS-ON-ARRAY",
    title="Java 对数组调用 equals (引用比较而非元素比较)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="比较数组内容请用 `Arrays.equals(a, b)`（多维数组用 `Arrays.deepEquals`）。",
    risk_priority="must-fix",
    tags=("defect", "java"),
    applicable_languages=("java",),
    cwe_ids=("CWE-595",),
    description_zh="Java 数组继承自 Object，其 `equals` 是引用比较而非元素比较，`a.equals(b)` 总是返回 false（除非同一对象） → 静默返回错误结果。",
    reference_url="https://docs.oracle.com/javase/tutorial/collections/algorithms/",
)

JAVA_INTEGER_BOXING_EQ = RuleSpec(
    rule_id="JAVA-INTEGER-BOXING-EQ",
    title="Java 装箱类型用 == 比较 (引用比较)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="比较装箱类型值相等请用 `.equals(...)` 或 `Objects.equals(...)`。",
    risk_priority="must-fix",
    tags=("defect", "java"),
    applicable_languages=("java",),
    cwe_ids=("CWE-595",),
    description_zh="Java 的 Integer/Long/Double/Boolean 等装箱类型用 `==` 比较是引用比较，仅在缓存范围 (-128..127) 内偶然为 true，超出范围时静默失败。",
    reference_url="https://cwe.mitre.org/data/definitions/595.html",
)

GO_NIL_MAP_WRITE = RuleSpec(
    rule_id="GO-NIL-MAP-WRITE",
    title="Go 向 nil map 写入",
    category="defect",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    fix_suggestion="使用 `m := make(map[K]V)` 初始化后再写入；或在写入前判空分配。",
    risk_priority="must-fix",
    tags=("defect", "go", "nil"),
    applicable_languages=("go",),
    cwe_ids=("CWE-476",),
    description_zh="Go 中 `var m map[K]V` 声明未经 `make` 初始化即 `m[k]=v` 会触发 `panic: assignment to entry in nil map`。",
    reference_url="https://go.dev/doc/effective_go#maps",
)

MONEY_FLOAT_PRECISION = RuleSpec(
    rule_id="MONEY-FLOAT-PRECISION",
    title="金额/货币字段使用浮点类型存在精度风险 (Money stored as float/double)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="金额计算使用 BigDecimal（Java/C#）、Decimal（Python/JS decimal.js）或定点整数（最小货币单位，如 cent）。",
    risk_priority="must-fix",
    tags=("defect", "precision", "money"),
    applicable_languages=("java", "csharp", "javascript", "typescript", "python", "go"),
    cwe_ids=("CWE-682",),
    description_zh="金额/价格/余额等货币字段使用 float/double/Number 类型存储。IEEE-754 浮点数无法精确表示十进制小数（如 0.1 + 0.2 ≠ 0.3），在金融计算中会逐步累积误差，导致对账偏差或资金损失。",
    reference_url="https://cwe.mitre.org/data/definitions/682.html",
)

BIGDECIMAL_DOUBLE_CTOR = RuleSpec(
    rule_id="BIGDECIMAL-DOUBLE-CTOR",
    title="BigDecimal 使用 double 构造器导致精度丢失 (BigDecimal constructed from double)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="改用 `new BigDecimal(\"0.1\")` 字符串构造、`BigDecimal.valueOf(0.1)` 或先 `Double.toString` 再构造。",
    risk_priority="must-fix",
    tags=("defect", "precision", "money"),
    applicable_languages=("java",),
    cwe_ids=("CWE-682",),
    description_zh="`new BigDecimal(double)` 直接接收浮点字面量会保留 IEEE-754 表示误差（如 `new BigDecimal(0.1)` 实际是 0.1000000000000000055511...）。这违背了引入 BigDecimal 的初衷，是金额计算最经典的精度坑。",
    reference_url="https://docs.oracle.com/javase/8/docs/api/java/math/BigDecimal.html#BigDecimal-double-",
)

EXECUTOR_NOT_SHUTDOWN = RuleSpec(
    rule_id="EXECUTOR-NOT-SHUTDOWN",
    title="ExecutorService/线程池创建后未 shutdown (ExecutorService not shut down)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在 finally 块中调用 `shutdown()`/`shutdownNow()`，或使用 try-with-resources（Java 19+ 起 ExecutorService 实现 AutoCloseable）。",
    risk_priority="must-fix",
    tags=("defect", "resource", "concurrency"),
    applicable_languages=("java",),
    cwe_ids=("CWE-404",),
    description_zh="通过 `Executors.newFixedThreadPool` / `newCachedThreadPool` / `newSingleThreadExecutor` 或 `new ThreadPoolExecutor(...)` 创建线程池后，整个文件中没有调用 `shutdown()` 或 `shutdownNow()`。线程池非守护线程会阻止 JVM 退出，长期运行还会泄漏线程与队列对象。",
    reference_url="https://cwe.mitre.org/data/definitions/404.html",
)

STATIC_SIMPLEDATEFORMAT = RuleSpec(
    rule_id="STATIC-SIMPLEDATEFORMAT",
    title="static SimpleDateFormat 字段非线程安全 (Shared SimpleDateFormat is not thread-safe)",
    category="defect",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="改用 `java.time.format.DateTimeFormatter`（不可变、线程安全）；若必须使用 `SimpleDateFormat`，每次新建实例或用 `ThreadLocal<SimpleDateFormat>` 包装。",
    risk_priority="must-fix",
    tags=("defect", "concurrency", "thread-safety"),
    applicable_languages=("java",),
    cwe_ids=("CWE-366",),
    description_zh="`SimpleDateFormat` 内部维护 `Calendar` 等可变状态，被多线程共享时会出现日期错乱、`NumberFormatException`、`ArrayIndexOutOfBoundsException` 等并发故障。声明为 `static` 字段意味着它会被全部线程共享，是经典并发陷阱。",
    reference_url="https://cwe.mitre.org/data/definitions/366.html",
)

MISSING_CHARSET = RuleSpec(
    rule_id="MISSING-CHARSET",
    title="字符串/IO 操作未显式指定字符集 (Missing explicit charset)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="显式传入字符集，例如 `new String(bytes, StandardCharsets.UTF_8)` / `bytes.getBytes(StandardCharsets.UTF_8)` / `new InputStreamReader(in, StandardCharsets.UTF_8)`。",
    risk_priority="should-fix",
    tags=("defect", "encoding", "portability"),
    applicable_languages=("java",),
    cwe_ids=("CWE-176",),
    description_zh="`new String(byte[])` / `byte[].getBytes()` / `new FileReader/FileWriter/InputStreamReader/OutputStreamWriter` 在未指定 `Charset` 时使用平台默认编码：Linux/macOS 通常是 UTF-8、Windows 简体常为 GBK，跨平台部署时会出现乱码或解析失败。",
    reference_url="https://cwe.mitre.org/data/definitions/176.html",
)

MISSING_TIMEZONE = RuleSpec(
    rule_id="MISSING-TIMEZONE",
    title="SimpleDateFormat 未显式设置时区 (SimpleDateFormat without explicit time zone)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在创建后调用 `df.setTimeZone(TimeZone.getTimeZone(\"UTC\"))`，或改用 `DateTimeFormatter.ofPattern(...).withZone(ZoneId.of(\"UTC\"))`。",
    risk_priority="should-fix",
    tags=("defect", "i18n", "time-zone"),
    applicable_languages=("java",),
    cwe_ids=("CWE-1389",),
    description_zh="`new SimpleDateFormat(pattern)` 默认使用 JVM 本地时区。如果服务跨多个机房 / 容器迁移到不同时区 / 数据回写到 UTC 数据库，会导致时间字符串解析出错或落库时间偏差数小时。整个文件中未发现 `setTimeZone` 调用即视为未显式管理时区。",
    reference_url="https://cwe.mitre.org/data/definitions/1389.html",
)

SWITCH_NO_DEFAULT = RuleSpec(
    rule_id="SWITCH-NO-DEFAULT",
    title="switch 缺少 default 分支 (Switch statement missing default branch)",
    category="defect",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="为 switch 添加 default 分支，明确处理未覆盖的情况（抛出异常 / 记录日志 / 返回兜底值），即使逻辑上认为不可能到达也要显式声明。",
    risk_priority="should-fix",
    tags=("defect", "robustness", "control-flow"),
    applicable_languages=("java",),
    cwe_ids=("CWE-478",),
    description_zh="switch 没有 default 分支时，新增枚举值或意外输入会被静默忽略，难以排查。即使当前所有 case 都覆盖完毕，也建议显式 default 防御 future-change。",
    reference_url="https://cwe.mitre.org/data/definitions/478.html",
)


DEFECT_RULES = register_rules(

    "defect",
    (
        DEAD_CODE,
        EMPTY_EXCEPT,
        PRINT_DEBUG,
        ASSERT_USED,
        BROAD_EXCEPT,
        BARE_EXCEPT,
        SYNTAX_ERROR,
        LOG_ONLY_EXCEPT,
        RESOURCE_LEAK,
        GO_ERROR_IGNORED,
        GO_DEFER_IN_LOOP,
        JS_UNHANDLED_PROMISE,
        UNREACHABLE_CODE,
        POSSIBLE_NONE_DEREF,
        SUSPICIOUS_BOOLEAN_BITWISE,
        DIVISION_BY_ZERO_RISK,
        COLLECTION_INDEX_OUT_OF_BOUNDS,
        SWALLOWED_EXCEPTION_FLOW,
        STATIC_MUTABLE_SHARED_STATE,
        RESOURCE_CLOSE_NOT_GUARANTEED,
        UNUSED_VARIABLE,


        ALWAYS_TRUE_FALSE,
        EXCEPTION_NOT_RAISED,
        MUTABLE_DEFAULT_ARG,
        EXCEPTION_SWALLOWED_NO_LOG,
        SUBPROCESS_SHELL_TRUE,
        SELF_ASSIGNMENT,
        REDEFINE_IN_LOOP,
        EXCEPTION_LOST_CONTEXT,
        INFINITE_RECURSION_RISK,
        INFINITE_LOOP_RISK,
        MISSING_SUPER_INIT,
        IDENTIFIER_TYPO,
        BOOL_PREFIX_NO_BOOL_RETURN,
        GETTER_HAS_SIDE_EFFECT,
        SETTER_RETURNS_VALUE,
        ASYNC_VOID,
        STUB_IN_PROD,
        PYTHON_LOCK_NO_RELEASE,
        HTTP_NO_STATUS_CHECK,
        DICT_ITERATE_MUTATE,
        DUPLICATE_DICT_KEY,
        JAVA_STRING_EQ_OPERATOR,
        FOREACH_COLLECTION_MUTATE,
        GO_RANGE_LOOP_VAR_ADDR,
        GO_CHANNEL_SEND_AFTER_CLOSE,
        CPP_USE_AFTER_FREE,
        CPP_DOUBLE_FREE,
        CPP_DELETE_MISMATCH,
        JAVA_HASHCODE_EQUALS_MISMATCH,
        JAVA_EQUALS_ON_ARRAY,
        JAVA_INTEGER_BOXING_EQ,
        GO_NIL_MAP_WRITE,
        MONEY_FLOAT_PRECISION,
        BIGDECIMAL_DOUBLE_CTOR,
        EXECUTOR_NOT_SHUTDOWN,
        STATIC_SIMPLEDATEFORMAT,
        MISSING_CHARSET,
        MISSING_TIMEZONE,
        SWITCH_NO_DEFAULT,
    ),
)

REGEX_RULES: list[tuple[RuleSpec, re.Pattern[str]]] = [
    (
        DEAD_CODE,
        re.compile(_DEAD_CODE_MARKERS_RE + r".*" + _DEAD_CODE_ACTIONS_RE, re.IGNORECASE),
    ),

    (
        EMPTY_EXCEPT,
        re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}", re.IGNORECASE),
    ),
    (
        PRINT_DEBUG,
        re.compile(
            r"(?<![\w.])print\s*\(|console\.(?:log|debug)\s*\(|System\.(?:out|err)\.println\s*\(|fmt\.(?:Print|Printf|Println|Fprint|Fprintf|Fprintln)\s*\(|(?:std::)?cout\s*<<|\bprintf\s*\(|Console(?:\.Error)?\.(?:Write|WriteLine)\s*\(|Debug\.(?:WriteLine|Print)\s*\(|println!\s*\(|dbg!\s*\(",

            re.IGNORECASE,
        ),
    ),
    (
        ASSERT_USED,
        re.compile(r"\bassert\s*(?:\(|!)|\bDebug\.Assert\s*\(", re.IGNORECASE),
    ),
    (
        BROAD_EXCEPT,
        re.compile(
            r"except\s+(?:Exception|BaseException|Error)\s*:|catch\s*\(\s*(?:Exception|Throwable|System\.Exception)\b",
            re.IGNORECASE,
        ),
    ),
    (
        BARE_EXCEPT,
        re.compile(r"except\s*:\s*$|catch\s*\(\s*\.\.\.\s*\)", re.IGNORECASE),
    ),
    # STUB-IN-PROD: 占位实现/未实现的功能进入了生产路径
    # 仅匹配那些明确表达"未实现"的语句模式，避免和正常的异常抛出混淆
    (
        STUB_IN_PROD,
        re.compile(
            r"\braise\s+NotImplementedError\b"                       # Python: raise NotImplementedError(...)
            r"|\bthrow\s+new\s+NotImplementedException\b"            # C#/Java: throw new NotImplementedException(...)
            r"|\bthrow\s+new\s+UnsupportedOperationException\b"      # Java: throw new UnsupportedOperationException(...)
            r"|\bpanic\s*\(\s*[\"`'](?:TODO|FIXME|not\s*implemented|unimplemented)" # Go: panic("TODO ...") / panic("not implemented ...")
            r"|\btodo!\s*\("                                          # Rust: todo!() / todo!("...")
            r"|\bunimplemented!\s*\("                                 # Rust: unimplemented!()
            r"|\bthrow\s+new\s+Error\s*\(\s*[\"`'](?:TODO|FIXME|not\s*implemented|unimplemented)",  # JS/TS: throw new Error("TODO ...")
            re.IGNORECASE,
        ),
    ),
    # MONEY-FLOAT-PRECISION: 金额字段使用 float/double 存储
    # 匹配字段/变量名包含金额语义（amount/price/balance/money/total/fee/cost/salary/payment）
    # 且类型为浮点（double/float/Float/Double/number）。
    (
        MONEY_FLOAT_PRECISION,
        re.compile(
            # Java/C#: private double amount;  /  public Double price = 0.0;
            r"\b(?:double|float|Double|Float)\s+\w*(?:amount|price|balance|money|total|fee|cost|salary|payment|wage|bonus|tax|refund)\w*\s*[=;,)]"
            # Java/C# 反向：字段名在前，类型在前——同样用上面那条覆盖；这里再覆盖泛型/字段声明
            r"|\b\w*(?:amount|price|balance|money|total|fee|cost|salary|payment|wage|bonus|tax|refund)\w*\s*:\s*(?:number|float|Float|double|Double)\b"  # TS: amount: number
            # Python: amount: float = 0.0  / price: float
            r"|\b\w*(?:amount|price|balance|money|total|fee|cost|salary|payment|wage|bonus|tax|refund)\w*\s*:\s*float\b"
            # Go: var amount float64
            r"|\bvar\s+\w*(?:amount|price|balance|money|total|fee|cost|salary|payment|wage|bonus|tax|refund)\w*\s+float(?:32|64)\b"
            r"|\b\w*(?:amount|price|balance|money|total|fee|cost|salary|payment|wage|bonus|tax|refund)\w*\s+float(?:32|64)\b",
            re.IGNORECASE,
        ),
    ),
    # BIGDECIMAL-DOUBLE-CTOR: new BigDecimal(<浮点字面量或 double 变量>)
    # 字符串字面量构造是安全的，应排除：new BigDecimal("0.1")
    (
        BIGDECIMAL_DOUBLE_CTOR,
        re.compile(
            r"\bnew\s+BigDecimal\s*\(\s*(?!\")"      # 必须不是字符串字面量
            r"(?:[+-]?\d+\.\d+(?:[eE][+-]?\d+)?[dDfF]?"   # 浮点字面量：0.1 / 1.5e-3 / 0.1d
            r"|\d+[dDfF]"                                  # 整数+d/f 后缀：1d / 5f
            r")\s*\)",
            re.IGNORECASE,
        ),
    ),
    # STATIC-SIMPLEDATEFORMAT: 共享的 SimpleDateFormat 实例（线程不安全）。
    # 同时覆盖几种修饰符顺序：
    #   private static final SimpleDateFormat SDF = ...
    #   static SimpleDateFormat sdf;
    #   public static final SimpleDateFormat SDF = new SimpleDateFormat(...)
    # 不命中：方法内局部变量（前面没有 static 修饰）。
    (
        STATIC_SIMPLEDATEFORMAT,
        re.compile(
            r"\b(?:public\s+|private\s+|protected\s+)?static\s+(?:final\s+)?(?:public\s+|private\s+|protected\s+)?SimpleDateFormat\b",
        ),
    ),
    # MISSING-CHARSET: 字符串/IO 操作未指定 charset。
    # 命中模式：
    #   new String(<bytes 表达式>)        — 形参表中没有逗号，即只有一个参数
    #   <bytes>.getBytes()                — 显式无参调用
    #   new FileReader( ... )             — 仅一个参数（文件名/File 对象），无 charset
    #   new FileWriter( ... )             — 同上
    #   new InputStreamReader(<stream>)   — 仅一个参数
    #   new OutputStreamWriter(<stream>)  — 仅一个参数
    # 用 `[^,()]*` 限制括号内不出现逗号即认为只有一个参数。
    (
        MISSING_CHARSET,
        re.compile(
            r"\bnew\s+String\s*\([^,()]+\)"
            r"|\.getBytes\s*\(\s*\)"
            r"|\bnew\s+FileReader\s*\([^,()]+\)"
            r"|\bnew\s+FileWriter\s*\((?:[^,()]+|[^,()]+,\s*(?:true|false))\)"  # FileWriter 第二参可能是 append 布尔
            r"|\bnew\s+InputStreamReader\s*\([^,()]+\)"
            r"|\bnew\s+OutputStreamWriter\s*\([^,()]+\)",
        ),
    ),
]


@lru_cache(maxsize=128)
def _go_module_version(project_root: Path) -> tuple[int, int] | None:
    """Parse `go X.Y` directive from <project_root>/go.mod.

    Returns (major, minor) on success, or None when go.mod is missing or
    unparseable. Cached per project_root to avoid re-reading on every file.
    """
    try:
        go_mod = project_root / "go.mod"
        if not go_mod.is_file():
            return None
        text = go_mod.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    # Match a top-level `go 1.22` or `go 1.22.3` directive (skip lines inside blocks).
    m = re.search(r"^\s*go\s+(\d+)\.(\d+)(?:\.\d+)?\s*$", text, re.MULTILINE)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _go_module_version_at_least(project_root: Path, minimum: tuple[int, int]) -> bool:
    """True iff go.mod declares a Go language version >= `minimum`."""
    version = _go_module_version(project_root)
    if version is None:
        return False
    return version >= minimum


class DefectEngine:
    """Detect code defects using AST-enhanced rules."""

    name = "defect"

    # Rule IDs that should be suppressed in test files (these are expected patterns in tests)
    _TEST_SUPPRESSED_RULES = frozenset({
        "PRINT-DEBUG", "ASSERT-USED", "DEAD-CODE",
    })
    @staticmethod
    def _is_test_file(rel_path: str) -> bool:
        """Heuristic: detect if a file is a test file (delegates to shared helper)."""
        return is_test_file_path(rel_path)

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
            hits = self._scan_regex(lines, rel_path, language)
            hits.extend(self._scan_ast(src_file, root, rel_path, content, language))
            hits.extend(self._scan_executor_not_shutdown(content, lines, rel_path, language))
            hits.extend(self._scan_missing_timezone(content, lines, rel_path, language))
            hits = filter_rule_hits(hits, ctx.config.rules)

            # Suppress noisy rules in test files
            is_test = is_test_file_path(rel_path)
            seen: set[tuple[str, str, int, int]] = set()
            for hit in hits:
                if is_test and hit.rule.rule_id in self._TEST_SUPPRESSED_RULES:
                    continue
                if is_suppressed_by_inline_comment(hit.rule.rule_id, lines, hit.line_start):
                    continue
                key = (hit.rule.rule_id, hit.file_path, hit.line_start, hit.line_end)
                if key in seen:
                    continue
                seen.add(key)
                counter += 1
                findings.append(build_finding(hit, lines, f"DEF-{counter:03d}", self.name, context_radius=1))

        return EngineResult(engine_name=self.name, findings=findings)

    # File-level pattern: ExecutorService/线程池在文件中创建但全文件无 shutdown 调用。
    # 用文件级而不是行级扫描，是为了规避"声明在 A 函数、shutdown 在 B 函数"的常见安全用法。
    # 仅 Java：Python concurrent.futures 用 with 上下文管理器较普遍，C# 有 IDisposable 兜底。
    _EXECUTOR_CREATE_RE = re.compile(
        r"\bExecutors\.new(?:Fixed|Cached|Single|Scheduled|WorkStealing)\w*\s*\("
        r"|\bnew\s+ThreadPoolExecutor\s*\("
        r"|\bnew\s+ScheduledThreadPoolExecutor\s*\("
        r"|\bnew\s+ForkJoinPool\s*\("
    )
    _EXECUTOR_SHUTDOWN_RE = re.compile(
        r"\.shutdown(?:Now)?\s*\("
        r"|\.awaitTermination\s*\("
        r"|\bExecutorService\.close\s*\("
    )

    @classmethod
    def _scan_executor_not_shutdown(
        cls, content: str, lines: list[str], rel_path: str, language: str,
    ) -> list[RuleHit]:
        if language != "java":
            return []
        if cls._EXECUTOR_SHUTDOWN_RE.search(content):
            return []
        hits: list[RuleHit] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            if cls._EXECUTOR_CREATE_RE.search(line):
                hits.append(
                    RuleHit(
                        rule=EXECUTOR_NOT_SHUTDOWN,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        language=language,
                        message="线程池在本文件创建后未发现 shutdown()/shutdownNow()/awaitTermination 调用。",
                    )
                )
        return hits

    # File-level pattern: SimpleDateFormat 创建后是否调用 setTimeZone。
    # 与 EXECUTOR-NOT-SHUTDOWN 同样的扫描思路：先看全文件有没有 setTimeZone /
    # withZone，再列出所有 new SimpleDateFormat(...) 创建点。
    _SDF_CREATE_RE = re.compile(r"\bnew\s+SimpleDateFormat\s*\(")
    _TIMEZONE_SETTER_RE = re.compile(
        r"\.setTimeZone\s*\("                          # df.setTimeZone(...)
        r"|\.withZone\s*\("                            # DateTimeFormatter.withZone(...)
        r"|TimeZone\.setDefault\s*\("                  # 显式改默认时区也算用户已意识到
    )

    @classmethod
    def _scan_missing_timezone(
        cls, content: str, lines: list[str], rel_path: str, language: str,
    ) -> list[RuleHit]:
        if language != "java":
            return []
        if cls._TIMEZONE_SETTER_RE.search(content):
            return []
        hits: list[RuleHit] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            if cls._SDF_CREATE_RE.search(line):
                hits.append(
                    RuleHit(
                        rule=MISSING_TIMEZONE,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        language=language,
                        message="SimpleDateFormat 创建后本文件未发现 setTimeZone 调用，将使用 JVM 默认时区。",
                    )
                )
        return hits

    # AST-based: Java switch 语句缺少 default 分支。
    # 使用项目内已有的 _walk_nodes 工具遍历，找 switch_expression 节点
    # （tree-sitter-java 把 switch 语句和表达式都归为 switch_expression）。
    # 判断 default 的方法：在子树文本里找独立 token "default"，覆盖
    #   - 经典：case A: ... default: ...
    #   - 箭头：case A -> ...; default -> ...;
    @classmethod
    def _scan_switch_no_default_java(
        cls, document: TreeSitterDocument, language: str,
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []
        # 复用类自身的 _walk_nodes
        for node in cls._walk_nodes(document.root_node):
            if node.type not in {"switch_expression", "switch_statement"}:
                continue
            # 找 switch 体内是否包含 default 关键字 token
            has_default = False
            for descendant in cls._walk_nodes(node):
                # tree-sitter-java 中 default 关键字本身节点 type 通常是 "default"，
                # 但也可能出现在 switch_label 的文本里；用类型 + 文本两路兜底。
                if descendant.type == "default":
                    has_default = True
                    break
                if descendant.type in {"switch_label", "switch_rule"}:
                    text = document.text_for(descendant)
                    if re.search(r"\bdefault\b", text):
                        has_default = True
                        break
            if has_default:
                continue
            line_start, line_end = document.line_range(node)
            hits.append(
                RuleHit(
                    rule=SWITCH_NO_DEFAULT,
                    file_path=document.relative_path,
                    line_start=line_start,
                    line_end=line_start,  # 仅标记起始行，避免高亮整段 switch
                    language=language,
                    message=f"switch 块 (L{line_start}-{line_end}) 缺少 default 分支。",
                )
            )
        return hits





    def _scan_ast(
        self,
        src_file: Path,
        root: Path,
        rel_path: str,
        content: str,
        language: str,
    ) -> list[RuleHit]:
        if language == "python":
            return self._scan_python_ast(content, rel_path, language)
        if language not in {"java", "javascript", "typescript", "cpp", "go", "lua", "csharp"}:
            return []

        document = get_tree_sitter_document(src_file, root, language)
        if document is None:
            return []

        hits = self._scan_tree_syntax_errors(document, language)
        if language == "java":
            hits.extend(self._scan_java_tree(document, language))
            return hits
        if language in {"javascript", "typescript"}:
            hits.extend(self._scan_javascript_tree(document, language))
            return hits
        if language == "cpp":
            hits.extend(self._scan_cpp_tree(document, language))
            return hits
        if language == "go":
            hits.extend(self._scan_go_tree(document, language))
            return hits
        if language == "lua":
            hits.extend(self._scan_lua_tree(document, language))
            return hits
        if language == "csharp":
            hits.extend(self._scan_csharp_tree(document, language))
            return hits
        return hits

    # Rules that tree-sitter AST analysis already handles for non-Python languages.
    # Regex fallback is only needed for languages without tree-sitter support.
    _AST_COVERED_RULES = frozenset({
        "EMPTY-EXCEPT", "PRINT-DEBUG", "ASSERT-USED", "BROAD-EXCEPT", "BARE-EXCEPT",
    })
    # Languages with tree-sitter deep detection that covers the above rules
    _AST_LANGUAGES = frozenset({"java", "javascript", "typescript", "cpp", "go", "lua", "csharp"})

    # Comment line prefixes by language group (after stripping whitespace)
    _COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
        "python": ("#",),
        "java": ("//", "*", "/*"),
        "javascript": ("//", "*", "/*"),
        "typescript": ("//", "*", "/*"),
        "cpp": ("//", "*", "/*"),
        "go": ("//", "*", "/*"),
        "lua": ("--",),
        "csharp": ("//", "*", "/*"),
        "rust": ("//", "*", "/*"),
    }

    @staticmethod
    def _scan_regex(lines: list[str], rel_path: str, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        # For languages with tree-sitter AST analysis, skip rules already covered by AST
        skip_rule_ids = DefectEngine._AST_COVERED_RULES if language in DefectEngine._AST_LANGUAGES else frozenset()
        comment_prefixes = DefectEngine._COMMENT_PREFIXES.get(language, ("#", "//"))
        for line_no, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            is_comment = bool(stripped) and any(stripped.startswith(p) for p in comment_prefixes)
            for rule, pattern in REGEX_RULES:
                if rule.rule_id in skip_rule_ids:
                    continue
                # Skip comment lines for most rules, but DEAD-CODE intentionally matches
                # comment markers (TODO/FIXME/HACK), so it should still scan comments
                if is_comment and rule.rule_id != "DEAD-CODE":
                    continue
                if pattern.search(line):
                    hits.append(
                        RuleHit(
                            rule=rule,
                            file_path=rel_path,
                            line_start=line_no,
                            line_end=line_no,
                            language=language,
                        )
                    )
        return hits

    def _scan_python_ast(self, content: str, rel_path: str, language: str) -> list[RuleHit]:
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            line_no = exc.lineno or 1
            return [
                RuleHit(
                    SYNTAX_ERROR,
                    rel_path,
                    line_no,
                    line_no,
                    language=language,
                    message=f"Python parser failed: {exc.msg}",
                )
            ]

        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                line_no = node.lineno
                if node.type is None:
                    hits.append(RuleHit(BARE_EXCEPT, rel_path, line_no, line_no, language=language))
                elif self._python_exception_name(node.type) in {"Exception", "BaseException", "Error"}:
                    hits.append(RuleHit(BROAD_EXCEPT, rel_path, line_no, line_no, language=language))
                if self._python_except_is_empty(node):
                    hits.append(RuleHit(EMPTY_EXCEPT, rel_path, line_no, line_no, language=language))
                elif self._python_except_only_logs(node):
                    hits.append(
                        RuleHit(
                            LOG_ONLY_EXCEPT,
                            rel_path,
                            line_no,
                            getattr(node, "end_lineno", line_no),
                            language=language,
                            message="Exception handler only logs the failure and then suppresses it.",
                        )
                    )
            elif isinstance(node, ast.Call):
                call_name = self._python_call_name(node.func)
                if call_name == "print":
                    hits.append(RuleHit(PRINT_DEBUG, rel_path, node.lineno, node.lineno, language=language))
            elif isinstance(node, ast.Assert):
                hits.append(RuleHit(ASSERT_USED, rel_path, node.lineno, node.lineno, language=language))
        hits.extend(self._scan_python_resource_leaks(tree, rel_path, language))
        hits.extend(self._scan_python_unreachable_code(tree, rel_path, language))
        hits.extend(self._scan_python_always_true_false(tree, rel_path, language))
        hits.extend(self._scan_python_unused_variables(tree, rel_path, language))
        hits.extend(self._scan_python_possible_none_deref(tree, rel_path, language))
        hits.extend(self._scan_python_division_by_zero(tree, rel_path, language))
        hits.extend(self._scan_python_index_out_of_bounds(tree, rel_path, language))
        hits.extend(self._scan_python_swallowed_exception_flow(tree, rel_path, language))
        hits.extend(self._scan_python_resource_close_not_guaranteed(tree, rel_path, language))
        hits.extend(self._scan_python_exception_not_raised(tree, rel_path, language))

        hits.extend(self._scan_python_mutable_default_arg(tree, rel_path, language))
        hits.extend(self._scan_python_exception_swallowed_no_log(tree, rel_path, language))
        hits.extend(self._scan_python_subprocess_shell_true(tree, rel_path, language))
        hits.extend(self._scan_python_self_assignment(tree, rel_path, language))
        hits.extend(self._scan_python_redefine_in_loop(tree, rel_path, language))
        hits.extend(self._scan_python_exception_lost_context(tree, rel_path, language))
        hits.extend(self._scan_python_infinite_recursion(tree, rel_path, language))
        hits.extend(self._scan_python_infinite_loop(tree, rel_path, language))
        hits.extend(self._scan_python_missing_super_init(tree, rel_path, language))
        hits.extend(self._scan_python_identifier_typo(tree, rel_path, language))
        hits.extend(self._scan_python_bool_prefix_no_bool_return(tree, rel_path, language))
        hits.extend(self._scan_python_getter_side_effect(tree, rel_path, language))
        hits.extend(self._scan_python_setter_returns_value(tree, rel_path, language))
        hits.extend(self._scan_python_lock_no_release(tree, rel_path, language))
        hits.extend(self._scan_python_http_no_status_check(tree, rel_path, language))
        hits.extend(self._scan_python_dict_iterate_mutate(tree, rel_path, language))
        hits.extend(self._scan_python_duplicate_dict_key(tree, rel_path, language))
        return hits

    def _scan_python_resource_leaks(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        hits = self._scan_python_resource_scope(tree.body, rel_path, language, "<module>")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                hits.extend(self._scan_python_resource_scope(node.body, rel_path, language, node.name))
        return hits

    def _scan_python_resource_scope(
        self,
        body: list[ast.stmt],
        rel_path: str,
        language: str,
        scope_name: str,
    ) -> list[RuleHit]:
        collector = _PythonResourceScopeCollector()
        collector.collect(body)
        hits: list[RuleHit] = []

        for resource_name, line_no, factory_name in collector.acquisitions:
            next_reassign = self._first_event_after(collector.reassignments.get(resource_name, []), line_no + 1, None)
            close_line = self._first_event_after(collector.closes.get(resource_name, []), line_no, next_reassign)
            transfer_line = self._first_event_after(collector.transfers.get(resource_name, []), line_no, next_reassign)
            if close_line is not None or transfer_line is not None:
                continue
            scope_label = "module scope" if scope_name == "<module>" else f"scope `{scope_name}`"
            hits.append(
                RuleHit(
                    RESOURCE_LEAK,
                    rel_path,
                    line_no,
                    line_no,
                    language=language,
                    message=f"Resource `{resource_name}` created via `{factory_name}` is not closed before leaving {scope_label}.",
                    metadata={
                        "resource_name": resource_name,
                        "resource_factory": factory_name,
                        "scope": scope_name,
                        "inspired_by": "infer-resource-leak",
                    },
                )
            )
        return hits

    # ── Unreachable code detection ───────────────────────────────────────
    _TERMINATOR_TYPES = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def _scan_python_unreachable_code(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Find statements that follow return/raise/break/continue in the same block."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            body: list[ast.stmt] | None = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.AsyncWith)):
                body = node.body
            elif isinstance(node, ast.ExceptHandler):
                body = node.body
            if body is None:
                continue
            self._check_block_for_unreachable(body, rel_path, language, hits)
            # Also check orelse blocks for If/For/While
            orelse = getattr(node, "orelse", None)
            if orelse:
                self._check_block_for_unreachable(orelse, rel_path, language, hits)
        return hits

    def _check_block_for_unreachable(
        self,
        stmts: list[ast.stmt],
        rel_path: str,
        language: str,
        hits: list[RuleHit],
    ) -> None:
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, self._TERMINATOR_TYPES) and i + 1 < len(stmts):
                next_stmt = stmts[i + 1]
                # Skip docstrings or type: ignore comments after raise in __init__
                if isinstance(next_stmt, ast.Expr) and isinstance(next_stmt.value, ast.Constant) and isinstance(next_stmt.value.value, str):
                    continue
                hits.append(
                    RuleHit(
                        UNREACHABLE_CODE,
                        rel_path,
                        next_stmt.lineno,
                        getattr(next_stmt, "end_lineno", next_stmt.lineno),
                        language=language,
                        message=f"This code is unreachable — preceded by `{type(stmt).__name__.lower()}` on line {stmt.lineno}.",
                    )
                )
                break  # Only report first unreachable in each block

    # ── Always-true / always-false condition detection ───────────────────
    def _scan_python_always_true_false(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect if/while conditions that are compile-time constant True/False."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                truth = self._constant_truth_value(node.test)
                if truth is not None:
                    val_str = "always true" if truth else "always false"
                    hits.append(
                        RuleHit(
                            ALWAYS_TRUE_FALSE,
                            rel_path,
                            node.lineno,
                            node.lineno,
                            language=language,
                            message=f"Condition is {val_str}: `{ast.dump(node.test)}`.",
                        )
                    )
            elif isinstance(node, ast.While):
                truth = self._constant_truth_value(node.test)
                # while True is idiomatic — skip it; but while False is suspicious
                if truth is False:
                    hits.append(
                        RuleHit(
                            ALWAYS_TRUE_FALSE,
                            rel_path,
                            node.lineno,
                            node.lineno,
                            language=language,
                            message="While-loop condition is always false — the loop body will never execute.",
                        )
                    )
        return hits

    @staticmethod
    def _constant_truth_value(node: ast.expr) -> bool | None:
        """Return True/False if node is a compile-time constant, else None."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        # Name references True/False/None
        if isinstance(node, ast.Name):
            if node.id == "True":
                return True
            if node.id in ("False", "None"):
                return False
        return None

    # ── Unused variable detection ────────────────────────────────────────
    def _scan_python_unused_variables(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect local variables assigned but never read within the same function."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            hits.extend(self._check_function_unused_vars(node, rel_path, language))
        return hits

    def _check_function_unused_vars(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_path: str,
        language: str,
    ) -> list[RuleHit]:
        """Check a single function for unused local variables."""
        # Collect all assigned names (excluding _ prefixed conventionally unused names)
        assigned: dict[str, int] = {}  # name -> first assignment line
        read_names: set[str] = set()

        # Names from parameters should not be flagged
        param_names = {arg.arg for arg in func_node.args.args}
        param_names |= {arg.arg for arg in func_node.args.posonlyargs}
        param_names |= {arg.arg for arg in func_node.args.kwonlyargs}
        if func_node.args.vararg:
            param_names.add(func_node.args.vararg.arg)
        if func_node.args.kwarg:
            param_names.add(func_node.args.kwarg.arg)

        for child in ast.walk(func_node):
            # Track assignments
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    for name in self._python_assignment_names(target):
                        if name not in param_names and not name.startswith("_"):
                            assigned.setdefault(name, child.lineno)
            elif isinstance(child, ast.AnnAssign) and child.value is not None:
                for name in self._python_assignment_names(child.target):
                    if name not in param_names and not name.startswith("_"):
                        assigned.setdefault(name, child.lineno)
            # Track reads — any Name in Load context
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                read_names.add(child.id)

        hits: list[RuleHit] = []
        for name, line_no in assigned.items():
            if name not in read_names:
                hits.append(
                    RuleHit(
                        UNUSED_VARIABLE,
                        rel_path,
                        line_no,
                        line_no,
                        language=language,
                        message=f"Variable `{name}` is assigned but never used in this function.",
                    )
                )
        return hits

    # ── Possible None dereference detection ──────────────────────────────
    # Pattern: x = something.get(...) followed by x.attr or x[...] without None check
    _NONE_RETURNING_METHODS = {"get", "pop", "find", "rfind"}

    def _scan_python_possible_none_deref(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect .get()/.find() results used directly for attribute access without None guard."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            hits.extend(self._check_function_none_deref(node, rel_path, language))
        return hits

    def _check_function_none_deref(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_path: str,
        language: str,
    ) -> list[RuleHit]:
        # Collect variables assigned from .get()/.find()/.pop()
        maybe_none_vars: dict[str, int] = {}  # name -> assignment line
        guarded_names: set[str] = set()

        for child in ast.walk(func_node):
            # Track assignments like: x = d.get("key")
            if isinstance(child, ast.Assign) and len(child.targets) == 1:
                target = child.targets[0]
                if isinstance(target, ast.Name) and isinstance(child.value, ast.Call):
                    if isinstance(child.value.func, ast.Attribute) and child.value.func.attr in self._NONE_RETURNING_METHODS:
                        # `.get(key, default)` / `.get(key, default=...)` never returns None.
                        if child.value.func.attr == "get" and (len(child.value.args) >= 2 or child.value.keywords):
                            continue
                        maybe_none_vars[target.id] = child.lineno

            # Track None guards: `if x is not None`, `if x:`, `if x is None`
            if isinstance(child, ast.If):
                guarded_names.update(self._extract_none_checked_names(child.test))
            # Ternary guard: `x.attr if x else default` — an expression-level guard
            # (ast.IfExp), distinct from statement-level `if` above.
            if isinstance(child, ast.IfExp):
                guarded_names.update(self._extract_none_checked_names(child.test))

        # Now find dereferences of maybe_none_vars without guards
        hits: list[RuleHit] = []
        for child in ast.walk(func_node):
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                name = child.value.id
                if name in maybe_none_vars and name not in guarded_names:
                    hits.append(
                        RuleHit(
                            POSSIBLE_NONE_DEREF,
                            rel_path,
                            child.value.lineno,
                            child.value.lineno,
                            language=language,
                            message=f"`{name}` may be None (assigned via `.get()`/`.find()` on line {maybe_none_vars[name]}) but is accessed without a None check.",
                        )
                    )
                    guarded_names.add(name)  # report only once per variable
            elif isinstance(child, ast.Subscript) and isinstance(child.value, ast.Name):
                name = child.value.id
                if name in maybe_none_vars and name not in guarded_names:
                    hits.append(
                        RuleHit(
                            POSSIBLE_NONE_DEREF,
                            rel_path,
                            child.value.lineno,
                            child.value.lineno,
                            language=language,
                            message=f"`{name}` may be None (assigned via `.get()`/`.find()` on line {maybe_none_vars[name]}) but is subscripted without a None check.",
                        )
                    )
                    guarded_names.add(name)
        return hits

    @staticmethod
    def _extract_none_checked_names(test_node: ast.expr) -> set[str]:
        """Extract variable names checked against None in an if-test."""
        names: set[str] = set()
        # `if x is None` / `if x is not None`
        if isinstance(test_node, ast.Compare):
            if isinstance(test_node.left, ast.Name):
                for op, comp in zip(test_node.ops, test_node.comparators):
                    if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(comp, ast.Constant) and comp.value is None:
                        names.add(test_node.left.id)
        # `if x:` / `if not x:`
        if isinstance(test_node, ast.Name):
            names.add(test_node.id)
        if isinstance(test_node, ast.UnaryOp) and isinstance(test_node.op, ast.Not) and isinstance(test_node.operand, ast.Name):
            names.add(test_node.operand.id)
        # `if x and y` / `if x or y`
        if isinstance(test_node, ast.BoolOp):
            for val in test_node.values:
                names.update(DefectEngine._extract_none_checked_names(val))
        return names

    def _scan_python_division_by_zero(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                continue
            if isinstance(node.right, ast.Constant) and node.right.value in {0, 0.0}:
                hits.append(RuleHit(
                    DIVISION_BY_ZERO_RISK, rel_path,
                    node.lineno, getattr(node, "end_lineno", node.lineno), language=language,
                    message="Division or modulo uses literal zero as denominator.",
                ))
        return hits

    def _scan_python_index_out_of_bounds(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
                continue
            index_name = node.target.id
            seq_name = self._python_range_len_plus_one_sequence(node.iter)
            if not seq_name:
                continue
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(child, ast.Subscript) and isinstance(child.value, ast.Name) and child.value.id == seq_name:
                    if isinstance(child.slice, ast.Name) and child.slice.id == index_name:
                        hits.append(RuleHit(
                            COLLECTION_INDEX_OUT_OF_BOUNDS, rel_path,
                            node.lineno, getattr(node, "end_lineno", node.lineno), language=language,
                            message=f"Loop iterates over `range(len({seq_name}) + 1)` and indexes `{seq_name}[{index_name}]`; last iteration is out of bounds.",
                        ))
                        break
        return hits

    def _scan_python_swallowed_exception_flow(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or any(isinstance(child, ast.Raise) for child in ast.walk(node)):
                continue
            has_log = any(
                isinstance(child, ast.Call) and self._python_call_name(child.func).lower().split(".")[-1] in {"error", "exception", "warning", "warn", "print"}
                for child in ast.walk(node)
            )
            has_default_flow = any(
                isinstance(child, (ast.Continue, ast.Break))
                or (isinstance(child, ast.Return) and self._python_is_default_return(child.value))
                for child in ast.walk(node)
            )
            if has_log and has_default_flow:
                hits.append(RuleHit(
                    SWALLOWED_EXCEPTION_FLOW, rel_path,
                    node.lineno, getattr(node, "end_lineno", node.lineno), language=language,
                    message="Exception handler logs the failure then returns a default value or continues control flow without propagating it.",
                ))
        return hits

    def _scan_python_resource_close_not_guaranteed(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for scope in [tree, *(node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))]:
            body = getattr(scope, "body", [])
            scope_text_nodes = list(ast.walk(ast.Module(body=body, type_ignores=[])))
            if any(isinstance(node, ast.With) for node in scope_text_nodes):
                continue
            if any(isinstance(node, ast.Try) and node.finalbody for node in scope_text_nodes):
                continue
            acquired: dict[str, int] = {}
            closed: set[str] = set()
            for child in scope_text_nodes:
                if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                    call_name = self._python_call_name(child.value.func)
                    if call_name in _PYTHON_RESOURCE_FACTORY_CALLS:
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                acquired[target.id] = child.lineno
                if isinstance(child, ast.Call):
                    close_name = self._python_resource_close_name(child)
                    if close_name:
                        closed.add(close_name)
            for name, line_no in acquired.items():
                if name in closed:
                    hits.append(RuleHit(
                        RESOURCE_CLOSE_NOT_GUARANTEED, rel_path,
                        line_no, line_no, language=language,
                        message=f"Resource `{name}` is closed manually, but not via `with` or `finally`; close may be skipped on exceptions.",
                    ))
        return hits

    @staticmethod
    def _python_range_len_plus_one_sequence(iter_node: ast.expr) -> str:
        if not isinstance(iter_node, ast.Call) or DefectEngine._python_call_name(iter_node.func) != "range":
            return ""
        if not iter_node.args:
            return ""
        arg = iter_node.args[0]
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            left, right = arg.left, arg.right
            if isinstance(right, ast.Constant) and right.value == 1:
                return DefectEngine._python_len_arg_name(left)
        return ""

    @staticmethod
    def _python_len_arg_name(node: ast.expr) -> str:
        if isinstance(node, ast.Call) and DefectEngine._python_call_name(node.func) == "len" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name):
                return first_arg.id
        return ""

    @staticmethod
    def _python_is_default_return(value: ast.expr | None) -> bool:
        return value is None or (isinstance(value, ast.Constant) and value.value in {None, False, True, 0, ""})

    # ── Exception created but not raised ───────────────────────────────
    _BUILTIN_EXCEPTION_NAMES = {

        "Exception", "BaseException", "ValueError", "TypeError", "KeyError",
        "IndexError", "AttributeError", "RuntimeError", "NotImplementedError",
        "IOError", "OSError", "FileNotFoundError", "PermissionError",
        "StopIteration", "StopAsyncIteration", "ArithmeticError",
        "ZeroDivisionError", "OverflowError", "FloatingPointError",
        "LookupError", "AssertionError", "ImportError", "ModuleNotFoundError",
        "NameError", "UnboundLocalError", "SyntaxError", "IndentationError",
        "SystemError", "UnicodeError", "UnicodeDecodeError", "UnicodeEncodeError",
        "ConnectionError", "ConnectionResetError", "ConnectionAbortedError",
        "TimeoutError", "BrokenPipeError", "ChildProcessError",
        "ProcessLookupError", "BufferError", "MemoryError", "RecursionError",
    }

    def _scan_python_exception_not_raised(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect exception objects created as bare expressions without 'raise'."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Expr):
                continue
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            call_name = self._python_call_name(call.func)
            # Check if calling a known exception constructor
            base_name = call_name.rsplit(".", 1)[-1] if "." in call_name else call_name
            if base_name in self._BUILTIN_EXCEPTION_NAMES or base_name.endswith("Error") or base_name.endswith("Exception"):
                hits.append(
                    RuleHit(
                        EXCEPTION_NOT_RAISED,
                        rel_path,
                        node.lineno,
                        getattr(node, "end_lineno", node.lineno),
                        language=language,
                        message=f"`{call_name}(...)` creates an exception but does not raise it — add `raise` before it.",
                    )
                )
        return hits

    # ── Mutable default argument ─────────────────────────────────────────
    def _scan_python_mutable_default_arg(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect mutable default arguments like def f(x=[], y={})."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    hits.append(
                        RuleHit(
                            MUTABLE_DEFAULT_ARG,
                            rel_path,
                            default.lineno,
                            getattr(default, "end_lineno", default.lineno),
                            language=language,
                            message=f"Mutable default `{type(default).__name__}` is shared between all calls — use `None` and create inside body.",
                        )
                    )
                elif isinstance(default, ast.Call):
                    call_name = self._python_call_name(default.func)
                    if call_name in ("list", "dict", "set"):
                        # list(), dict(), set() as defaults — also mutable, but less common mistake.
                        # Skip to reduce noise since these are more intentional.
                        pass
        return hits

    # ── Exception swallowed without log ──────────────────────────────────
    def _scan_python_exception_swallowed_no_log(
        self, tree: ast.Module, rel_path: str, language: str,
    ) -> list[RuleHit]:
        """Detect except blocks that suppress the exception with neither
        a log nor a re-raise.

        Coverage gap this rule fills:
          - EMPTY-EXCEPT covers strict ``except: pass`` / ``...``
          - LOG-ONLY-EXCEPT covers handlers that only log
          - SWALLOWED-EXCEPTION-FLOW requires ``has_log AND default_flow``
        Cases like ``except: x = 0`` / ``except: return None`` (no log,
        no raise, body isn't strictly empty) currently fall through. This
        rule reports them at LOW severity since they are observability
        smells rather than guaranteed bugs.
        """
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            # Skip empty bodies — already handled by EMPTY-EXCEPT.
            if self._python_except_is_empty(node):
                continue
            # Walk the body looking for raise / log / non-trivial work.
            has_raise = False
            has_log = False
            for child in ast.walk(node):
                # Don't count the ExceptHandler node itself.
                if child is node:
                    continue
                if isinstance(child, ast.Raise):
                    has_raise = True
                    break
                if isinstance(child, ast.Call) and self._python_expr_is_log_call(child):
                    has_log = True
                    break
            if has_raise or has_log:
                continue
            hits.append(
                RuleHit(
                    EXCEPTION_SWALLOWED_NO_LOG,
                    rel_path,
                    node.lineno,
                    getattr(node, "end_lineno", node.lineno),
                    language=language,
                    message="Exception handler suppresses the error without logging or re-raising — root cause will be invisible at runtime.",
                )
            )
        return hits

    # ── subprocess(..., shell=True) ──────────────────────────────────────
    _SUBPROCESS_SHELL_CALLS: frozenset[str] = frozenset({
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    })

    def _scan_python_subprocess_shell_true(
        self, tree: ast.Module, rel_path: str, language: str,
    ) -> list[RuleHit]:
        """Detect subprocess.* calls passing ``shell=True``.

        This is a low-severity static smell (LOW/HIGH-confidence). The
        security engine's COMMAND-INJECTION-RISK only fires when a tainted
        value flows into the call; this rule flags the construct itself
        regardless of taint, so future edits that introduce dynamic input
        cannot silently turn the call into an injection sink.
        """
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = self._python_call_name(node.func)
            if call_name not in self._SUBPROCESS_SHELL_CALLS:
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    hits.append(
                        RuleHit(
                            SUBPROCESS_SHELL_TRUE,
                            rel_path,
                            node.lineno,
                            getattr(node, "end_lineno", node.lineno),
                            language=language,
                            message=f"`{call_name}(..., shell=True)` — prefer argv list form to avoid future command-injection risk.",
                        )
                    )
                    break
        return hits

    # ── Self-assignment detection ────────────────────────────────────────
    def _scan_python_self_assignment(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect x = x patterns that are likely copy-paste errors."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if len(node.targets) != 1:
                continue
            target = node.targets[0]
            value = node.value
            if self._ast_nodes_equal(target, value):
                name_str = ast.dump(target)
                if isinstance(target, ast.Name):
                    name_str = target.id
                elif isinstance(target, ast.Attribute):
                    name_str = self._python_call_name(target)
                hits.append(
                    RuleHit(
                        SELF_ASSIGNMENT,
                        rel_path,
                        node.lineno,
                        getattr(node, "end_lineno", node.lineno),
                        language=language,
                        message=f"`{name_str} = {name_str}` — variable assigned to itself.",
                    )
                )
        return hits

    @staticmethod
    def _ast_nodes_equal(a: ast.expr, b: ast.expr) -> bool:
        """Check if two AST expression nodes are structurally identical."""
        if type(a) is not type(b):
            return False
        if isinstance(a, ast.Name):
            return a.id == b.id  # type: ignore[union-attr]
        if isinstance(a, ast.Attribute):
            return (
                a.attr == b.attr  # type: ignore[union-attr]
                and DefectEngine._ast_nodes_equal(a.value, b.value)  # type: ignore[union-attr]
            )
        if isinstance(a, ast.Subscript):
            return (
                DefectEngine._ast_nodes_equal(a.value, b.value)  # type: ignore[union-attr]
                and ast.dump(a.slice) == ast.dump(b.slice)  # type: ignore[union-attr]
            )
        return False

    # ── Function/class redefined in loop ─────────────────────────────────
    def _scan_python_redefine_in_loop(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect function or class definitions inside loop bodies."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                continue
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    hits.append(
                        RuleHit(
                            REDEFINE_IN_LOOP,
                            rel_path,
                            stmt.lineno,
                            getattr(stmt, "end_lineno", stmt.lineno),
                            language=language,
                            message=f"Function `{stmt.name}` is redefined on every loop iteration — closures will capture the last loop variable value.",
                        )
                    )
                elif isinstance(stmt, ast.ClassDef):
                    hits.append(
                        RuleHit(
                            REDEFINE_IN_LOOP,
                            rel_path,
                            stmt.lineno,
                            getattr(stmt, "end_lineno", stmt.lineno),
                            language=language,
                            message=f"Class `{stmt.name}` is redefined on every loop iteration.",
                        )
                    )
        return hits

    # ── Exception lost context (raise without from) ──────────────────────
    def _scan_python_exception_lost_context(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect raise NewException() inside except blocks without 'from err' or 'from None'."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Raise):
                    continue
                # raise without argument (re-raise) is fine
                if child.exc is None:
                    continue
                # raise X from Y is fine (cause is set)
                if child.cause is not None:
                    continue
                # Only flag if raising a NEW exception (constructor call), not re-raising a variable
                if isinstance(child.exc, ast.Call):
                    hits.append(
                        RuleHit(
                            EXCEPTION_LOST_CONTEXT,
                            rel_path,
                            child.lineno,
                            getattr(child, "end_lineno", child.lineno),
                            language=language,
                            message="New exception raised in except block without `from` — original traceback is lost.",
                        )
                    )
        return hits

    # ── Infinite recursion risk ──────────────────────────────────────────
    def _scan_python_infinite_recursion(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect functions whose first executable statement is an unconditional self-call."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.body:
                continue
            # Skip decorators, docstrings
            body = node.body
            start_idx = 0
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                start_idx = 1
            if start_idx >= len(body):
                continue
            # Check if ALL paths lead to self-call without guard
            first_stmt = body[start_idx]
            if self._is_unconditional_self_call(first_stmt, node.name):
                hits.append(
                    RuleHit(
                        INFINITE_RECURSION_RISK,
                        rel_path,
                        node.lineno,
                        getattr(node, "end_lineno", node.lineno),
                        language=language,
                        message=f"Function `{node.name}` calls itself unconditionally — will cause RecursionError.",
                    )
                )
        return hits

    def _is_unconditional_self_call(self, stmt: ast.stmt, func_name: str) -> bool:
        """Check if a statement is an unconditional call to the given function name."""
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return self._python_call_name(stmt.value.func) == func_name
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            return self._python_call_name(stmt.value.func) == func_name
        return False

    # ── Infinite loop (while True without break) ───────────────────────
    def _scan_python_infinite_loop(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect while True / while 1 loops without break/return/raise in body."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.While):
                continue
            # Check if condition is always True
            if not self._is_always_true(node.test):
                continue
            # Check if body has any exit path
            if not self._has_exit_statement(node.body):
                hits.append(RuleHit(
                    INFINITE_LOOP_RISK,
                    rel_path,
                    node.lineno,
                    getattr(node, "end_lineno", node.lineno),
                    language=language,
                    message="while True loop with no break/return/raise — will never exit.",
                ))
        return hits

    @staticmethod
    def _is_always_true(node: ast.expr) -> bool:
        """Check if an expression is a constant True/1."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        return False

    @staticmethod
    def _has_exit_statement(stmts: list[ast.stmt]) -> bool:
        """Recursively check if statement list contains break/return/raise."""
        for stmt in stmts:
            if isinstance(stmt, (ast.Break, ast.Return, ast.Raise)):
                return True
            # Check inside if/else branches
            if isinstance(stmt, ast.If):
                if DefectEngine._has_exit_statement(stmt.body):
                    return True
                if DefectEngine._has_exit_statement(stmt.orelse):
                    return True
            # Check inside try/except
            if isinstance(stmt, ast.Try):
                if DefectEngine._has_exit_statement(stmt.body):
                    return True
                for handler in stmt.handlers:
                    if DefectEngine._has_exit_statement(handler.body):
                        return True
            # Check inside for/while (nested loops with break don't count for outer)
            if isinstance(stmt, (ast.For, ast.While)):
                # A return/raise inside nested loop still exits the outer loop
                if DefectEngine._has_exit_in_nested(stmt.body):
                    return True
        return False

    @staticmethod
    def _has_exit_in_nested(stmts: list[ast.stmt]) -> bool:
        """Check for return/raise (not break) in nested statements."""
        for stmt in stmts:
            if isinstance(stmt, (ast.Return, ast.Raise)):
                return True
            if isinstance(stmt, ast.If):
                if DefectEngine._has_exit_in_nested(stmt.body):
                    return True
                if DefectEngine._has_exit_in_nested(stmt.orelse):
                    return True
        return False

    # ── Missing super().__init__ ─────────────────────────────────────────
    def _scan_python_missing_super_init(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect subclass __init__ that doesn't call super().__init__."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # Skip classes with no explicit bases (just `object` implicitly)
            if not node.bases:
                continue
            # Skip classes inheriting only from Exception/enum/etc  where super init is optional
            base_names = {self._python_call_name(b) if isinstance(b, (ast.Name, ast.Attribute)) else "" for b in node.bases}
            if base_names <= {"Exception", "BaseException", "ValueError", "TypeError", "RuntimeError",
                              "KeyError", "IndexError", "AttributeError", "Enum", "IntEnum", "StrEnum",
                              "Flag", "IntFlag", ""}:
                continue
            for item in node.body:
                if not isinstance(item, ast.FunctionDef) or item.name != "__init__":
                    continue
                if self._init_calls_super(item):
                    continue
                hits.append(
                    RuleHit(
                        MISSING_SUPER_INIT,
                        rel_path,
                        item.lineno,
                        getattr(item, "end_lineno", item.lineno),
                        language=language,
                        message=f"Class `{node.name}.__init__` does not call `super().__init__()` — parent class may not be initialized.",
                    )
                )
        return hits

    @staticmethod
    def _init_calls_super(func_node: ast.FunctionDef) -> bool:
        """Check if a function contains super().__init__(...) or ClassName.__init__(self, ...)."""
        for child in ast.walk(func_node):
            if not isinstance(child, ast.Call):
                continue
            if isinstance(child.func, ast.Attribute) and child.func.attr == "__init__":
                value = child.func.value
                # super().__init__(...)
                if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "super":
                    return True
                # ParentClass.__init__(self, ...)
                if isinstance(value, ast.Name):
                    return True
        return False

    # ── Identifier typo detection ────────────────────────────────────────
    # Common misspellings in code identifiers.  Each entry maps a wrong
    # word fragment to its correct form.  We match on word-boundary splits
    # of snake_case / camelCase identifiers.
    _COMMON_TYPOS: dict[str, str] = {
        "recieve": "receive",
        "reciever": "receiver",
        "recieved": "received",
        "recieving": "receiving",
        "occured": "occurred",
        "occuring": "occurring",
        "occurence": "occurrence",
        "occurances": "occurrences",
        "occurance": "occurrence",
        "seperate": "separate",
        "seperated": "separated",
        "seperator": "separator",
        "seperating": "separating",
        "definately": "definitely",
        "defintion": "definition",
        "defination": "definition",
        "lenght": "length",
        "lenth": "length",
        "widht": "width",
        "heigth": "height",
        "hieght": "height",
        "higth": "height",
        "weigth": "weight",
        "strenght": "strength",
        "calender": "calendar",
        "catagory": "category",
        "categroy": "category",
        "enviroment": "environment",
        "envirnoment": "environment",
        "envrionment": "environment",
        "paramater": "parameter",
        "paramter": "parameter",
        "paraemter": "parameter",
        "paramerter": "parameter",
        "arguement": "argument",
        "arguemnt": "argument",
        "fucntion": "function",
        "funciton": "function",
        "funtion": "function",
        "retrun": "return",
        "reutrn": "return",
        "reponse": "response",
        "repsonse": "response",
        "resonse": "response",
        "resposne": "response",
        "requets": "request",
        "reqeust": "request",
        "reuqest": "request",
        "reuslt": "result",
        "resutl": "result",
        "reslut": "result",
        "databse": "database",
        "databaes": "database",
        "datbase": "database",
        "mesage": "message",
        "messge": "message",
        "messgae": "message",
        "excpetion": "exception",
        "exeption": "exception",
        "excepiton": "exception",
        "descrption": "description",
        "descripton": "description",
        "desciption": "description",
        "initalize": "initialize",
        "initailize": "initialize",
        "intiialize": "initialize",
        "initlize": "initialize",
        "improt": "import",
        "imoprt": "import",
        "fitler": "filter",
        "fliter": "filter",
        "udpate": "update",
        "upadte": "update",
        "updaet": "update",
        "verison": "version",
        "vesrion": "version",
        "vresion": "version",
        "avaiable": "available",
        "avaliable": "available",
        "avaialble": "available",
        "availble": "available",
        "destory": "destroy",
        "destoryed": "destroyed",
        "managr": "manager",
        "mananger": "manager",
        "mangaer": "manager",
        "sucessful": "successful",
        "succesful": "successful",
        "sucess": "success",
        "succes": "success",
        "faield": "failed",
        "fialed": "failed",
        "flase": "false",
        "ture": "true",
        "treu": "true",
        "cancle": "cancel",
        "canceld": "canceled",
        "cancelled": "canceled",
        "adress": "address",
        "addres": "address",
        "adrress": "address",
        "propertie": "property",
        "properites": "properties",
        "temperary": "temporary",
        "temporray": "temporary",
        "temproary": "temporary",
        "singlton": "singleton",
        "singletone": "singleton",
        "refernce": "reference",
        "referece": "reference",
        "rference": "reference",
        "colum": "column",
        "colmun": "column",
        "coulmn": "column",
        "rquest": "request",
        "conifg": "config",
        "confg": "config",
        "cofnig": "config",
        "hadnler": "handler",
        "hander": "handler",
        "hanlder": "handler",
        "proccess": "process",
        "porcess": "process",
        "privelege": "privilege",
        "priviledge": "privilege",
        "privilige": "privilege",
        "accross": "across",
        "achive": "achieve",
        "acheive": "achieve",
        "anomoly": "anomaly",
        "asynchrnous": "asynchronous",
        "asyncronous": "asynchronous",
        "atribute": "attribute",
        "attibute": "attribute",
        "attirbute": "attribute",
        "beahvior": "behavior",
        "behaivour": "behavior",
        "behaviuor": "behavior",
        "boundry": "boundary",
        "boundray": "boundary",
        "caculate": "calculate",
        "calcualte": "calculate",
        "calulate": "calculate",
        "complet": "complete",
        "complte": "complete",
        "condtion": "condition",
        "condiion": "condition",
        "connecton": "connection",
        "connetion": "connection",
        "conenction": "connection",
        "contineu": "continue",
        "contiue": "continue",
        "deafult": "default",
        "defualt": "default",
        "defulat": "default",
        "depenency": "dependency",
        "dependecy": "dependency",
        "dependancy": "dependency",
        "direcotry": "directory",
        "directroy": "directory",
        "diretory": "directory",
        "exectuion": "execution",
        "executon": "execution",
        "implment": "implement",
        "implemetn": "implement",
        "implmentation": "implementation",
        "indx": "index",
        "indxe": "index",
        "iteraion": "iteration",
        "iteraton": "iteration",
        "langauge": "language",
        "langugage": "language",
        "libraray": "library",
        "libray": "library",
        "nubmer": "number",
        "nmber": "number",
        "nuber": "number",
        "opeartion": "operation",
        "operaton": "operation",
        "overide": "override",
        "overrride": "override",
        "pacakge": "package",
        "packge": "package",
        "postion": "position",
        "positon": "position",
        "reguler": "regular",
        "regualr": "regular",
        "scheudle": "schedule",
        "schdule": "schedule",
        "shcedule": "schedule",
        "sequnce": "sequence",
        "seqeunce": "sequence",
        "specifc": "specific",
        "specfic": "specific",
        "stauts": "status",
        "statis": "status",
        "startegy": "strategy",
        "stratgey": "strategy",
        "stragety": "strategy",
        "strng": "string",
        "stirng": "string",
        "tempalte": "template",
        "tempalet": "template",
        "templte": "template",
        "threashold": "threshold",
        "thresold": "threshold",
        "treshold": "threshold",
        "valiation": "validation",
        "validaton": "validation",
        "vaiable": "variable",
        "vairable": "variable",
        "varialbe": "variable",
    }

    _TYPO_WORD_SPLIT_RE = re.compile(r"[_]|(?<=[a-z])(?=[A-Z])")

    def _scan_python_identifier_typo(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect common typos in variable, function, class, and argument names."""
        hits: list[RuleHit] = []
        seen_reports: set[tuple[int, str]] = set()  # (line, wrong_word) — deduplicate

        for node in ast.walk(tree):
            identifiers: list[tuple[str, int]] = []  # (name, lineno)

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                identifiers.append((node.name, node.lineno))
                # Also check argument names
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    identifiers.append((arg.arg, arg.lineno))
                if node.args.vararg:
                    identifiers.append((node.args.vararg.arg, node.args.vararg.lineno))
                if node.args.kwarg:
                    identifiers.append((node.args.kwarg.arg, node.args.kwarg.lineno))
            elif isinstance(node, ast.ClassDef):
                identifiers.append((node.name, node.lineno))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                identifiers.append((node.id, node.lineno))

            for name, lineno in identifiers:
                # Skip single-char, dunder, and ALL_CAPS constants
                if len(name) <= 2 or (name.startswith("__") and name.endswith("__")):
                    continue
                # Split camelCase and snake_case into words
                words = self._TYPO_WORD_SPLIT_RE.split(name)
                for word in words:
                    lower_word = word.lower()
                    if lower_word in self._COMMON_TYPOS:
                        key = (lineno, lower_word)
                        if key in seen_reports:
                            continue
                        seen_reports.add(key)
                        correct = self._COMMON_TYPOS[lower_word]
                        hits.append(
                            RuleHit(
                                IDENTIFIER_TYPO,
                                rel_path,
                                lineno,
                                lineno,
                                language=language,
                                message=f"Identifier `{name}` contains typo `{lower_word}` — did you mean `{correct}`?",
                            )
                        )
        return hits

    # ── Bool prefix function does not return bool ────────────────────────
    _BOOL_PREFIXES = ("is_", "has_", "can_", "should_", "was_", "will_", "does_", "needs_")

    def _scan_python_bool_prefix_no_bool_return(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect functions named is_*/has_*/can_*/should_* that don't consistently return bool."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(node.name.startswith(p) for p in self._BOOL_PREFIXES):
                continue
            # Collect all explicit return values
            returns = list(self._collect_returns(node))
            if not returns:
                # No explicit return at all — implicitly returns None, which is fine for
                # some patterns like property-based checks.  Skip to reduce noise.
                continue
            non_bool_returns = []
            for ret in returns:
                if ret.value is None:
                    # bare `return` → returns None, not bool
                    continue
                if not self._is_bool_expression(ret.value):
                    non_bool_returns.append(ret)
            if non_bool_returns and len(non_bool_returns) == len([r for r in returns if r.value is not None]):
                # ALL non-bare returns are non-bool
                first_bad = non_bool_returns[0]
                hits.append(
                    RuleHit(
                        BOOL_PREFIX_NO_BOOL_RETURN,
                        rel_path,
                        node.lineno,
                        getattr(node, "end_lineno", node.lineno),
                        language=language,
                        message=f"Function `{node.name}` has a boolean prefix but returns non-boolean value (line {first_bad.lineno}).",
                    )
                )
        return hits

    @staticmethod
    def _collect_returns(func_node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Yield all Return nodes directly inside this function (not nested functions)."""
        for child in ast.walk(func_node):
            if child is not func_node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Return):
                yield child

    @staticmethod
    def _is_bool_expression(node: ast.expr) -> bool:
        """Check if an expression is clearly a boolean."""
        # Literal True/False
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return True
        # Comparison: a > b, a == b, a in b, a is b, etc.
        if isinstance(node, ast.Compare):
            return True
        # Boolean operations: a and b, a or b
        if isinstance(node, ast.BoolOp):
            return True
        # Unary not: not x
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return True
        # isinstance(...), hasattr(...), callable(...), any(...), all(...)
        if isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in {"isinstance", "issubclass", "hasattr", "callable", "any", "all",
                         "bool", "startswith", "endswith", "isdigit", "isalpha", "isalnum",
                         "isupper", "islower", "isspace", "exists", "is_file", "is_dir",
                         "is_absolute", "is_relative_to"}:
                return True
        # Ternary: x if cond else y — check both branches
        if isinstance(node, ast.IfExp):
            return DefectEngine._is_bool_expression(node.body) and DefectEngine._is_bool_expression(node.orelse)
        return False

    # ── Getter with side effects ─────────────────────────────────────────
    _MUTATING_CALL_PATTERNS = {
        "delete", "remove", "pop", "clear", "drop", "truncate",
        "insert", "append", "extend", "add", "update", "write",
        "save", "commit", "execute", "send", "post", "put", "patch",
        "push", "publish", "emit", "dispatch", "set", "setattr",
        "unlink", "rmdir", "rename", "replace", "move",
    }
    _MUTATING_ATTR_PATTERN = re.compile(
        r"^(?:delete|remove|pop|clear|drop|truncate|insert|append|extend|add|update|"
        r"write|save|commit|execute|send|post|put|patch|push|publish|emit|dispatch|"
        r"set|unlink|rmdir|rename|replace|move)",
        re.IGNORECASE,
    )

    def _scan_python_getter_side_effect(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect functions named get_* that contain mutating operations."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("get_"):
                continue
            # Scan function body for mutating calls
            side_effects = self._find_side_effect_calls(node)
            if side_effects:
                first_effect = side_effects[0]
                hits.append(
                    RuleHit(
                        GETTER_HAS_SIDE_EFFECT,
                        rel_path,
                        node.lineno,
                        getattr(node, "end_lineno", node.lineno),
                        language=language,
                        message=f"Getter `{node.name}` has side effect: calls `{first_effect[0]}` at line {first_effect[1]}.",
                    )
                )
        return hits

    def _find_side_effect_calls(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, int]]:
        """Find mutating method/function calls inside a function body."""
        effects: list[tuple[str, int]] = []
        for child in ast.walk(func_node):
            # Skip nested function/class definitions
            if child is not func_node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if not isinstance(child, ast.Call):
                continue
            call_name = self._python_call_name(child.func)
            # Check if the method name itself is mutating
            method_name = call_name.rsplit(".", 1)[-1] if "." in call_name else call_name
            if method_name.lower() in self._MUTATING_CALL_PATTERNS:
                effects.append((call_name, child.lineno))
            elif self._MUTATING_ATTR_PATTERN.match(method_name):
                effects.append((call_name, child.lineno))
        return effects

    # ── Setter returns a value ───────────────────────────────────────────
    def _scan_python_setter_returns_value(self, tree: ast.Module, rel_path: str, language: str) -> list[RuleHit]:
        """Detect functions named set_* that return a non-None value."""
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("set_"):
                continue
            for ret in self._collect_returns(node):
                if ret.value is None:
                    continue
                # Allow `return None`
                if isinstance(ret.value, ast.Constant) and ret.value.value is None:
                    continue
                # Allow `return self` (fluent interface pattern)
                if isinstance(ret.value, ast.Name) and ret.value.id == "self":
                    continue
                hits.append(
                    RuleHit(
                        SETTER_RETURNS_VALUE,
                        rel_path,
                        node.lineno,
                        getattr(node, "end_lineno", node.lineno),
                        language=language,
                        message=f"Setter `{node.name}` returns a value at line {ret.lineno} — setters should return None.",
                    )
                )
                break  # One hit per function is enough
        return hits

    # ── PYTHON-LOCK-NO-RELEASE ──────────────────────────────────────────
    # 检测 `xxx.acquire()` 调用但同函数内既无 `with xxx:` 也无 try/finally release()
    # 触发条件（保守，降低误报）：
    #   1) 同一函数体内出现 `<obj>.acquire(...)` 直接调用语句
    #   2) 该函数体内未出现对同一对象的 `release()` 调用
    #   3) 该函数体内未出现以同一对象作为 context manager 的 with 语句
    # 这样能识别"裸 acquire 没配 release"和"acquire 在 try 但 release 不在 finally 而在
    # try 末尾（异常路径丢失）"——后者通过结构性检查覆盖（见 _release_in_finally）。
    _LOCK_TARGETS_LAST_NAMES = frozenset({"lock", "rlock", "mutex", "_lock", "_mutex"})

    def _scan_python_lock_no_release(
        self, tree: ast.Module, rel_path: str, language: str
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # 收集 with 语句包裹的对象表达式，以及函数体内（不含嵌套函数）
            # 出现的 acquire / release 调用。手写 BFS 来尊重函数边界。
            with_protected: set[str] = set()
            acquire_calls: list[tuple[ast.Call, ast.Attribute]] = []
            release_calls: list[ast.Call] = []

            stack: list[ast.AST] = list(func.body)
            while stack:
                node = stack.pop()
                if node is not func and isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    continue  # 不进入嵌套函数体
                if isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        ctx_expr = item.context_expr
                        with_protected.add(self._expr_key(ctx_expr))
                        if isinstance(ctx_expr, ast.Call):
                            with_protected.add(self._expr_key(ctx_expr.func))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "acquire":
                        acquire_calls.append((node, node.func))
                    elif node.func.attr == "release":
                        release_calls.append(node)
                stack.extend(ast.iter_child_nodes(node))

            for call, attr in acquire_calls:
                receiver = attr.value
                receiver_key = self._expr_key(receiver)

                # 启发式：仅当受体看起来像锁时才告警
                last_name = receiver_key.rsplit(".", 1)[-1].lower()
                if "lock" not in last_name and "mutex" not in last_name:
                    continue

                if receiver_key in with_protected:
                    continue

                released = False
                release_in_finally = False
                for rel_call in release_calls:
                    if not isinstance(rel_call.func, ast.Attribute):
                        continue
                    if self._expr_key(rel_call.func.value) != receiver_key:
                        continue
                    released = True
                    if self._call_is_in_finally(func, rel_call):
                        release_in_finally = True
                        break

                if released and release_in_finally:
                    continue
                msg_extra = (
                    "found release() but not in a try/finally block"
                    if released
                    else "no matching release() in this function"
                )
                hits.append(
                    RuleHit(
                        PYTHON_LOCK_NO_RELEASE,
                        rel_path,
                        call.lineno,
                        getattr(call, "end_lineno", call.lineno),
                        language=language,
                        message=(
                            f"`{receiver_key}.acquire()` may leak the lock on the exception path "
                            f"({msg_extra}). Use `with {receiver_key}:` or wrap release in try/finally."
                        ),
                        metadata={"receiver": receiver_key},
                    )
                )
        return hits

    @staticmethod
    def _expr_key(node: ast.expr) -> str:
        """Stable string form of a Name/Attribute chain; '?' for anything else."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{DefectEngine._expr_key(node.value)}.{node.attr}"
        return "?"

    @staticmethod
    def _call_is_in_finally(
        func: ast.FunctionDef | ast.AsyncFunctionDef, target: ast.Call
    ) -> bool:
        """Return True if `target` is lexically inside a Try.finalbody under `func`."""
        for node in ast.walk(func):
            if not isinstance(node, ast.Try):
                continue
            for stmt in node.finalbody:
                for child in ast.walk(stmt):
                    if child is target:
                        return True
        return False

    # ── HTTP-NO-STATUS-CHECK ────────────────────────────────────────────
    # 检测 `r = requests.<verb>(...)` 后续对 r 直接使用 .json()/.text/.content
    # 但完全没有 .status_code / .raise_for_status / .ok / .status 引用。
    # 只在同一函数体内分析（不跨函数），并且只覆盖最常见的 requests 库模式以
    # 控制误报。
    _HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request"})
    _STATUS_ATTRS = frozenset({"status_code", "status", "ok", "raise_for_status"})
    _CONSUMING_ATTRS = frozenset({"json", "text", "content", "iter_content", "iter_lines"})

    def _scan_python_http_no_status_check(
        self, tree: ast.Module, rel_path: str, language: str
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # 第一遍：找到 `var = requests.<verb>(...)` 赋值
            assignments: list[tuple[str, ast.Call]] = []
            # BFS，剪枝嵌套 def
            stack: list[ast.AST] = list(func.body)
            all_nodes: list[ast.AST] = []
            while stack:
                node = stack.pop()
                if node is not func and isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    continue
                all_nodes.append(node)
                stack.extend(ast.iter_child_nodes(node))

            for node in all_nodes:
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                target = node.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                if not isinstance(node.value, ast.Call):
                    continue
                call_name = self._http_call_name(node.value.func)
                if call_name is None:
                    continue
                assignments.append((target.id, node.value))

            if not assignments:
                continue

            # 第二遍：对每个 var，分析其属性引用
            for var_name, call_node in assignments:
                status_checked = False
                consumed = False
                escaped = False  # 通过 return / 函数调用参数 传出函数
                for node in all_nodes:
                    # var.<attr> 访问
                    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == var_name:
                        if node.attr in self._STATUS_ATTRS:
                            status_checked = True
                        elif node.attr in self._CONSUMING_ATTRS:
                            consumed = True
                    # return var / return var.something
                    elif isinstance(node, ast.Return) and node.value is not None:
                        for sub in ast.walk(node.value):
                            if isinstance(sub, ast.Name) and sub.id == var_name:
                                escaped = True
                                break
                    # foo(var) — 把 var 作为参数交给别的函数
                    elif isinstance(node, ast.Call):
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id == var_name:
                                escaped = True
                                break

                if escaped or status_checked or not consumed:
                    continue

                hits.append(
                    RuleHit(
                        HTTP_NO_STATUS_CHECK,
                        rel_path,
                        call_node.lineno,
                        getattr(call_node, "end_lineno", call_node.lineno),
                        language=language,
                        message=(
                            f"`{var_name}` from requests.* is consumed (.json/.text/.content) "
                            f"without checking status_code / raise_for_status; 4xx/5xx will be parsed as data."
                        ),
                        metadata={"var": var_name},
                    )
                )
        return hits

    @staticmethod
    def _http_call_name(node: ast.expr) -> str | None:
        """Return 'requests.get' style name if call is requests.<verb>(...), else None.

        Conservative: only match `requests.<verb>` (not session.<verb>) to avoid false positives.
        """
        if not isinstance(node, ast.Attribute):
            return None
        if node.attr not in DefectEngine._HTTP_VERBS:
            return None
        if not isinstance(node.value, ast.Name):
            return None
        if node.value.id != "requests":
            return None
        return f"requests.{node.attr}"


    # ── DICT-ITERATE-MUTATE ─────────────────────────────────────────────
    # 在 for 循环体里对正在迭代的容器调用 del/pop/clear/赋值新键。
    # 边界排除：
    #  - 迭代 list(d) / list(d.keys()) / dict(d) / d.copy() / tuple(d) — 已快照
    #  - 嵌套函数体内的修改（不在当前 for 直接作用域）— 跳过
    _MUTATING_DICT_METHODS = frozenset({"pop", "popitem", "clear", "update", "setdefault"})
    _MUTATING_LIST_METHODS = frozenset({"append", "extend", "insert", "remove", "pop", "clear"})
    _SNAPSHOT_FUNCS = frozenset({"list", "tuple", "set", "frozenset", "dict", "sorted", "reversed"})

    def _scan_python_dict_iterate_mutate(
        self, tree: ast.Module, rel_path: str, language: str
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for for_node in ast.walk(tree):
            if not isinstance(for_node, (ast.For, ast.AsyncFor)):
                continue
            container_name = self._for_iter_container(for_node.iter)
            if container_name is None:
                continue

            # 在 for 体内（不进入嵌套函数）查找直接 mutate
            for child in self._iter_loop_body_nodes(for_node):
                hit_msg: str | None = None
                # del d[k]
                if isinstance(child, ast.Delete):
                    for tgt in child.targets:
                        if (
                            isinstance(tgt, ast.Subscript)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == container_name
                        ):
                            hit_msg = f"`del {container_name}[...]` while iterating `{container_name}`"
                            break
                # d[k] = v  (新键赋值会改 size)
                elif isinstance(child, ast.Assign):
                    for tgt in child.targets:
                        if (
                            isinstance(tgt, ast.Subscript)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == container_name
                        ):
                            hit_msg = f"`{container_name}[...] = ...` while iterating `{container_name}` (new key changes dict size)"
                            break
                # d.pop(k) / d.clear() / l.remove(x) / l.append(x) ...
                elif isinstance(child, ast.Call):
                    if (
                        isinstance(child.func, ast.Attribute)
                        and isinstance(child.func.value, ast.Name)
                        and child.func.value.id == container_name
                        and child.func.attr in (self._MUTATING_DICT_METHODS | self._MUTATING_LIST_METHODS)
                    ):
                        hit_msg = (
                            f"`{container_name}.{child.func.attr}(...)` while iterating `{container_name}` "
                            f"— RuntimeError (dict) or skipped element (list)."
                        )

                if hit_msg is not None:
                    hits.append(
                        RuleHit(
                            DICT_ITERATE_MUTATE,
                            rel_path,
                            child.lineno,
                            getattr(child, "end_lineno", child.lineno),
                            language=language,
                            message=hit_msg,
                            metadata={"container": container_name},
                        )
                    )
        return hits

    @classmethod
    def _for_iter_container(cls, iter_node: ast.expr) -> str | None:
        """Return container name iff `for ... in <name>` or `for ... in <name>.keys()/values()/items()`.

        Returns None if iterator is a snapshot wrapper (list(d), d.copy(), ...).
        """
        # for k in d:
        if isinstance(iter_node, ast.Name):
            return iter_node.id
        # for k in d.keys() / d.values() / d.items()
        if isinstance(iter_node, ast.Call):
            func = iter_node.func
            # Snapshot wrappers: list(d), tuple(d.keys()) — safe, return None
            if isinstance(func, ast.Name) and func.id in cls._SNAPSHOT_FUNCS:
                return None
            if isinstance(func, ast.Attribute):
                # d.copy() — snapshot
                if func.attr == "copy":
                    return None
                # d.keys() / d.values() / d.items()
                if func.attr in {"keys", "values", "items"} and isinstance(func.value, ast.Name):
                    return func.value.id
        return None

    @staticmethod
    def _iter_loop_body_nodes(for_node: ast.For | ast.AsyncFor) -> list[ast.AST]:
        """Yield nodes inside a for body, NOT entering nested functions/comprehensions."""
        result: list[ast.AST] = []
        stack: list[ast.AST] = list(for_node.body)
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                 ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
                continue  # skip nested scopes
            result.append(node)
            stack.extend(ast.iter_child_nodes(node))
        return result

    # ── DUPLICATE-DICT-KEY ──────────────────────────────────────────────
    # dict 字面量内重复键。识别字符串/数字/True/False/None 等可静态求值的常量键。
    def _scan_python_duplicate_dict_key(
        self, tree: ast.Module, rel_path: str, language: str
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            seen: dict[object, int] = {}  # normalized_key -> first lineno
            for key in node.keys:
                if key is None:
                    continue  # **expansion, skip
                normalized = self._normalize_constant_key(key)
                if normalized is _UNHASHABLE:
                    continue
                first = seen.get(normalized)
                if first is None:
                    seen[normalized] = key.lineno
                else:
                    hits.append(
                        RuleHit(
                            DUPLICATE_DICT_KEY,
                            rel_path,
                            key.lineno,
                            getattr(key, "end_lineno", key.lineno),
                            language=language,
                            message=(
                                f"Duplicate dict key {normalized!r} at line {key.lineno} "
                                f"(first defined at line {first}); the later value silently overwrites."
                            ),
                            metadata={"key": repr(normalized), "first_line": str(first)},
                        )
                    )
        return hits

    @staticmethod
    def _normalize_constant_key(key: ast.expr) -> object:
        """Return a hashable canonical form for constant dict keys, or _UNHASHABLE if not constant.

        Note: 1 and 1.0 and True hash-equal in Python; we deliberately preserve that
        so the rule flags `{1: ..., True: ...}` as duplicate (matches runtime behavior).
        """
        if isinstance(key, ast.Constant):
            return key.value
        # Negative numbers parse as UnaryOp(USub, Constant) in older AST
        if (
            isinstance(key, ast.UnaryOp)
            and isinstance(key.op, ast.USub)
            and isinstance(key.operand, ast.Constant)
            and isinstance(key.operand.value, (int, float, complex))
        ):
            return -key.operand.value
        return _UNHASHABLE


    # Log/print function names used across languages — for log-only catch detection
    _LOG_CALL_NAMES = frozenset({
        # JS/TS
        "console.log", "console.error", "console.warn", "console.info", "console.debug",
        # Java
        "System.out.println", "System.err.println", "System.out.print", "System.err.print",
        "logger.error", "logger.warn", "logger.info", "logger.debug",
        "log.error", "log.warn", "log.info", "log.debug",
        "LOG.error", "LOG.warn", "LOG.info", "LOG.debug",
        "Logger.error", "Logger.warn", "Logger.info", "Logger.debug",
        # C++
        "printf", "fprintf", "std::cerr", "std::cout", "cerr", "cout",
        "spdlog::error", "spdlog::warn", "spdlog::info",
        # Go
        "fmt.Println", "fmt.Printf", "fmt.Print",
        "log.Println", "log.Printf", "log.Print",
        "log.Error", "log.Warn", "log.Info",
    })

    @staticmethod
    def _ts_is_log_statement(node: Node, document: 'TreeSitterDocument') -> bool:
        """Check if a statement is exclusively a log/print call (for log-only catch detection)."""
        if node.type == "expression_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr is None:
                return False
            return DefectEngine._ts_is_log_call(expr, document)
        # Some languages have call_expression at statement level
        if node.type in {"call_expression", "method_invocation", "function_call"}:
            return DefectEngine._ts_is_log_call(node, document)
        return False

    @staticmethod
    def _ts_is_log_call(node: Node, document: 'TreeSitterDocument') -> bool:
        """Check if a node is a call to a known logging function."""
        if node.type not in {"call_expression", "method_invocation", "function_call"}:
            return False

        # For Java method_invocation: children are [object, method_name, argument_list]
        # For JS/C++ call_expression: has "function" field
        fn_node = node.child_by_field_name("function") or node.child_by_field_name("name")

        if node.type == "method_invocation" and fn_node is None:
            # Java method_invocation: reconstruct "object.method" from children
            identifiers = [c for c in node.named_children if c.type == "identifier"]
            if len(identifiers) >= 2:
                obj_name = document.text_for(identifiers[0]).strip()
                method_name = document.text_for(identifiers[1]).strip()
                fn_text = f"{obj_name}.{method_name}"
            elif len(identifiers) == 1:
                fn_text = document.text_for(identifiers[0]).strip()
            else:
                # Try full text
                fn_text = document.text_for(node).strip().split("(")[0]
        else:
            if fn_node is None:
                fn_node = node.named_children[0] if node.named_children else None
            if fn_node is None:
                return False
            fn_text = document.text_for(fn_node).strip()

        # Direct match
        if fn_text in DefectEngine._LOG_CALL_NAMES:
            return True
        # Method name suffix match (e.g., someLogger.error(), e.printStackTrace())
        method = fn_text.split(".")[-1] if "." in fn_text else fn_text
        if method in {"error", "warn", "warning", "info", "debug", "trace",
                       "println", "print", "printf", "log",
                       "printStackTrace", "Error", "Warn", "Info"}:
            return True
        return False

    _TS_TERMINATOR_TYPES = frozenset({
        "return_statement", "throw_statement", "break_statement",
        "continue_statement", "goto_statement",
    })

    def _ts_detect_unreachable(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect unreachable code after return/throw/break/continue in any tree-sitter language."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            # Look for block-like containers
            if node.type not in {"block", "statement_block", "compound_statement",
                                  "function_body", "method_body", "switch_body",
                                  "case_clause", "default_clause", "statement_list"}:
                continue
            children = node.named_children
            for i, child in enumerate(children):
                if child.type in self._TS_TERMINATOR_TYPES and i + 1 < len(children):
                    next_child = children[i + 1]
                    # Skip labels, closing braces, and comments
                    if next_child.type in {"comment", "}", "label_statement", "labeled_statement",
                                            "block_comment", "line_comment"}:
                        continue
                    line_start, line_end = document.line_range(next_child)
                    term_line, _ = document.line_range(child)
                    hits.append(RuleHit(
                        UNREACHABLE_CODE, document.relative_path,
                        line_start, line_end, language=language,
                        message=f"This code is unreachable — preceded by `{child.type}` on line {term_line}.",
                    ))
                    break
        return hits

    def _ts_detect_self_assignment(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect x = x patterns via tree-sitter in C-family / Go / Lua."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"assignment_expression", "assignment_statement",
                                  "augmented_assignment_expression"}:
                continue
            # Try standard left/right field names first (C++, Java, JS)
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            # Lua/Go use variable_list/expression_list children instead of left/right fields
            if left is None or right is None:
                var_list = None
                expr_list = None
                for child in node.named_children:
                    if child.type == "variable_list":
                        var_list = child
                    elif child.type == "expression_list":
                        if var_list is not None:
                            expr_list = child  # second expression_list is the RHS
                        else:
                            # Go: first expression_list is LHS in short_var_declaration
                            pass
                if var_list is not None and expr_list is not None:
                    # Compare individual items in Lua-style variable_list = expression_list
                    left_items = [document.text_for(c).strip() for c in var_list.named_children]
                    right_items = [document.text_for(c).strip() for c in expr_list.named_children]
                    for li, ri in zip(left_items, right_items):
                        if li and li == ri and not li.startswith("("):
                            line_start, line_end = document.line_range(node)
                            hits.append(RuleHit(
                                SELF_ASSIGNMENT, document.relative_path,
                                line_start, line_end, language=language,
                                message=f"`{li} = {ri}` — variable assigned to itself.",
                            ))
                continue
            left_text = document.text_for(left).strip()
            right_text = document.text_for(right).strip()
            if left_text and left_text == right_text and not left_text.startswith("("):
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    SELF_ASSIGNMENT, document.relative_path,
                    line_start, line_end, language=language,
                    message=f"`{left_text} = {right_text}` — variable assigned to itself.",
                ))
        return hits

    def _ts_detect_infinite_recursion(self, document: TreeSitterDocument, language: str,
                                       func_types: frozenset[str], name_field: str = "name") -> list[RuleHit]:
        """Detect functions that unconditionally call themselves via tree-sitter."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in func_types:
                continue
            func_name = self._ts_extract_func_name(node, document, name_field)
            if not func_name:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            # For Go, the body is block → statement_list
            effective_body = body
            for child in body.named_children:
                if child.type == "statement_list":
                    effective_body = child
                    break
            # Get first meaningful statement in body
            first_stmt = self._ts_first_meaningful_stmt(effective_body)
            if first_stmt is None:
                continue
            # Check if it's an unconditional call to self
            if self._ts_stmt_is_self_call(first_stmt, func_name, document):
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    INFINITE_RECURSION_RISK, document.relative_path,
                    line_start, line_end, language=language,
                    message=f"Function `{func_name}` calls itself unconditionally — will cause stack overflow.",
                ))
        return hits

    @staticmethod
    def _ts_extract_func_name(node: Node, document: 'TreeSitterDocument', name_field: str = "name") -> str:
        """Extract function name from different language AST structures."""
        # Try direct name field first (Java, Go, JS)
        name_node = node.child_by_field_name(name_field)
        if name_node is not None:
            return document.text_for(name_node).strip()
        # C++: function_definition → declarator → function_declarator → declarator → identifier
        decl_node = node.child_by_field_name("declarator")
        if decl_node is not None:
            if decl_node.type == "function_declarator":
                inner_decl = decl_node.child_by_field_name("declarator")
                if inner_decl is not None:
                    return document.text_for(inner_decl).strip()
            # Might be pointer_declarator wrapping function_declarator
            for child in DefectEngine._walk_nodes(decl_node):
                if child.type == "function_declarator":
                    inner_decl = child.child_by_field_name("declarator")
                    if inner_decl is not None:
                        return document.text_for(inner_decl).strip()
        return ""

    @staticmethod
    def _ts_first_meaningful_stmt(body_node: Node) -> Node | None:
        """Return the first non-comment child of a block/body node."""
        for child in body_node.named_children:
            if child.type in {"comment", "block_comment", "line_comment"}:
                continue
            return child
        return None

    def _ts_stmt_is_self_call(self, stmt: Node, func_name: str, document: TreeSitterDocument) -> bool:
        """Check if a statement is an unconditional call to func_name."""
        # Direct expression statement: func_name(...)
        if stmt.type == "expression_statement":
            expr = stmt.named_children[0] if stmt.named_children else None
            if expr is not None:
                return self._ts_is_call_to(expr, func_name, document)
        # return func_name(...)
        if stmt.type == "return_statement":
            for child in stmt.named_children:
                if self._ts_is_call_to(child, func_name, document):
                    return True
        return False

    @staticmethod
    def _ts_is_call_to(node: Node, func_name: str, document: TreeSitterDocument) -> bool:
        """Check if node is a call_expression to func_name."""
        if node.type not in {"call_expression", "method_invocation"}:
            return False
        fn_node = node.child_by_field_name("function") or node.child_by_field_name("name")
        if fn_node is None:
            # Try first named child
            fn_node = node.named_children[0] if node.named_children else None
        if fn_node is None:
            return False
        return document.text_for(fn_node).strip() == func_name

    def _ts_detect_unused_variables(self, document: TreeSitterDocument, language: str,
                                     func_types: frozenset[str]) -> list[RuleHit]:
        """Detect variables declared/assigned but never read within a function scope."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in func_types:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            # Collect declarations and identifier references
            declared: dict[str, tuple[int, int]] = {}  # name -> (line_start, line_end)
            read_names: set[str] = set()
            # Gather parameters to exclude
            param_names = self._ts_collect_params(node, document)
            self._ts_collect_var_usage(body, document, declared, read_names, param_names, func_types)

            for name, (ls, le) in declared.items():
                if name not in read_names and not name.startswith("_"):
                    hits.append(RuleHit(
                        UNUSED_VARIABLE, document.relative_path,
                        ls, le, language=language,
                        message=f"Variable `{name}` is assigned but never used in this function.",
                    ))
        return hits

    @staticmethod
    def _ts_collect_params(func_node: Node, document: TreeSitterDocument) -> set[str]:
        """Collect parameter names from a function node."""
        params: set[str] = set()
        param_node = func_node.child_by_field_name("parameters") or func_node.child_by_field_name("parameter_list")
        if param_node is None:
            return params
        for child in DefectEngine._walk_nodes(param_node):
            if child.type in {"identifier", "name"} and child.parent is not None and child.parent.type in {
                "formal_parameter", "parameter_declaration", "parameter",
                "required_parameter", "optional_parameter",
                "simple_parameter", "parameter_list",
            }:
                params.add(document.text_for(child).strip())
        return params

    def _ts_collect_var_usage(self, body: Node, document: TreeSitterDocument,
                               declared: dict[str, tuple[int, int]], read_names: set[str],
                               param_names: set[str], func_types: frozenset[str]) -> None:
        """Walk body tree collecting variable declarations and reads."""
        for child in self._walk_nodes(body):
            # Skip nested function bodies
            if child is not body and child.type in func_types:
                continue
            # Variable declarations / assignments
            if child.type in {"variable_declarator", "local_variable_declaration",
                               "short_var_declaration", "var_spec", "local_declaration"}:
                name_node = child.child_by_field_name("name") or child.child_by_field_name("left")
                if name_node is not None:
                    name = document.text_for(name_node).strip()
                    if name and name not in param_names and not name.startswith("_"):
                        line_s, line_e = document.line_range(child)
                        declared.setdefault(name, (line_s, line_e))
            # Assignment expressions/statements
            elif child.type in {"assignment_expression", "assignment_statement"}:
                left = child.child_by_field_name("left")
                if left is not None and left.type == "identifier":
                    name = document.text_for(left).strip()
                    if name and name not in param_names and not name.startswith("_"):
                        line_s, line_e = document.line_range(child)
                        declared.setdefault(name, (line_s, line_e))
            # Identifier reads (in general context)
            elif child.type == "identifier":
                name = document.text_for(child).strip()
                # Heuristic: if the parent is NOT an assignment target or declaration name, it's a read
                parent = child.parent
                if parent is not None:
                    if parent.type in {"assignment_expression", "assignment_statement"}:
                        left = parent.child_by_field_name("left")
                        if left is child:
                            continue
                    if parent.type == "variable_declarator":
                        name_field = parent.child_by_field_name("name")
                        if name_field is child:
                            continue
                read_names.add(name)

    # ══════════════════════════════════════════════════════════════════════
    #  C++ deep tree-sitter analysis
    # ══════════════════════════════════════════════════════════════════════
    _CPP_FUNC_TYPES = frozenset({"function_definition", "function_declarator"})
    _CPP_RESOURCE_FACTORIES = frozenset({
        "fopen", "open", "socket", "accept", "malloc", "calloc", "realloc",
        "new", "CreateFile", "CreateFileA", "CreateFileW",
    })

    def _scan_cpp_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Deep C++ defect detection using tree-sitter."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            text = document.text_for(node)
            # 1. Empty catch handler / log-only catch
            if node.type == "catch_clause":
                block = node.child_by_field_name("body") or self._find_child(node, "compound_statement")
                if block is not None:
                    block_children = [c for c in block.named_children if c.type != "comment"]
                    if not block_children:
                        hits.append(RuleHit(EMPTY_EXCEPT, document.relative_path, line_start, line_end, language=language))
                    elif all(self._ts_is_log_statement(c, document) for c in block_children):
                        hits.append(RuleHit(
                            LOG_ONLY_EXCEPT, document.relative_path,
                            line_start, line_end, language=language,
                            message="Catch block only logs the exception and swallows it — add re-throw or recovery logic.",
                        ))
                # Also check for catch(...) — broadest possible catch
                if "..." in text:
                    hits.append(RuleHit(BARE_EXCEPT, document.relative_path, line_start, line_end, language=language))
                # catch(Exception) / catch(std::exception) — too broad
                elif re.search(r"catch\s*\(\s*(?:const\s+)?(?:std::)?[Ee]xception\b", text):
                    hits.append(RuleHit(BROAD_EXCEPT, document.relative_path, line_start, line_end, language=language,
                                        message="catch(Exception) / catch(std::exception) is too broad — catches all standard exceptions indiscriminately."))
            # 3. Debug prints
            elif node.type == "call_expression":
                fn_node = node.child_by_field_name("function")
                if fn_node is not None:
                    fn_text = document.text_for(fn_node).strip()
                    if fn_text in {"printf", "puts", "fprintf", "std::cout", "cout"}:
                        hits.append(RuleHit(PRINT_DEBUG, document.relative_path, line_start, line_end, language=language))
            # 4. std::cout << (operator expression)
            elif node.type == "binary_expression" or node.type == "shift_expression":
                if "cout" in text and "<<" in text and text.index("cout") < text.index("<<"):
                    hits.append(RuleHit(PRINT_DEBUG, document.relative_path, line_start, line_end, language=language))
            # 5. Assert
            elif node.type == "call_expression" and "assert" in text.split("(")[0].lower():
                hits.append(RuleHit(ASSERT_USED, document.relative_path, line_start, line_end, language=language))

        # Deep detection
        hits.extend(self._ts_detect_unreachable(document, language))
        hits.extend(self._ts_detect_self_assignment(document, language))
        hits.extend(self._ts_detect_infinite_recursion(
            document, language, frozenset({"function_definition"})))
        hits.extend(self._ts_detect_unused_variables(
            document, language, frozenset({"function_definition"})))
        hits.extend(self._scan_cpp_resource_leaks(document, language))
        hits.extend(self._scan_cpp_null_deref(document, language))
        hits.extend(self._scan_cpp_division_by_zero(document, language))
        hits.extend(self._scan_cpp_index_out_of_bounds(document, language))
        hits.extend(self._scan_cpp_swallowed_exception_flow(document, language))
        hits.extend(self._scan_cpp_resource_close_not_guaranteed(document, language))
        hits.extend(self._scan_cpp_use_after_free(document, language))
        hits.extend(self._scan_cpp_double_free(document, language))
        hits.extend(self._scan_cpp_delete_mismatch(document, language))
        return hits


    def _scan_cpp_resource_leaks(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect C/C++ resource acquisitions without RAII or explicit close."""
        hits: list[RuleHit] = []
        body_text = document.source
        for node in self._walk_nodes(document.root_node):
            if node.type != "call_expression":
                continue
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                continue
            fn_name = document.text_for(fn_node).strip()
            if fn_name not in self._CPP_RESOURCE_FACTORIES:
                continue
            # Check if assigned to a variable
            parent = node.parent
            if parent is None or parent.type not in {"init_declarator", "assignment_expression", "declaration"}:
                continue
            line_start, line_end = document.line_range(node)
            # Look for a corresponding close/free/delete in the same function scope
            func_node = self._ts_enclosing_function(node)
            if func_node is None:
                continue
            func_text = document.text_for(func_node)
            close_patterns = {"fclose", "close", "free", "delete", "delete[]",
                              "CloseHandle", "closesocket", "release"}
            has_close = any(p in func_text for p in close_patterns)
            # Also check for RAII wrappers
            has_raii = any(kw in func_text for kw in {"unique_ptr", "shared_ptr", "RAII", "ScopeGuard"})
            if not has_close and not has_raii:
                hits.append(RuleHit(
                    RESOURCE_LEAK, document.relative_path,
                    line_start, line_end, language=language,
                    message=f"Resource acquired via `{fn_name}()` may not be released — no close/free/delete found in scope.",
                ))
        return hits

    def _scan_cpp_null_deref(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect potential null pointer dereferences in C++: result of find/malloc etc used without check."""
        hits: list[RuleHit] = []
        _nullable_calls = {"malloc", "calloc", "realloc", "strstr", "strchr",
                           "strrchr", "find", "dynamic_cast"}
        for node in self._walk_nodes(document.root_node):
            if node.type != "init_declarator":
                continue
            # Get the value being assigned (may be wrapped in cast_expression)
            value_node = node.child_by_field_name("value")
            if value_node is None:
                continue
            # Unwrap cast expressions: (int*)malloc(...)
            actual_call = value_node
            if actual_call.type == "cast_expression":
                inner = actual_call.child_by_field_name("value")
                if inner is not None:
                    actual_call = inner
            if actual_call.type != "call_expression":
                continue
            fn_node = actual_call.child_by_field_name("function")
            if fn_node is None:
                continue
            fn_name = document.text_for(fn_node).strip().split("::")[-1]
            if fn_name not in _nullable_calls:
                continue
            # Get the variable name from declarator chain
            decl_node = node.child_by_field_name("declarator")
            if decl_node is None:
                continue
            # Navigate through pointer_declarator if present
            var_name = document.text_for(decl_node).strip().lstrip("*").strip()
            if not var_name:
                continue
            # Check if there's a null check in the enclosing function
            func_node = self._ts_enclosing_function(node)
            if func_node is None:
                continue
            func_text = document.text_for(func_node)
            assign_line, _ = document.line_range(node)
            null_checks = [f"{var_name} == nullptr", f"{var_name} == NULL", f"{var_name} == 0",
                           f"!{var_name}", f"{var_name} != nullptr", f"{var_name} != NULL",
                           f"if ({var_name})", f"if({var_name})"]
            has_check = any(check in func_text for check in null_checks)
            if not has_check:
                hits.append(RuleHit(
                    POSSIBLE_NONE_DEREF, document.relative_path,
                    assign_line, assign_line, language=language,
                    message=f"`{var_name}` assigned from `{fn_name}()` (may return NULL) but used without null check.",
                ))
        return hits

    def _scan_cpp_division_by_zero(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        literal = re.search(r"(?<![*/])(?:/|%)\s*0\b", document.source)
        if literal is not None:
            line = document.source[:literal.start()].count("\n") + 1
            hits.append(RuleHit(DIVISION_BY_ZERO_RISK, document.relative_path, line, line, language=language,
                                message="Division or modulo uses literal zero as denominator."))
        source_vars = re.finditer(r"\b(?:auto|int|long|size_t|double|float)\s+(?P<var>[A-Za-z_][\w]*)\s*=\s*(?:std::)?(?:stoi|stol|atoi|atol)\s*\(", document.source)
        for assignment in source_vars:
            var_name = assignment.group("var")
            if self._c_like_has_zero_check(document.source, var_name):
                continue
            use = re.search(rf"(?<![*/])(?:/|%)\s*{re.escape(var_name)}\b", document.source[assignment.end():])
            if use is None:
                continue
            line = document.source[: assignment.end() + use.start()].count("\n") + 1
            hits.append(RuleHit(DIVISION_BY_ZERO_RISK, document.relative_path, line, line, language=language,
                                message=f"`{var_name}` is parsed from input/config and used as a denominator without an obvious zero check."))
        return hits

    def _scan_cpp_index_out_of_bounds(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        pattern = re.compile(r"for\s*\([^;]*\b(?P<idx>[A-Za-z_][\w]*)\b[^;]*;[^;]*\b(?P=idx)\s*<=\s*(?P<seq>[A-Za-z_][\w]*)\.size\s*\(\)[^;]*;[^)]*\)\s*\{(?P<body>.*?)\}", re.DOTALL)
        for match in pattern.finditer(document.source):
            idx, seq = match.group("idx"), match.group("seq")
            if re.search(rf"\b{re.escape(seq)}\s*(?:\[\s*{re.escape(idx)}\s*\]|\.at\s*\(\s*{re.escape(idx)}\s*\))", match.group("body")) is None:
                continue
            line = document.source[:match.start()].count("\n") + 1
            hits.append(RuleHit(COLLECTION_INDEX_OUT_OF_BOUNDS, document.relative_path, line, line, language=language,
                                message=f"Loop uses `<= {seq}.size()` and accesses `{seq}[{idx}]`/`.at({idx})`; last iteration can be out of bounds."))
        return hits

    def _scan_cpp_swallowed_exception_flow(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        pattern = re.compile(r"catch\s*\([^)]*\)\s*\{(?P<body>.*?)\}", re.DOTALL)
        for match in pattern.finditer(document.source):
            body = match.group("body")
            if "throw" in body:
                continue
            has_log = re.search(r"\b(?:printf|fprintf|cout|cerr|LOG|log)\b", body) is not None
            default_flow = re.search(r"\breturn\s+(?:nullptr|NULL|false|true|0|\"\")\s*;|\b(?:continue|break)\s*;", body) is not None
            if has_log and default_flow:
                line = document.source[:match.start()].count("\n") + 1
                hits.append(RuleHit(SWALLOWED_EXCEPTION_FLOW, document.relative_path, line, line, language=language,
                                    message="Catch block logs the exception then returns a default value or continues without propagating failure."))
        return hits

    def _scan_cpp_resource_close_not_guaranteed(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for match in re.finditer(r"\b(?P<var>[A-Za-z_][\w]*)\s*=\s*fopen\s*\(", document.source):
            var_name = match.group("var")
            if re.search(rf"\bfclose\s*\(\s*{re.escape(var_name)}\s*\)", document.source[match.end():]) is None:
                continue
            if any(token in document.source for token in {"unique_ptr", "shared_ptr", "ScopeGuard"}):
                continue
            line = document.source[:match.start()].count("\n") + 1
            hits.append(RuleHit(RESOURCE_CLOSE_NOT_GUARANTEED, document.relative_path, line, line, language=language,
                                message=f"`{var_name}` is manually closed, but not managed by RAII/scope guard; early returns or exceptions may skip cleanup."))
        return hits

    # ── CPP-USE-AFTER-FREE ──────────────────────────────────────────────
    # 同函数内：delete p; 或 free(p); 之后再次出现 p 的解引用/成员访问/再次 delete/free，
    # 且未将 p 重新赋值（包括赋值为 nullptr/NULL/新对象）。
    def _scan_cpp_use_after_free(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        # 收集函数节点
        func_nodes = [
            n for n in self._walk_nodes(document.root_node)
            if n.type in {"function_definition"}
        ]
        for func in func_nodes:
            func_text = document.text_for(func)
            func_start_byte = func.start_byte
            # 匹配 delete p; / delete[] p; / free(p);
            free_re = re.compile(
                r"(?:\bdelete\s*(?:\[\s*\])?\s+(?P<v1>[A-Za-z_][\w]*)\s*;"
                r"|\bfree\s*\(\s*(?P<v2>[A-Za-z_][\w]*)\s*\)\s*;)"
            )
            for m in free_re.finditer(func_text):
                var = m.group("v1") or m.group("v2")
                if not var:
                    continue
                after = func_text[m.end():]
                # 找重赋值（含置空）位置：var = ... ;
                reassign = re.search(rf"\b{re.escape(var)}\s*=\s*[^=]", after)
                # 找下一次危险使用：*var / var->x / var[i] / delete var / free(var)
                use_re = re.compile(
                    rf"(?:\*\s*{re.escape(var)}\b"
                    rf"|\b{re.escape(var)}\s*->\s*[A-Za-z_]"
                    rf"|\b{re.escape(var)}\s*\[\s*[^\]]*\]"
                    rf"|\bdelete\s*(?:\[\s*\])?\s+{re.escape(var)}\b"
                    rf"|\bfree\s*\(\s*{re.escape(var)}\s*\))"
                )
                use_m = use_re.search(after)
                if use_m is None:
                    continue
                # 重赋值发生在使用之前 → 已修复，跳过
                if reassign is not None and reassign.start() < use_m.start():
                    continue
                # 计算行号（基于整文档源码偏移）
                free_offset_in_doc = func_text[:m.start()].count("\n")
                free_line = document.source[:func_start_byte].count("\n") + 1 + free_offset_in_doc
                use_offset_in_doc = func_text[:m.end() + use_m.start()].count("\n")
                use_line = document.source[:func_start_byte].count("\n") + 1 + use_offset_in_doc
                hits.append(RuleHit(
                    CPP_USE_AFTER_FREE, document.relative_path,
                    use_line, use_line, language=language,
                    message=(
                        f"`{var}` is freed at line {free_line} but used again at line {use_line} "
                        f"without being reassigned to nullptr — use-after-free."
                    ),
                    metadata={"var": var, "free_line": str(free_line)},
                ))
        return hits

    # ── CPP-DOUBLE-FREE ─────────────────────────────────────────────────
    # 同一函数内，同一个指针被 delete/free 两次，中间没有重赋值或置 nullptr。
    def _scan_cpp_double_free(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        func_nodes = [
            n for n in self._walk_nodes(document.root_node)
            if n.type in {"function_definition"}
        ]
        free_re = re.compile(
            r"(?:\bdelete\s*(?:\[\s*\])?\s+(?P<v1>[A-Za-z_][\w]*)\s*;"
            r"|\bfree\s*\(\s*(?P<v2>[A-Za-z_][\w]*)\s*\)\s*;)"
        )
        for func in func_nodes:
            func_text = document.text_for(func)
            func_start_byte = func.start_byte
            # 按变量名聚合所有 free 位置
            per_var: dict[str, list[int]] = {}
            for m in free_re.finditer(func_text):
                var = m.group("v1") or m.group("v2")
                if not var:
                    continue
                per_var.setdefault(var, []).append(m.start())
            for var, positions in per_var.items():
                if len(positions) < 2:
                    continue
                # 检查相邻两次 free 之间是否有重赋值
                for i in range(1, len(positions)):
                    prev_pos = positions[i - 1]
                    cur_pos = positions[i]
                    # 第 i 次释放前，是否有 `var = ...` 重赋值
                    between = func_text[prev_pos:cur_pos]
                    if re.search(rf"\b{re.escape(var)}\s*=\s*[^=]", between):
                        continue  # 已经被重新赋值（含 nullptr），不是 double-free
                    # 触发
                    line1_offset = func_text[:prev_pos].count("\n")
                    line2_offset = func_text[:cur_pos].count("\n")
                    line1 = document.source[:func_start_byte].count("\n") + 1 + line1_offset
                    line2 = document.source[:func_start_byte].count("\n") + 1 + line2_offset
                    hits.append(RuleHit(
                        CPP_DOUBLE_FREE, document.relative_path,
                        line2, line2, language=language,
                        message=(
                            f"`{var}` is freed at line {line1} and freed again at line {line2} "
                            f"without being reassigned in between — double-free."
                        ),
                        metadata={"var": var, "first_free_line": str(line1)},
                    ))
        return hits

    # ── CPP-DELETE-MISMATCH ─────────────────────────────────────────────
    # 函数内 `T* p = new T[...]` 但配 `delete p`（应 delete[]），或反之。
    def _scan_cpp_delete_mismatch(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        func_nodes = [
            n for n in self._walk_nodes(document.root_node)
            if n.type in {"function_definition"}
        ]
        # new: `p = new T(...)` 或 `T* p = new T(...)`
        # new[]: `p = new T[...]` 或 `T* p = new T[...]`
        new_scalar_re = re.compile(
            r"(?P<var>[A-Za-z_][\w]*)\s*=\s*new\s+[A-Za-z_:][\w:<>\s,]*\s*\("
        )
        new_array_re = re.compile(
            r"(?P<var>[A-Za-z_][\w]*)\s*=\s*new\s+[A-Za-z_:][\w:<>\s,]*\s*\["
        )
        delete_scalar_re = re.compile(
            r"\bdelete\s+(?P<var>[A-Za-z_][\w]*)\s*;"
        )
        delete_array_re = re.compile(
            r"\bdelete\s*\[\s*\]\s*(?P<var>[A-Za-z_][\w]*)\s*;"
        )
        for func in func_nodes:
            func_text = document.text_for(func)
            func_start_byte = func.start_byte
            new_scalar_vars: dict[str, int] = {}
            new_array_vars: dict[str, int] = {}
            for m in new_scalar_re.finditer(func_text):
                new_scalar_vars.setdefault(m.group("var"), m.start())
            for m in new_array_re.finditer(func_text):
                new_array_vars.setdefault(m.group("var"), m.start())
            # scalar new 却 delete[] 释放
            for m in delete_array_re.finditer(func_text):
                var = m.group("var")
                if var in new_scalar_vars and var not in new_array_vars:
                    line_off = func_text[:m.start()].count("\n")
                    line = document.source[:func_start_byte].count("\n") + 1 + line_off
                    hits.append(RuleHit(
                        CPP_DELETE_MISMATCH, document.relative_path,
                        line, line, language=language,
                        message=(
                            f"`delete[] {var}` but `{var}` was allocated with `new T(...)` — "
                            f"use `delete {var}` instead."
                        ),
                        metadata={"var": var, "kind": "scalar-new-array-delete"},
                    ))
            # array new 却 delete 释放
            for m in delete_scalar_re.finditer(func_text):
                var = m.group("var")
                if var in new_array_vars and var not in new_scalar_vars:
                    line_off = func_text[:m.start()].count("\n")
                    line = document.source[:func_start_byte].count("\n") + 1 + line_off
                    hits.append(RuleHit(
                        CPP_DELETE_MISMATCH, document.relative_path,
                        line, line, language=language,
                        message=(
                            f"`delete {var}` but `{var}` was allocated with `new T[...]` — "
                            f"use `delete[] {var}` instead."
                        ),
                        metadata={"var": var, "kind": "array-new-scalar-delete"},
                    ))
        return hits

    @staticmethod
    def _ts_enclosing_function(node: Node) -> Node | None:

        """Walk up the tree to find the enclosing function definition."""
        current = node.parent
        while current is not None:
            if current.type in {"function_definition", "method_declaration",
                                "function_declaration", "constructor_declaration",
                                "local_function_declaration_statement",
                                "function_definition_statement"}:
                return current
            current = current.parent
        return None

    # ══════════════════════════════════════════════════════════════════════
    #  Go deep tree-sitter analysis
    # ══════════════════════════════════════════════════════════════════════
    _GO_RESOURCE_FACTORIES = frozenset({
        "Open", "OpenFile", "Create", "NewFile", "Dial", "DialTCP",
        "DialUDP", "Listen", "ListenTCP", "NewReader", "NewWriter",
        "NewScanner", "Connect",
    })

    def _scan_go_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Deep Go defect detection using tree-sitter."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            text = document.text_for(node)
            # 1. Debug prints (fmt.Println etc.)
            if node.type == "call_expression":
                fn_node = node.child_by_field_name("function")
                if fn_node is not None:
                    fn_text = document.text_for(fn_node).strip()
                    if fn_text in {"fmt.Println", "fmt.Printf", "fmt.Print",
                                   "fmt.Fprintln", "fmt.Fprintf", "fmt.Fprint",
                                   "log.Println", "log.Printf", "log.Print"}:
                        hits.append(RuleHit(PRINT_DEBUG, document.relative_path, line_start, line_end, language=language))
            # 2. Panic used
            if node.type == "call_expression":
                fn_node = node.child_by_field_name("function")
                if fn_node is not None and document.text_for(fn_node).strip() == "panic":
                    hits.append(RuleHit(ASSERT_USED, document.relative_path, line_start, line_end, language=language,
                                        metadata={"note": "panic() used — prefer returning errors in Go."}))

        # Deep detection
        hits.extend(self._ts_detect_unreachable(document, language))
        hits.extend(self._ts_detect_self_assignment(document, language))
        hits.extend(self._ts_detect_infinite_recursion(
            document, language, frozenset({"function_declaration", "method_declaration"})))
        hits.extend(self._ts_detect_unused_variables(
            document, language, frozenset({"function_declaration", "method_declaration"})))
        hits.extend(self._scan_go_error_ignored(document, language))
        hits.extend(self._scan_go_resource_leaks(document, language))
        hits.extend(self._scan_go_nil_deref(document, language))
        hits.extend(self._scan_go_defer_in_loop(document, language))
        hits.extend(self._scan_go_division_by_zero(document, language))
        hits.extend(self._scan_go_index_out_of_bounds(document, language))
        hits.extend(self._scan_go_swallowed_error_flow(document, language))
        hits.extend(self._scan_go_resource_close_not_guaranteed(document, language))
        hits.extend(self._scan_go_range_loop_var_addr(document, language))
        hits.extend(self._scan_go_channel_send_after_close(document, language))
        hits.extend(self._scan_go_nil_map_write(document, language))
        return hits


    def _scan_go_defer_in_loop(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect defer statements inside for loops — deferred calls accumulate until function returns."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "defer_statement":
                continue
            # Walk up to find if inside a for_statement
            current = node.parent
            while current is not None:
                if current.type in {"function_declaration", "method_declaration",
                                     "func_literal"}:
                    break  # Reached function boundary, not inside loop
                if current.type == "for_statement":
                    line_start, line_end = document.line_range(node)
                    defer_text = document.text_for(node).strip()
                    # Truncate for display
                    display = defer_text[:60] + "..." if len(defer_text) > 60 else defer_text
                    hits.append(RuleHit(
                        GO_DEFER_IN_LOOP, document.relative_path,
                        line_start, line_end, language=language,
                        message=f"`{display}` inside loop — deferred calls accumulate until function returns, risking resource exhaustion.",
                    ))
                    break
                current = current.parent
        return hits

    def _scan_go_error_ignored(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Go error values discarded with _ or completely ignored."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"short_var_declaration", "assignment_statement"}:
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            # Go left is expression_list containing identifiers
            left_children = left.named_children if left.type == "expression_list" else [left]
            right_children = right.named_children if right.type == "expression_list" else [right]
            # Check if right side contains a call expression
            has_call = any(c.type == "call_expression" for c in right_children)
            if not has_call:
                continue
            # Check if last left identifier is _ (blank = error discarded)
            if not left_children:
                continue
            last_ident = document.text_for(left_children[-1]).strip()
            if last_ident == "_" and len(left_children) >= 2:
                fn_name = "?"
                for c in right_children:
                    if c.type == "call_expression":
                        fn_node = c.child_by_field_name("function")
                        if fn_node:
                            fn_name = document.text_for(fn_node).strip()
                        break
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    GO_ERROR_IGNORED, document.relative_path,
                    line_start, line_end, language=language,
                    message=f"Error from `{fn_name}()` is discarded with `_` — handle or explicitly document the reason.",
                ))
        return hits

    def _scan_go_resource_leaks(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Go resources opened without defer close."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"short_var_declaration", "assignment_statement"}:
                continue
            right = node.child_by_field_name("right")
            if right is None:
                continue
            # Go right side is expression_list; find a call_expression within
            right_children = right.named_children if right.type == "expression_list" else [right]
            call_node = None
            for c in right_children:
                if c.type == "call_expression":
                    call_node = c
                    break
            if call_node is None:
                continue
            fn_node = call_node.child_by_field_name("function")
            if fn_node is None:
                continue
            fn_text = document.text_for(fn_node).strip()
            # Check if it's a resource factory (e.g., os.Open, net.Dial)
            method_name = fn_text.split(".")[-1] if "." in fn_text else fn_text
            if method_name not in self._GO_RESOURCE_FACTORIES:
                continue
            # Check the enclosing function for defer *.Close()
            func_node = self._ts_enclosing_function(node)
            if func_node is None:
                continue
            func_text = document.text_for(func_node)
            if "defer" in func_text and ".Close()" in func_text:
                continue
            line_start, line_end = document.line_range(node)
            hits.append(RuleHit(
                RESOURCE_LEAK, document.relative_path,
                line_start, line_end, language=language,
                message=f"Resource from `{fn_text}()` may leak — no `defer *.Close()` found in scope.",
            ))
        return hits

    def _scan_go_nil_deref(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect potential nil dereference in Go: err check missing after fallible call."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"short_var_declaration", "assignment_statement"}:
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            # Go: left and right are expression_list
            left_children = left.named_children if left.type == "expression_list" else [left]
            right_children = right.named_children if right.type == "expression_list" else [right]
            # Pattern: result, err := SomeFunc()
            has_call = any(c.type == "call_expression" for c in right_children)
            if not has_call or len(left_children) < 2:
                continue
            val_name = document.text_for(left_children[0]).strip()
            err_name = document.text_for(left_children[-1]).strip()
            if err_name == "_" or not val_name:
                continue
            # Check if next sibling is an if-err check
            parent = node.parent
            if parent is None:
                continue
            siblings = parent.named_children
            node_idx = None
            for i, s in enumerate(siblings):
                if s.id == node.id:
                    node_idx = i
                    break
            if node_idx is None or node_idx + 1 >= len(siblings):
                continue
            next_stmt = siblings[node_idx + 1]
            if next_stmt.type == "if_statement":
                cond = next_stmt.child_by_field_name("condition")
                if cond is not None and err_name in document.text_for(cond):
                    continue
            # No immediate error check — check if val is accessed via method/field
            func_node = self._ts_enclosing_function(node)
            if func_node is None:
                continue
            assign_line, _ = document.line_range(node)
            func_text = document.text_for(func_node)
            if f"{val_name}." in func_text:
                hits.append(RuleHit(
                    POSSIBLE_NONE_DEREF, document.relative_path,
                    assign_line, assign_line, language=language,
                    message=f"`{val_name}` may be nil if `{err_name}` is non-nil, but accessed without error check.",
                ))
        return hits

    def _scan_go_division_by_zero(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        literal = re.search(r"(?<![*/])(?:/|%)\s*0\b", document.source)
        if literal is not None:
            line = document.source[:literal.start()].count("\n") + 1
            hits.append(RuleHit(DIVISION_BY_ZERO_RISK, document.relative_path, line, line, language=language,
                                message="Division or modulo uses literal zero as denominator."))
        for assignment in re.finditer(r"(?P<var>[A-Za-z_][\w]*)\s*,\s*(?:err|_)\s*:=\s*strconv\.(?:Atoi|ParseInt|ParseUint)\s*\(", document.source):
            var_name = assignment.group("var")
            if self._c_like_has_zero_check(document.source, var_name):
                continue
            use = re.search(rf"(?<![*/])(?:/|%)\s*{re.escape(var_name)}\b", document.source[assignment.end():])
            if use is None:
                continue
            line = document.source[: assignment.end() + use.start()].count("\n") + 1
            hits.append(RuleHit(DIVISION_BY_ZERO_RISK, document.relative_path, line, line, language=language,
                                message=f"`{var_name}` is parsed from input/config and used as a denominator without an obvious zero check."))
        return hits

    def _scan_go_index_out_of_bounds(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        pattern = re.compile(r"for\s+(?P<idx>[A-Za-z_][\w]*)\s*:=\s*0\s*;\s*(?P=idx)\s*<=\s*len\s*\(\s*(?P<seq>[A-Za-z_][\w]*)\s*\)[^{]*\{(?P<body>.*?)\}", re.DOTALL)
        for match in pattern.finditer(document.source):
            idx, seq = match.group("idx"), match.group("seq")
            if re.search(rf"\b{re.escape(seq)}\s*\[\s*{re.escape(idx)}\s*\]", match.group("body")) is None:
                continue
            line = document.source[:match.start()].count("\n") + 1
            hits.append(RuleHit(COLLECTION_INDEX_OUT_OF_BOUNDS, document.relative_path, line, line, language=language,
                                message=f"Loop uses `<= len({seq})` and accesses `{seq}[{idx}]`; last iteration can be out of bounds."))
        return hits

    def _scan_go_swallowed_error_flow(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        pattern = re.compile(r"if\s+(?P<err>[A-Za-z_][\w]*)\s*!=\s*nil\s*\{(?P<body>.*?)\}", re.DOTALL)
        for match in pattern.finditer(document.source):
            body = match.group("body")
            has_log = re.search(r"\b(?:log\.|fmt\.Print|println\s*\()", body) is not None
            no_return = "return" not in body
            default_return = re.search(r"return\s+(?:nil|false|true|0|\"\")\s*(?:,\s*nil)?\s*$", body.strip()) is not None
            if not (has_log and (no_return or default_return)):
                continue
            line = document.source[:match.start()].count("\n") + 1
            hits.append(RuleHit(SWALLOWED_EXCEPTION_FLOW, document.relative_path, line, line, language=language,
                                message="Error branch logs the error but does not propagate it or returns a default success-like value."))
        return hits

    def _scan_go_resource_close_not_guaranteed(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        pattern = re.compile(r"(?P<var>[A-Za-z_][\w]*)\s*,\s*(?:err|_)\s*:=\s*(?:os\.)?(?:Open|OpenFile|Create)\s*\(")
        for match in pattern.finditer(document.source):
            var_name = match.group("var")
            after = document.source[match.end():]
            if re.search(rf"defer\s+{re.escape(var_name)}\.Close\s*\(", after):
                continue
            if re.search(rf"\b{re.escape(var_name)}\.Close\s*\(\s*\)", after) is None:
                continue
            line = document.source[:match.start()].count("\n") + 1
            hits.append(RuleHit(RESOURCE_CLOSE_NOT_GUARANTEED, document.relative_path, line, line, language=language,
                                message=f"`{var_name}.Close()` is called manually instead of deferred; early returns may skip cleanup."))
        return hits

    # ── GO-RANGE-LOOP-VAR-ADDR ──────────────────────────────────────────
    # Go<1.22 range 循环变量复用同一地址。检测：
    #   for _, v := range xs { ... &v ... }
    # 其中 &v 出现在闭包/goroutine/append 等"逃逸"场景。
    def _scan_go_range_loop_var_addr(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        # Go 1.22+ changes range loop variable scoping: each iteration gets its own
        # variable, eliminating this entire class of bugs. If the project's go.mod
        # declares `go 1.22` or higher, taking &v is no longer a defect — keeping
        # the rule active would be pure false positives. Disable it in that case.
        if _go_module_version_at_least(document.project_root, (1, 22)):
            return []
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "for_statement":
                continue
            # tree-sitter-go: range 语句类型为 range_clause
            range_clause = None
            for child in node.named_children:
                if child.type == "range_clause":
                    range_clause = child
                    break
            if range_clause is None:
                continue
            # range_clause 形如: <var-list> := range <expr>
            # 提取左侧变量名
            left = range_clause.child_by_field_name("left")
            if left is None:
                continue
            loop_vars: list[str] = []
            children_iter = left.named_children if left.type == "expression_list" else [left]
            for c in children_iter:
                txt = document.text_for(c).strip()
                if txt and txt != "_":
                    loop_vars.append(txt)
            if not loop_vars:
                continue
            # 找 body 内的 &<loop_var>
            body = node.child_by_field_name("body")
            if body is None:
                continue
            # tree-sitter-go: unary_expression with operator '&'
            for inner in self._walk_nodes(body):
                if inner.type != "unary_expression":
                    continue
                op = inner.child_by_field_name("operator")
                if op is None or document.text_for(op).strip() != "&":
                    continue
                operand = inner.child_by_field_name("operand")
                if operand is None:
                    continue
                operand_text = document.text_for(operand).strip()
                if operand_text not in loop_vars:
                    continue
                # 排除：&v 出现在同一行的 v := v 重声明之后（开发者已修复）
                # 通过检查同一作用域是否有 `<v> := <v>` 局部副本
                body_text = document.text_for(body)
                if re.search(rf"\b{re.escape(operand_text)}\s*:=\s*{re.escape(operand_text)}\b", body_text):
                    continue
                line_start, line_end = document.line_range(inner)
                hits.append(RuleHit(
                    GO_RANGE_LOOP_VAR_ADDR, document.relative_path,
                    line_start, line_end, language=language,
                    message=(
                        f"`&{operand_text}` taken on range loop variable — in Go<1.22 all iterations share "
                        f"the same address. Add `{operand_text} := {operand_text}` inside the loop."
                    ),
                ))
        return hits

    # ── GO-CHANNEL-SEND-AFTER-CLOSE ─────────────────────────────────────
    # 同函数内：close(ch) 之后的代码再次出现 ch <- ...
    def _scan_go_channel_send_after_close(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for func_node in self._walk_nodes(document.root_node):
            if func_node.type not in {"function_declaration", "method_declaration", "func_literal"}:
                continue
            close_calls: list[tuple[str, int, int]] = []  # (chan_name, byte_offset, line)
            send_stmts: list[tuple[str, int, int]] = []   # (chan_name, byte_offset, line)
            for inner in self._walk_nodes(func_node):
                # close(ch)
                if inner.type == "call_expression":
                    fn = inner.child_by_field_name("function")
                    if fn is not None and document.text_for(fn).strip() == "close":
                        args = inner.child_by_field_name("arguments")
                        if args is not None and args.named_children:
                            ch = document.text_for(args.named_children[0]).strip()
                            if re.fullmatch(r"[A-Za-z_][\w]*", ch):
                                close_calls.append((ch, inner.start_byte, inner.start_point[0] + 1))
                # ch <- expr  (tree-sitter-go: send_statement)
                elif inner.type == "send_statement":
                    chan_node = inner.child_by_field_name("channel")
                    if chan_node is not None:
                        ch = document.text_for(chan_node).strip()
                        if re.fullmatch(r"[A-Za-z_][\w]*", ch):
                            send_stmts.append((ch, inner.start_byte, inner.start_point[0] + 1))
            if not close_calls or not send_stmts:
                continue
            # 对每个 close，看有没有发生在它之后的 send 同名 channel
            for ch, close_off, _close_line in close_calls:
                for send_ch, send_off, send_line in send_stmts:
                    if send_ch != ch:
                        continue
                    if send_off <= close_off:
                        continue  # send 发生在 close 之前
                    hits.append(RuleHit(
                        GO_CHANNEL_SEND_AFTER_CLOSE, document.relative_path,
                        send_line, send_line, language=language,
                        message=(
                            f"`{ch} <- ...` occurs after `close({ch})` in the same function — "
                            f"runtime panic: send on closed channel."
                        ),
                    ))
        return hits

    # ── GO-NIL-MAP-WRITE ────────────────────────────────────────────────
    # 函数内：`var m map[K]V` 但之后出现 `m[k] = v` 赋值，且未经 make(...) 初始化。
    def _scan_go_nil_map_write(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for func_node in self._walk_nodes(document.root_node):
            if func_node.type not in {"function_declaration", "method_declaration", "func_literal"}:
                continue
            func_text = document.text_for(func_node)
            # 收集 `var m map[...]...`（没有 "=" 或 "=" 后不是 make）的变量
            nil_map_vars: set[str] = set()
            # 形式 1: var m map[K]V
            # 形式 2: var m = map[K]V{}       → 已初始化，不收集
            # 形式 3: var m map[K]V = nil     → 仍是 nil
            var_decl_re = re.compile(
                r"\bvar\s+(?P<var>[A-Za-z_][\w]*)\s+map\s*\[[^\]]+\][^\n=]*(?P<rhs>=[^\n]*)?"
            )
            for m in var_decl_re.finditer(func_text):
                var = m.group("var")
                rhs = m.group("rhs") or ""
                # 如果没有 rhs 或 rhs 就是 = nil，则视为 nil map
                if not rhs.strip():
                    nil_map_vars.add(var)
                else:
                    # 去掉 "=" 前缀
                    assigned = rhs.lstrip("=").strip()
                    if assigned == "nil":
                        nil_map_vars.add(var)
            if not nil_map_vars:
                continue
            # 收集后续 make/重赋值位置：一旦 `var = make(...)` 或 `var = map[..]..{...}` 出现，
            # 之后的写入不再是 nil map 写入
            initialized_offsets: dict[str, int] = {}
            init_re = re.compile(
                r"\b(?P<var>[A-Za-z_][\w]*)\s*=\s*(?:make\s*\(|map\s*\[)"
            )
            for m in init_re.finditer(func_text):
                var = m.group("var")
                if var in nil_map_vars and var not in initialized_offsets:
                    initialized_offsets[var] = m.start()
            # 扫描 `var[key] = value` 赋值位置
            func_start_byte = func_node.start_byte
            # 由于 tree-sitter 的 assignment 节点结构较复杂，用 regex 定位：
            # 左侧形如 `<ident>[...]`，后接 = 且不是 ==
            write_re = re.compile(
                r"\b(?P<var>[A-Za-z_][\w]*)\s*\[\s*[^\]\n]+\s*\]\s*=(?!=)"
            )
            for m in write_re.finditer(func_text):
                var = m.group("var")
                if var not in nil_map_vars:
                    continue
                init_off = initialized_offsets.get(var)
                if init_off is not None and init_off < m.start():
                    continue  # 在写入前已经初始化
                line_off = func_text[:m.start()].count("\n")
                line = document.source[:func_start_byte].count("\n") + 1 + line_off
                hits.append(RuleHit(
                    GO_NIL_MAP_WRITE, document.relative_path,
                    line, line, language=language,
                    message=(
                        f"`{var}[...] = ...` but `{var}` was declared as `var {var} map[...]...` "
                        f"without `make(...)` — runtime panic: assignment to entry in nil map."
                    ),
                    metadata={"var": var},
                ))
        return hits

    # ══════════════════════════════════════════════════════════════════════
    #  Lua deep tree-sitter analysis
    # ══════════════════════════════════════════════════════════════════════

    def _scan_lua_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Deep Lua defect detection using tree-sitter."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            # 1. Debug prints
            if node.type == "function_call":
                fn_text = ""
                for child in node.named_children:
                    if child.type in {"identifier", "dot_index_expression"}:
                        fn_text = document.text_for(child).strip()
                        break
                if fn_text == "print":
                    hits.append(RuleHit(PRINT_DEBUG, document.relative_path, line_start, line_end, language=language))
            # 2. Assert usage
            if node.type == "function_call":
                fn_text = ""
                for child in node.named_children:
                    if child.type in {"identifier", "dot_index_expression"}:
                        fn_text = document.text_for(child).strip()
                        break
                if fn_text == "assert":
                    hits.append(RuleHit(ASSERT_USED, document.relative_path, line_start, line_end, language=language))

        # Deep detection
        hits.extend(self._ts_detect_unreachable(document, language))
        hits.extend(self._ts_detect_self_assignment(document, language))
        hits.extend(self._scan_lua_infinite_recursion(document, language))
        hits.extend(self._scan_lua_unused_variables(document, language))
        return hits

    def _scan_lua_infinite_recursion(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Lua functions calling themselves unconditionally."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"function_declaration", "local_function_declaration_statement",
                                  "function_definition_statement"}:
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            func_name = document.text_for(name_node).strip()
            if not func_name:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            # Check first statement
            first_stmt = self._ts_first_meaningful_stmt(body)
            if first_stmt is None:
                continue
            if first_stmt.type in {"expression_statement", "function_call"}:
                stmt_text = document.text_for(first_stmt).strip()
                if stmt_text.startswith(func_name + "(") or stmt_text.startswith(f"return {func_name}("):
                    line_start, line_end = document.line_range(node)
                    hits.append(RuleHit(
                        INFINITE_RECURSION_RISK, document.relative_path,
                        line_start, line_end, language=language,
                        message=f"Function `{func_name}` calls itself unconditionally — will cause stack overflow.",
                    ))
            elif first_stmt.type == "return_statement":
                for child in first_stmt.named_children:
                    child_text = document.text_for(child).strip()
                    if child_text.startswith(func_name + "("):
                        line_start, line_end = document.line_range(node)
                        hits.append(RuleHit(
                            INFINITE_RECURSION_RISK, document.relative_path,
                            line_start, line_end, language=language,
                            message=f"Function `{func_name}` calls itself unconditionally — will cause stack overflow.",
                        ))
                        break
        return hits

    def _scan_lua_unused_variables(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Lua local variables that are assigned but never read."""
        hits: list[RuleHit] = []
        # Simple approach: collect local declarations and identifier references
        declared: dict[str, tuple[int, int]] = {}
        read_names: set[str] = set()
        for node in self._walk_nodes(document.root_node):
            if node.type in {"local_variable_declaration", "variable_declaration"}:
                for child in node.named_children:
                    if child.type == "variable_list":
                        for var_child in child.named_children:
                            name = document.text_for(var_child).strip()
                            if name and not name.startswith("_"):
                                ls, le = document.line_range(var_child)
                                declared.setdefault(name, (ls, le))
            elif node.type == "identifier":
                parent = node.parent
                # Skip if this is the declaration name itself
                if parent is not None and parent.type in {"local_variable_declaration", "variable_declaration"}:
                    name_list = None
                    for c in parent.named_children:
                        if c.type == "variable_list":
                            name_list = c
                            break
                    if name_list is not None and any(c.id == node.id for c in name_list.named_children):
                        continue
                read_names.add(document.text_for(node).strip())

        for name, (ls, le) in declared.items():
            if name not in read_names:
                hits.append(RuleHit(
                    UNUSED_VARIABLE, document.relative_path,
                    ls, le, language=language,
                    message=f"Variable `{name}` is declared but never used.",
                ))
        return hits

    # ══════════════════════════════════════════════════════════════════════
    #  Enhanced JavaScript/TypeScript tree-sitter analysis
    # ══════════════════════════════════════════════════════════════════════

    def _scan_javascript_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Enhanced JS/TS defect detection using tree-sitter."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            if node.type == "catch_clause":
                block = node.child_by_field_name("body") or self._find_child(node, "statement_block")
                param = node.child_by_field_name("parameter")
                if block is not None and not block.named_children:
                    hits.append(RuleHit(EMPTY_EXCEPT, document.relative_path, line_start, line_end, language=language))
                elif block is not None and param is not None:
                    # Check if catch parameter is never referenced in the block body
                    param_name = document.text_for(param).strip()
                    block_text = document.text_for(block)
                    # Log-only catch: only console.log/console.error in the block
                    block_children = [c for c in block.named_children if c.type != "comment"]
                    if block_children and all(self._ts_is_log_statement(c, document) for c in block_children):
                        hits.append(RuleHit(
                            LOG_ONLY_EXCEPT, document.relative_path,
                            line_start, line_end, language=language,
                            message="Catch block only logs the error and swallows it — add re-throw or recovery logic.",
                        ))
                # Catch without parameter: catch { ... } — broad/bare catch
                if param is None:
                    hits.append(RuleHit(BROAD_EXCEPT, document.relative_path, line_start, line_end, language=language,
                                        message="Catch clause without parameter — all errors are caught indiscriminately."))
            elif node.type == "call_expression":
                function_node = node.child_by_field_name("function") or self._first_named_child(node)
                callee = document.text_for(function_node).strip() if function_node is not None else ""
                if callee in {"console.log", "console.debug", "console.info"}:
                    hits.append(RuleHit(PRINT_DEBUG, document.relative_path, line_start, line_end, language=language))
                elif callee == "console.assert":
                    hits.append(RuleHit(ASSERT_USED, document.relative_path, line_start, line_end, language=language))
                elif callee in {"console.warn", "console.error"}:
                    # Warn/error in catch might be log-only; checked above
                    pass

        # Deep detection
        hits.extend(self._ts_detect_unreachable(document, language))
        hits.extend(self._ts_detect_self_assignment(document, language))
        hits.extend(self._ts_detect_infinite_recursion(
            document, language, frozenset({"function_declaration", "method_definition",
                                            "arrow_function", "function"})))
        hits.extend(self._ts_detect_unused_variables(
            document, language, frozenset({"function_declaration", "method_definition",
                                            "arrow_function", "function"})))
        hits.extend(self._scan_js_unhandled_promise(document, language))
        hits.extend(self._scan_js_null_deref(document, language))
        return hits

    def _scan_js_unhandled_promise(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect async function calls whose returned Promise is neither awaited nor .catch()-ed."""
        hits: list[RuleHit] = []
        # Track known async function names (defined with `async` keyword)
        async_fn_names: set[str] = set()
        for node in self._walk_nodes(document.root_node):
            if node.type in {"function_declaration", "method_definition"}:
                if any(c.type == "async" or document.text_for(c).strip() == "async"
                       for c in node.children if not c.is_named):
                    name_node = node.child_by_field_name("name")
                    if name_node:
                        async_fn_names.add(document.text_for(name_node).strip())

        for node in self._walk_nodes(document.root_node):
            if node.type != "expression_statement":
                continue
            expr = self._first_named_child(node)
            if expr is None or expr.type != "call_expression":
                continue
            # Check if this is an async call without await
            fn_node = expr.child_by_field_name("function")
            if fn_node is None:
                continue
            fn_text = document.text_for(fn_node).strip()
            # Check if calling a known async function
            fn_base = fn_text.split(".")[-1] if "." in fn_text else fn_text
            if fn_base not in async_fn_names:
                continue
            # Check parent is NOT an await_expression
            if node.parent and node.parent.type == "await_expression":
                continue
            # Check the call itself is not inside an await
            parent_expr = node
            while parent_expr:
                if parent_expr.type == "await_expression":
                    break
                parent_expr = parent_expr.parent
            else:
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    JS_UNHANDLED_PROMISE, document.relative_path,
                    line_start, line_end, language=language,
                    message=f"Async call `{fn_text}()` is not awaited — Promise rejection will be unhandled.",
                ))
        return hits

    def _scan_js_null_deref(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect potential null/undefined dereference patterns in JS/TS."""
        hits: list[RuleHit] = []
        _nullable_methods = {"getElementById", "querySelector", "find", "get",
                              "getAttribute", "closest", "parentElement"}
        for node in self._walk_nodes(document.root_node):
            if node.type != "call_expression":
                continue
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                continue
            fn_text = document.text_for(fn_node).strip()
            method_name = fn_text.split(".")[-1] if "." in fn_text else fn_text
            if method_name not in _nullable_methods:
                continue
            # Check if result is used in a member_expression chain without optional chaining
            parent = node.parent
            if parent is not None and parent.type == "member_expression":
                text = document.text_for(parent)
                # If using optional chaining ?. then it's safe
                if "?." not in text:
                    line_start, line_end = document.line_range(node)
                    hits.append(RuleHit(
                        POSSIBLE_NONE_DEREF, document.relative_path,
                        line_start, line_end, language=language,
                        message=f"`.{method_name}()` may return null but result is accessed directly — use optional chaining `?.` or add null check.",
                    ))
        return hits

    # ══════════════════════════════════════════════════════════════════════
    #  Enhanced Java tree-sitter analysis
    # ══════════════════════════════════════════════════════════════════════

    def _scan_java_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            text = document.text_for(node)
            if node.type == "catch_clause":
                if re.search(r"\b(?:Exception|Throwable|Error)\b", text):
                    hits.append(RuleHit(BROAD_EXCEPT, document.relative_path, line_start, line_end, language=language))
                block = node.child_by_field_name("body") or self._find_child(node, "block")
                if block is not None:
                    block_children = [c for c in block.named_children if c.type != "comment"]
                    if not block_children:
                        hits.append(RuleHit(EMPTY_EXCEPT, document.relative_path, line_start, line_end, language=language))
                    elif all(self._ts_is_log_statement(c, document) for c in block_children):
                        hits.append(RuleHit(
                            LOG_ONLY_EXCEPT, document.relative_path,
                            line_start, line_end, language=language,
                            message="Catch block only logs the exception and swallows it — add re-throw or recovery logic.",
                        ))
            elif node.type == "method_invocation":
                if "System.out.println" in text or "System.err.println" in text:
                    hits.append(RuleHit(PRINT_DEBUG, document.relative_path, line_start, line_end, language=language))
            elif node.type == "assert_statement":
                hits.append(RuleHit(ASSERT_USED, document.relative_path, line_start, line_end, language=language))

        # Deep detection
        hits.extend(self._ts_detect_unreachable(document, language))
        hits.extend(self._ts_detect_self_assignment(document, language))
        hits.extend(self._ts_detect_infinite_recursion(
            document, language, frozenset({"method_declaration", "constructor_declaration"})))
        hits.extend(self._ts_detect_unused_variables(
            document, language, frozenset({"method_declaration", "constructor_declaration"})))
        hits.extend(self._scan_java_resource_leaks(document, language))
        hits.extend(self._scan_java_null_deref(document, language))
        hits.extend(self._scan_java_nullable_flow(document, language))
        hits.extend(self._scan_java_boolean_bitwise(document, language))
        hits.extend(self._scan_java_division_by_zero(document, language))
        hits.extend(self._scan_java_index_out_of_bounds(document, language))
        hits.extend(self._scan_java_swallowed_exception_flow(document, language))
        hits.extend(self._scan_java_static_mutable_state(document, language))
        hits.extend(self._scan_java_resource_close_not_guaranteed(document, language))
        hits.extend(self._scan_java_string_eq_operator(document, language))
        hits.extend(self._scan_java_foreach_collection_mutate(document, language))
        hits.extend(self._scan_java_hashcode_equals_mismatch(document, language))
        hits.extend(self._scan_java_equals_on_array(document, language))
        hits.extend(self._scan_java_integer_boxing_eq(document, language))
        hits.extend(self._scan_switch_no_default_java(document, language))
        return hits



    _JAVA_RESOURCE_FACTORIES = frozenset({
        "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
        "BufferedReader", "BufferedWriter", "InputStreamReader", "OutputStreamWriter",
        "Socket", "ServerSocket", "DatagramSocket", "Connection",
        "PreparedStatement", "Statement", "ResultSet",
    })

    def _scan_java_resource_leaks(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Java resources opened without try-with-resources or explicit close."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "object_creation_expression":
                continue
            type_node = node.child_by_field_name("type")
            if type_node is None:
                continue
            type_name = document.text_for(type_node).strip()
            if type_name not in self._JAVA_RESOURCE_FACTORIES:
                continue
            # Check if inside try-with-resources
            parent = node.parent
            in_try_with = False
            current = parent
            while current is not None:
                if current.type == "try_with_resources_statement":
                    in_try_with = True
                    break
                if current.type in {"method_declaration", "constructor_declaration"}:
                    break
                current = current.parent
            if in_try_with:
                continue
            # Check if .close() is called in the enclosing method
            func_node = self._ts_enclosing_function(node)
            if func_node is None:
                continue
            func_text = document.text_for(func_node)
            if ".close()" in func_text:
                continue
            line_start, line_end = document.line_range(node)
            hits.append(RuleHit(
                RESOURCE_LEAK, document.relative_path,
                line_start, line_end, language=language,
                message=f"`new {type_name}(...)` not in try-with-resources and no `.close()` found — potential resource leak.",
            ))
        return hits

    def _scan_java_null_deref(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect potential NullPointerException in Java."""
        hits: list[RuleHit] = []
        _nullable_methods = {"get", "find", "findFirst", "poll", "peek",
                              "getProperty", "getAttribute", "remove"}
        for node in self._walk_nodes(document.root_node):
            if node.type != "method_invocation":
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            method_name = document.text_for(name_node).strip()
            if method_name not in _nullable_methods:
                continue
            # Check if the result is used in a method chain without null check
            parent = node.parent
            if parent is not None and parent.type == "method_invocation":
                # Chained: someMap.get(key).doSomething() — dangerous
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    POSSIBLE_NONE_DEREF, document.relative_path,
                    line_start, line_end, language=language,
                    message=f"`.{method_name}()` may return null but result is chained directly — add null check.",
                ))
        return hits

    def _scan_java_nullable_flow(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect Java nullable-return propagation and dangerous sinks.

        This is deliberately API-contract based, not file-specific: Java APIs such as
        Properties.getProperty(), Map.get(), ClassLoader.getResourceAsStream(), and
        project wrapper methods that return those values may produce null. Directly
        calling trim()/toString()/parseXxx()/Properties.load(...) on those values is
        a realistic runtime crash risk.
        """
        hits: list[RuleHit] = []
        nullable_methods = {
            "getProperty", "getResourceAsStream", "get", "find", "findFirst", "poll", "peek", "getAttribute", "remove",
        }
        nullable_methods.update(self._java_nullable_returning_methods(document))
        if not nullable_methods:
            return hits

        method_names = "|".join(re.escape(name) for name in sorted(nullable_methods, key=len, reverse=True))
        nullable_call = rf"(?:\b\w+\.)?(?:{method_names})\s*\([^;\n]*\)"
        nullable_expr = rf"[^;\n]*(?:{method_names})\s*\([^;\n]*\)"
        dangerous_chain = re.compile(
            rf"(?P<call>{nullable_call})\s*\.\s*(?P<sink>trim|toString|length|isEmpty|equals|equalsIgnoreCase)\s*\(",
        )
        parse_direct = re.compile(
            rf"\b(?:Integer|Long|Double|Float|Short|Byte)\.parse\w+\s*\(\s*(?P<call>{nullable_call})",
        )


        for method_node in self._java_method_nodes(document):
            method_text = document.text_for(method_node)
            method_start, _ = document.line_range(method_node)
            for pattern, sink_desc in (
                (dangerous_chain, "method call on nullable return value"),
                (parse_direct, "parseXxx call on nullable return value"),
            ):
                for match in pattern.finditer(method_text):
                    call_text = match.group("call").strip()
                    # The greedy `nullable_call` sub-pattern can capture one extra
                    # trailing ')'. Balance parentheses so guard matching / message
                    # use the exact expression (e.g. `map.get("k")`, not `map.get("k"))`).
                    while call_text.endswith(")") and call_text.count(")") > call_text.count("("):
                        call_text = call_text[:-1]
                    # Skip if the same nullable expression is null-guarded in scope.
                    if self._java_expr_is_guarded(method_text, call_text):
                        continue
                    line = method_start + method_text[:match.start()].count("\n")
                    hits.append(RuleHit(
                        POSSIBLE_NONE_DEREF, document.relative_path,
                        line, line, language=language,
                        message=f"`{call_text}` may return null and is used by {sink_desc}; add null/default handling first.",
                    ))
            hits.extend(self._scan_java_nullable_vars_in_method(document, method_node, nullable_expr, language))
        return hits

    def _scan_java_nullable_vars_in_method(
        self,
        document: TreeSitterDocument,
        method_node: Node,
        nullable_expr: str,
        language: str,
    ) -> list[RuleHit]:

        hits: list[RuleHit] = []
        method_text = document.text_for(method_node)
        method_start, _ = document.line_range(method_node)
        assignment_re = re.compile(
            rf"(?:^|[;{{\n])\s*(?:[\w<>\[\]]+\s+)?(?P<var>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>{nullable_expr})\s*;",
        )

        for assignment in assignment_re.finditer(method_text):
            var_name = assignment.group("var")
            if self._java_has_null_check(method_text, var_name):
                continue
            after_assignment = method_text[assignment.end():]
            sink_match = re.search(
                rf"(?:\b{re.escape(var_name)}\s*\.\s*(?:trim|toString|length|isEmpty|equals|equalsIgnoreCase)\s*\(|\b(?:Integer|Long|Double|Float|Short|Byte)\.parse\w+\s*\(\s*{re.escape(var_name)}\b|\.load\s*\(\s*{re.escape(var_name)}\s*\))",
                after_assignment,
            )
            if sink_match is None:
                continue
            use_offset = assignment.end() + sink_match.start()
            line = method_start + method_text[:use_offset].count("\n")
            hits.append(RuleHit(
                POSSIBLE_NONE_DEREF, document.relative_path,
                line, line, language=language,
                message=f"`{var_name}` is assigned from a nullable API (`{assignment.group('expr').strip()}`) and used without a null check.",
            ))
        return hits

    def _java_nullable_returning_methods(self, document: TreeSitterDocument) -> set[str]:
        nullable_methods: set[str] = set()
        nullable_source_re = re.compile(r"(?:\.getProperty\s*\(|\.get\s*\(|getResourceAsStream\s*\()")
        for method_node in self._java_method_nodes(document):
            name_node = method_node.child_by_field_name("name")
            if name_node is None:
                continue
            method_name = document.text_for(name_node).strip()
            text = document.text_for(method_node)
            if re.search(r"return\s+[^;]*(?:\.getProperty\s*\(|\.get\s*\(|getResourceAsStream\s*\()", text):
                nullable_methods.add(method_name)
                continue
            for assigned in re.finditer(r"(?:[\w<>\[\]]+\s+)?(?P<var>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^;]+);", text):
                var_name = assigned.group("var")
                if not nullable_source_re.search(assigned.group("expr")):
                    continue
                if re.search(rf"return\s+{re.escape(var_name)}\s*;", text[assigned.end():]):
                    nullable_methods.add(method_name)
                    break
        return nullable_methods

    def _scan_java_boolean_bitwise(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type not in {"if_statement", "while_statement", "for_statement"}:
                continue
            text = document.text_for(node)
            first_line = text.split("\n", 1)[0]
            condition = self._java_condition_text(first_line)
            if not condition:
                continue
            has_single_amp = re.search(r"(?<![&])&(?![&=])", condition) is not None
            has_single_pipe = re.search(r"(?<![|])\|(?![|=])", condition) is not None
            looks_boolean = re.search(r"==|!=|>=|<=|>|<|\btrue\b|\bfalse\b|\bnull\b|\.equals\s*\(", condition) is not None
            if not (looks_boolean and (has_single_amp or has_single_pipe)):
                continue
            line_start, line_end = document.line_range(node)
            op = "&" if has_single_amp else "|"
            replacement = "&&" if has_single_amp else "||"
            hits.append(RuleHit(
                SUSPICIOUS_BOOLEAN_BITWISE, document.relative_path,
                line_start, line_end, language=language,
                message=f"Boolean condition uses `{op}` instead of short-circuit `{replacement}`: `{condition.strip()}`.",
            ))
        return hits

    def _scan_java_division_by_zero(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for method_node in self._java_method_nodes(document):
            method_text = document.text_for(method_node)
            method_start, _ = document.line_range(method_node)

            literal_zero = re.search(r"(?<![*/])(?:/|%)\s*0(?:\.0+)?\b", method_text)
            if literal_zero is not None:
                line = method_start + method_text[:literal_zero.start()].count("\n")
                hits.append(RuleHit(
                    DIVISION_BY_ZERO_RISK, document.relative_path,
                    line, line, language=language,
                    message="Division or modulo uses literal zero as denominator.",
                ))
                continue

            for match in re.finditer(r"(?<![*/])(?P<op>/|%)\s*(?P<den>[A-Za-z_$][\w$]*)\b", method_text):
                denominator = match.group("den")
                if self._java_has_zero_check(method_text, denominator):
                    continue
                if not self._java_looks_external_numeric(method_text, denominator):
                    continue
                line = method_start + method_text[:match.start()].count("\n")
                hits.append(RuleHit(
                    DIVISION_BY_ZERO_RISK, document.relative_path,
                    line, line, language=language,
                    message=f"`{denominator}` is used as a denominator without an obvious zero check.",
                ))
        return hits

    def _scan_java_index_out_of_bounds(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "for_statement":
                continue
            text = document.text_for(node)
            match = re.search(r"(?P<idx>[A-Za-z_$][\w$]*)\s*<=\s*(?P<target>[A-Za-z_$][\w$]*)\s*\.\s*(?P<kind>size\s*\(\)|length)(?!\w)", text)

            if match is None:
                continue
            idx = match.group("idx")
            target = match.group("target")
            kind = match.group("kind")
            uses_collection = re.search(rf"\b{re.escape(target)}\s*\.\s*get\s*\(\s*{re.escape(idx)}\s*\)", text) is not None
            uses_array = re.search(rf"\b{re.escape(target)}\s*\[\s*{re.escape(idx)}\s*\]", text) is not None
            if not (uses_collection or ("length" in kind and uses_array)):
                continue
            line_start, line_end = document.line_range(node)
            hits.append(RuleHit(
                COLLECTION_INDEX_OUT_OF_BOUNDS, document.relative_path,
                line_start, line_end, language=language,
                message=f"Loop uses `<= {target}.{kind}` and accesses index `{idx}`; last iteration can be out of bounds.",
            ))
        return hits

    def _scan_java_swallowed_exception_flow(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "catch_clause":
                continue
            text = document.text_for(node)
            if "throw" in text:
                continue
            has_log = re.search(r"(?:logger\s*\.|log\s*\.|System\.(?:err|out)\.|printStackTrace\s*\()", text) is not None
            swallows_flow = re.search(r"\breturn\s+(?:null|false|true|0|\"\")\s*;|\b(?:continue|break)\s*;", text) is not None
            if not (has_log and swallows_flow):
                continue
            line_start, line_end = document.line_range(node)
            hits.append(RuleHit(
                SWALLOWED_EXCEPTION_FLOW, document.relative_path,
                line_start, line_end, language=language,
                message="Catch block logs the exception then returns a default value or continues control flow without propagating failure.",
            ))
        return hits

    _JAVA_MUTABLE_FIELD_TYPES = frozenset({
        "Map", "HashMap", "ConcurrentHashMap", "LinkedHashMap", "TreeMap", "Hashtable",
        "List", "ArrayList", "LinkedList", "Vector",
        "Set", "HashSet", "TreeSet", "LinkedHashSet",
        "Properties", "StringBuilder", "StringBuffer",
    })

    def _scan_java_static_mutable_state(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect non-final static mutable FIELDS.

        Uses the AST ``field_declaration`` node so that static METHODS whose
        signature/body merely mention a mutable type (e.g.
        ``public static void copyMap(Map dest, Map src)``) are not misclassified.
        """
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "field_declaration":
                continue
            modifier_tokens: set[str] = set()
            for child in node.children:
                if child.type == "modifiers":
                    modifier_tokens = set(document.text_for(child).split())
                    break
            if "static" not in modifier_tokens or "final" in modifier_tokens:
                continue
            type_node = node.child_by_field_name("type")
            if type_node is None:
                continue
            type_text = document.text_for(type_node).strip()
            base_type = re.split(r"[<\[]", type_text, maxsplit=1)[0].strip()
            if base_type not in self._JAVA_MUTABLE_FIELD_TYPES:
                continue
            line_start, line_end = document.line_range(node)
            hits.append(RuleHit(
                STATIC_MUTABLE_SHARED_STATE, document.relative_path,
                line_start, line_end, language=language,
                message="Non-final static mutable state is shared across threads/tests; define synchronization or use immutable/concurrent alternatives.",
            ))
        return hits

    def _scan_java_resource_close_not_guaranteed(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        factories = "|".join(re.escape(name) for name in sorted(self._JAVA_RESOURCE_FACTORIES, key=len, reverse=True))
        assignment_re = re.compile(rf"\b(?P<type>{factories})\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*new\s+(?P=type)\s*\(")
        for method_node in self._java_method_nodes(document):
            method_text = document.text_for(method_node)
            if "try (" in method_text or "finally" in method_text:
                continue
            method_start, _ = document.line_range(method_node)
            for match in assignment_re.finditer(method_text):
                var_name = match.group("var")
                if re.search(rf"\b{re.escape(var_name)}\s*\.\s*close\s*\(", method_text) is None:
                    continue
                line = method_start + method_text[:match.start()].count("\n")
                hits.append(RuleHit(
                    RESOURCE_CLOSE_NOT_GUARANTEED, document.relative_path,
                    line, line, language=language,
                    message=f"`{var_name}.close()` exists, but the resource is not managed by try-with-resources/finally; close may be skipped on exceptions.",
                ))
        return hits

    # ── JAVA-STRING-EQ-OPERATOR ─────────────────────────────────────────
    # Java 中用 == / != 比较 String 是引用比较，不是内容相等。
    # 触发：binary_expression (== 或 !=) 两侧任意一侧是 String literal、
    # String 类型变量声明、或返回 String 的常见方法调用。
    _JAVA_STRING_RETURNERS = frozenset({
        "toString", "trim", "substring", "concat", "replace", "replaceAll", "replaceFirst",
        "toLowerCase", "toUpperCase", "valueOf", "format", "join",
        "getString", "getProperty", "getName", "getValue", "getMessage",
        "readLine", "name",
    })

    def _scan_java_string_eq_operator(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        # 收集函数体内被声明为 String 的变量名（粗粒度，用方法源码 regex）
        for method_node in self._java_method_nodes(document):
            method_text = document.text_for(method_node)
            string_vars: set[str] = set()
            for m in re.finditer(r"\bString(?:\s*\[\s*\])?\s+(?P<var>[A-Za-z_$][\w$]*)\b", method_text):
                string_vars.add(m.group("var"))
            method_start, _ = document.line_range(method_node)

            # 遍历方法内的二元表达式
            for node in self._walk_nodes(method_node):
                if node.type != "binary_expression":
                    continue
                op = node.child_by_field_name("operator")
                if op is None:
                    continue
                op_text = document.text_for(op).strip()
                if op_text not in {"==", "!="}:
                    continue
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None:
                    continue
                # 两侧 null 字面量：合法 (a == null) 检查，跳过
                left_text = document.text_for(left).strip()
                right_text = document.text_for(right).strip()
                if left_text == "null" or right_text == "null":
                    continue
                if not (self._java_side_is_string(left, left_text, string_vars)
                        or self._java_side_is_string(right, right_text, string_vars)):
                    continue
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    JAVA_STRING_EQ_OPERATOR, document.relative_path,
                    line_start, line_end, language=language,
                    message=(
                        f"`{left_text} {op_text} {right_text}` compares String references; "
                        f"use `Objects.equals(...)` or `.equals(...)` for content equality."
                    ),
                ))
        return hits

    @staticmethod
    def _java_side_is_string(node: Node, text: str, string_vars: set[str]) -> bool:
        # String literal
        if node.type == "string_literal":
            return True
        # Local variable known to be String
        if node.type == "identifier" and text in string_vars:
            return True
        # Method invocation returning a likely String (heuristic by method name)
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = (name_node.text or b"").decode("utf-8", errors="ignore")
                if name in DefectEngine._JAVA_STRING_RETURNERS:
                    return True
            # x.toString() / x.trim() — last segment matches
            last_seg = text.split(".")[-1].split("(")[0]
            if last_seg in DefectEngine._JAVA_STRING_RETURNERS:
                return True
        return False

    # ── FOREACH-COLLECTION-MUTATE (Java) ────────────────────────────────
    # for (T x : coll) { coll.add/remove/clear/put/... }
    _JAVA_MUTATING_METHODS = frozenset({"add", "addAll", "remove", "removeAll", "removeIf",
                                         "clear", "put", "putAll", "retainAll", "set"})

    def _scan_java_foreach_collection_mutate(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "enhanced_for_statement":
                continue
            # tree-sitter-java field name for the iterable expression in `for(T x : it)`
            iterable_node = (
                node.child_by_field_name("value")
                or node.child_by_field_name("iterable")
                or node.child_by_field_name("expression")
            )
            body_node = node.child_by_field_name("body")
            if iterable_node is None or body_node is None:
                continue
            coll_text = document.text_for(iterable_node).strip()
            # 仅当迭代对象是简单变量名时分析（避免 for(... : list.subList(...))）
            if not re.fullmatch(r"[A-Za-z_$][\w$]*", coll_text):
                continue
            # 在 body 内查找 coll.<mut>(...) 调用
            for inner in self._walk_nodes(body_node):
                if inner.type != "method_invocation":
                    continue
                obj_node = inner.child_by_field_name("object")
                name_node = inner.child_by_field_name("name")
                if obj_node is None or name_node is None:
                    continue
                if document.text_for(obj_node).strip() != coll_text:
                    continue
                method_name = document.text_for(name_node).strip()
                if method_name not in self._JAVA_MUTATING_METHODS:
                    continue
                line_start, line_end = document.line_range(inner)
                hits.append(RuleHit(
                    FOREACH_COLLECTION_MUTATE, document.relative_path,
                    line_start, line_end, language=language,
                    message=(
                        f"`{coll_text}.{method_name}(...)` inside enhanced-for over `{coll_text}` "
                        f"— ConcurrentModificationException at runtime."
                    ),
                ))
        return hits

    # ── JAVA-HASHCODE-EQUALS-MISMATCH ───────────────────────────────────
    # class 重写 equals(Object) 或 hashCode() 其一，未同时重写另一个。
    def _scan_java_hashcode_equals_mismatch(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            if node.type != "class_declaration":
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            has_equals = False
            has_hashcode = False
            equals_line = 0
            hashcode_line = 0
            class_name_node = node.child_by_field_name("name")
            class_name = document.text_for(class_name_node).strip() if class_name_node else "<anon>"
            for member in body.named_children:
                if member.type != "method_declaration":
                    continue
                name_node = member.child_by_field_name("name")
                params_node = member.child_by_field_name("parameters")
                if name_node is None or params_node is None:
                    continue
                method_name = document.text_for(name_node).strip()
                params_text = document.text_for(params_node).strip()
                # equals 签名：equals(Object <name>)
                if method_name == "equals" and re.match(r"\(\s*Object\s+[A-Za-z_$][\w$]*\s*\)", params_text):
                    has_equals = True
                    equals_line = document.line_range(member)[0]
                # hashCode 签名：hashCode()
                elif method_name == "hashCode" and params_text == "()":
                    has_hashcode = True
                    hashcode_line = document.line_range(member)[0]
            if has_equals ^ has_hashcode:
                if has_equals:
                    line = equals_line
                    missing = "hashCode()"
                    present = "equals(Object)"
                else:
                    line = hashcode_line
                    missing = "equals(Object)"
                    present = "hashCode()"
                hits.append(RuleHit(
                    JAVA_HASHCODE_EQUALS_MISMATCH, document.relative_path,
                    line, line, language=language,
                    message=(
                        f"Class `{class_name}` overrides `{present}` but not `{missing}` — "
                        f"violates Object contract; HashMap/HashSet behavior will be broken."
                    ),
                    metadata={"class": class_name, "missing": missing},
                ))
        return hits

    # ── JAVA-EQUALS-ON-ARRAY ────────────────────────────────────────────
    # 对已知的数组局部变量 arr 调用 arr.equals(...) 或反向。
    def _scan_java_equals_on_array(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for method_node in self._java_method_nodes(document):
            method_text = document.text_for(method_node)
            # 收集方法内数组类型局部变量（粗粒度 regex）
            # 形式 1: int[] a  / String[] xs / byte[] buf
            # 形式 2: int a[]  （C 风格，较少见；也支持）
            # 不包含多维（简化）
            array_vars: set[str] = set()
            # 形式 1
            for m in re.finditer(
                r"\b(?:int|long|short|byte|char|float|double|boolean|String|Object|[A-Z][\w]*)\s*\[\s*\]\s+(?P<var>[A-Za-z_$][\w$]*)\b",
                method_text,
            ):
                array_vars.add(m.group("var"))
            # 形式 2: T var[]
            for m in re.finditer(
                r"\b(?:int|long|short|byte|char|float|double|boolean|String|Object|[A-Z][\w]*)\s+(?P<var>[A-Za-z_$][\w$]*)\s*\[\s*\]",
                method_text,
            ):
                array_vars.add(m.group("var"))
            if not array_vars:
                continue
            for node in self._walk_nodes(method_node):
                if node.type != "method_invocation":
                    continue
                name_node = node.child_by_field_name("name")
                if name_node is None or document.text_for(name_node).strip() != "equals":
                    continue
                obj_node = node.child_by_field_name("object")
                args_node = node.child_by_field_name("arguments")
                if obj_node is None or args_node is None:
                    continue
                obj_text = document.text_for(obj_node).strip()
                args_named = [c for c in args_node.named_children if c.type != "comment"]
                if len(args_named) != 1:
                    continue
                arg_text = document.text_for(args_named[0]).strip()
                if obj_text in array_vars or arg_text in array_vars:
                    line_start, line_end = document.line_range(node)
                    which = obj_text if obj_text in array_vars else arg_text
                    hits.append(RuleHit(
                        JAVA_EQUALS_ON_ARRAY, document.relative_path,
                        line_start, line_end, language=language,
                        message=(
                            f"`equals` called with array `{which}` — Array.equals is reference "
                            f"comparison; use `Arrays.equals(...)` for element comparison."
                        ),
                        metadata={"var": which},
                    ))
        return hits

    # ── JAVA-INTEGER-BOXING-EQ ──────────────────────────────────────────
    # 方法体内已知的装箱类型局部变量两端用 == / != 比较（排除 null）。
    _JAVA_BOXED_TYPES = frozenset({
        "Integer", "Long", "Double", "Float", "Short", "Byte", "Boolean", "Character",
    })

    def _scan_java_integer_boxing_eq(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for method_node in self._java_method_nodes(document):
            method_text = document.text_for(method_node)
            # 收集装箱类型局部变量；不含泛型/数组
            boxed_vars: set[str] = set()
            type_alt = "|".join(self._JAVA_BOXED_TYPES)
            for m in re.finditer(
                rf"\b(?:{type_alt})\s+(?P<var>[A-Za-z_$][\w$]*)\b(?!\s*\()",
                method_text,
            ):
                boxed_vars.add(m.group("var"))
            if not boxed_vars:
                continue
            for node in self._walk_nodes(method_node):
                if node.type != "binary_expression":
                    continue
                op = node.child_by_field_name("operator")
                if op is None:
                    continue
                if document.text_for(op).strip() not in {"==", "!="}:
                    continue
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None:
                    continue
                left_text = document.text_for(left).strip()
                right_text = document.text_for(right).strip()
                # 排除 == null 合法判空
                if left_text == "null" or right_text == "null":
                    continue
                # 排除两侧都是数字字面量（int 比较，不会装箱）。
                # tree-sitter-java: decimal_integer_literal / hex_integer_literal /
                # decimal_floating_point_literal / character_literal 等。
                _LITERAL_TYPES = {
                    "decimal_integer_literal", "hex_integer_literal",
                    "octal_integer_literal", "binary_integer_literal",
                    "decimal_floating_point_literal", "hex_floating_point_literal",
                    "character_literal", "string_literal", "true", "false",
                }
                if left.type in _LITERAL_TYPES and right.type in _LITERAL_TYPES:
                    continue
                # 至少一侧必须是已知装箱本地变量（identifier 命中 boxed_vars）。
                # 这样 `methodCall() == known_boxed_var` / `arr[i] == known_boxed_var` 等
                # 主流漏报场景能命中，而完全没有装箱上下文的 `a == b` 不会泛滥误报。
                left_is_boxed_id = left.type == "identifier" and left_text in boxed_vars
                right_is_boxed_id = right.type == "identifier" and right_text in boxed_vars
                if not (left_is_boxed_id or right_is_boxed_id):
                    continue
                line_start, line_end = document.line_range(node)
                hits.append(RuleHit(
                    JAVA_INTEGER_BOXING_EQ, document.relative_path,
                    line_start, line_end, language=language,
                    message=(
                        f"`{left_text} {document.text_for(op).strip()} {right_text}` compares boxed "
                        f"numeric references; use `.equals(...)` or `Objects.equals(...)`."
                    ),
                    metadata={"left": left_text, "right": right_text},
                ))
        return hits

    def _java_method_nodes(self, document: TreeSitterDocument) -> list[Node]:
        return [
            node for node in self._walk_nodes(document.root_node)
            if node.type in {"method_declaration", "constructor_declaration"}
        ]

    @staticmethod
    def _java_has_null_check(text: str, var_name: str) -> bool:

        var = re.escape(var_name)
        return re.search(rf"(?:{var}\s*(?:!=|==)\s*null|null\s*(?:!=|==)\s*{var}|Objects\.requireNonNull\s*\(\s*{var}\b|Optional\.ofNullable\s*\(\s*{var}\b)", text) is not None

    @staticmethod
    def _java_expr_is_guarded(text: str, call_text: str) -> bool:
        """Whether a nullable call expression is guarded within the enclosing scope.

        Covers the common Java idiom ``if (map.get(k) != null) { ...map.get(k)... }``
        where the SAME expression is null-checked, and ``map.containsKey(k)`` guards
        for ``map.get(k)`` uses.
        """
        expr = re.escape(call_text)
        if re.search(rf"{expr}\s*(?:!=|==)\s*null", text):
            return True
        if re.search(rf"null\s*(?:!=|==)\s*{expr}", text):
            return True
        # containsKey guard for a `<receiver>.get(<key>)` expression.
        m = re.search(r"^(?P<recv>.+?)\.\s*get\s*\(\s*(?P<key>.+?)\s*\)\s*$", call_text)
        if m:
            recv = re.escape(m.group("recv").strip())
            key = re.escape(m.group("key").strip())
            if re.search(rf"{recv}\s*\.\s*containsKey\s*\(\s*{key}\s*\)", text):
                return True
        return False

    @staticmethod
    def _c_like_has_zero_check(text: str, var_name: str) -> bool:
        var = re.escape(var_name)
        return re.search(rf"(?:{var}\s*(?:!=|==|>|<|>=|<=)\s*0|0\s*(?:!=|==|>|<|>=|<=)\s*{var})", text) is not None

    @staticmethod
    def _java_has_zero_check(text: str, var_name: str) -> bool:

        var = re.escape(var_name)
        return re.search(rf"(?:{var}\s*(?:!=|==|>|<|>=|<=)\s*0|0\s*(?:!=|==|>|<|>=|<=)\s*{var}|Math\.max\s*\(\s*{var}\s*,\s*1\s*\))", text) is not None

    @staticmethod
    def _java_looks_external_numeric(text: str, var_name: str) -> bool:
        var = re.escape(var_name)
        return re.search(rf"\b{var}\s*=\s*(?:[^;]*parse\w+\s*\(|[^;]*\.get\s*\(|[^;]*getProperty\s*\()", text) is not None

    @staticmethod
    def _java_condition_text(line: str) -> str:

        start = line.find("(")
        end = line.rfind(")")
        if start == -1 or end <= start:
            return ""
        return line[start + 1:end]

    # ══════════════════════════════════════════════════════════════
    # C# tree-sitter based detection
    # ══════════════════════════════════════════════════════════════

    # C# IDisposable types that must be in `using` statements
    _CSHARP_DISPOSABLE_TYPES = frozenset({
        "SqlConnection", "SqlCommand", "SqlDataReader", "SqlDataAdapter",
        "NpgsqlConnection", "NpgsqlCommand", "MySqlConnection", "MySqlCommand",
        "DbConnection", "DbCommand", "DbDataReader",
        "StreamReader", "StreamWriter", "FileStream", "MemoryStream",
        "BinaryReader", "BinaryWriter", "TextReader", "TextWriter",
        "HttpClient", "WebClient", "TcpClient", "UdpClient", "NetworkStream",
        "Process", "Timer", "CancellationTokenSource",
        "Bitmap", "Graphics", "Font", "Brush", "Pen",
    })

    def _scan_csharp_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """C#-specific tree-sitter rules."""
        hits: list[RuleHit] = []
        hits.extend(self._scan_csharp_resource_leaks(document, language))
        hits.extend(self._scan_csharp_empty_catch(document, language))
        hits.extend(self._scan_csharp_async_void(document, language))
        hits.extend(self._scan_csharp_null_deref(document, language))
        hits.extend(self._scan_csharp_foreach_collection_mutate(document, language))
        return hits

    def _scan_csharp_resource_leaks(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect IDisposable objects created without `using` statement."""
        hits: list[RuleHit] = []
        all_nodes = self._walk_nodes(document.tree.root_node)
        text = document.source

        for node in all_nodes:
            if node.type != "object_creation_expression":
                continue
            # Get type name
            type_node = node.child_by_field_name("type")
            if not type_node or not type_node.text:
                continue
            type_name = type_node.text.decode("utf-8", errors="ignore")
            # Strip namespace prefix
            short_name = type_name.split(".")[-1] if "." in type_name else type_name

            if short_name not in self._CSHARP_DISPOSABLE_TYPES:
                continue

            # Check if inside a `using` statement or `using` declaration
            parent = node.parent
            in_using = False
            depth = 0
            while parent and depth < 10:
                if parent.type in {"using_statement", "using_declaration"}:
                    in_using = True
                    break
                parent = parent.parent
                depth += 1

            if not in_using:
                # Check if .Dispose() or .Close() called later in same method
                method_node = self._find_enclosing_method_csharp(node)
                if method_node:
                    method_text = method_node.text.decode("utf-8", errors="ignore") if method_node.text else ""
                    if ".Dispose()" in method_text or ".Close()" in method_text:
                        # Has manual close, check if in finally
                        if "finally" in method_text:
                            continue  # OK: disposed in finally
                        # Has close but not guaranteed — weaker rule
                        hits.append(RuleHit(
                            rule=RESOURCE_CLOSE_NOT_GUARANTEED,
                            file_path=document.relative_path,
                            line_start=node.start_point[0] + 1,
                            line_end=node.end_point[0] + 1,
                            message=(
                                f"`new {short_name}()` has Dispose()/Close() call but not in "
                                f"using/finally — resource may leak on exception path."
                            ),
                            language=language,
                        ))
                        continue

                hits.append(RuleHit(
                    rule=RESOURCE_LEAK,
                    file_path=document.relative_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    message=(
                        f"`new {short_name}()` not wrapped in `using` statement — "
                        f"IDisposable resource may leak."
                    ),
                    language=language,
                ))

        return hits

    def _scan_csharp_empty_catch(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect empty catch blocks and catch(Exception) in C#."""
        hits: list[RuleHit] = []
        all_nodes = self._walk_nodes(document.tree.root_node)

        for node in all_nodes:
            if node.type != "catch_clause":
                continue

            # Check for empty catch body (does not preclude broad-except check)
            body = node.child_by_field_name("body")
            if body:
                # Count meaningful statements (not just braces/whitespace)
                statements = [c for c in body.named_children if c.type not in {"comment"}]
                if not statements:
                    hits.append(RuleHit(
                        rule=EMPTY_EXCEPT,
                        file_path=document.relative_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                        message="Empty catch block swallows exception silently.",
                        language=language,
                    ))

            # Check for catch(Exception) — too broad (independent of body emptiness)
            # Use regex on full catch_clause text for robustness across tree-sitter versions.
            if node.text:
                catch_full = node.text.decode("utf-8", errors="ignore")
                # Match catch (Exception ...) / catch (System.Exception ...) — but not SpecificException
                if re.search(r"\bcatch\s*\(\s*(?:System\.)?Exception\b(?!\w)", catch_full):
                    hits.append(RuleHit(
                        rule=BROAD_EXCEPT,
                        file_path=document.relative_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                        message="catch(Exception) is too broad — catches all exceptions including system errors.",
                        language=language,
                    ))

        return hits

    def _scan_csharp_async_void(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect async void methods (fire-and-forget, unobserved exceptions)."""
        hits: list[RuleHit] = []
        all_nodes = self._walk_nodes(document.tree.root_node)

        for node in all_nodes:
            if node.type != "method_declaration":
                continue
            # Check modifiers for async
            text = node.text.decode("utf-8", errors="ignore") if node.text else ""
            first_line = text.split("\n")[0] if text else ""

            if "async" in first_line and "void" in first_line:
                # Allow event handlers (common pattern)
                name_node = node.child_by_field_name("name")
                name = name_node.text.decode("utf-8") if name_node and name_node.text else ""
                if name.startswith("On") or name.endswith("_Click") or name.endswith("Handler"):
                    continue  # Event handler pattern is acceptable

                hits.append(RuleHit(
                    rule=ASYNC_VOID,
                    file_path=document.relative_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    message=f"async void method '{name}' — unobserved exceptions will crash the process.",
                    language=language,
                ))

        return hits

    def _scan_csharp_null_deref(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Detect potential null dereference in C# (basic pattern)."""
        hits: list[RuleHit] = []
        all_nodes = self._walk_nodes(document.tree.root_node)

        for node in all_nodes:
            # Pattern: var x = something that could be null; x.Method() without null check
            if node.type != "invocation_expression":
                continue
            # Check if target is a member access on a potentially nullable variable
            target = node.child_by_field_name("function") or (node.named_children[0] if node.named_children else None)
            if not target or target.type != "member_access_expression":
                continue

            obj = target.child_by_field_name("expression") or (target.named_children[0] if target.named_children else None)
            if not obj or not obj.text:
                continue

            obj_name = obj.text.decode("utf-8", errors="ignore")

            # Simple heuristic: if obj was assigned from a method ending in OrDefault/FirstOrDefault/Find
            # and there's no null check before this line
            method_node = self._find_enclosing_method_csharp(node)
            if not method_node or not method_node.text:
                continue

            method_text = method_node.text.decode("utf-8", errors="ignore")
            # Check if variable was assigned from nullable pattern
            nullable_patterns = [
                f"{obj_name} = ",  # assignment exists
            ]
            nullable_sources = ["FirstOrDefault", "SingleOrDefault", "Find(", "as ", "null"]

            has_nullable_assignment = False
            for line in method_text.splitlines():
                if f"{obj_name} =" in line or f"{obj_name}=" in line:
                    if any(src in line for src in nullable_sources):
                        has_nullable_assignment = True
                        break

            if not has_nullable_assignment:
                continue

            # Check if there's a null check before this usage
            node_line = node.start_point[0] + 1
            preceding = method_text.splitlines()[:node_line - (method_node.start_point[0] + 1)]
            preceding_text = "\n".join(preceding)

            if f"{obj_name} != null" in preceding_text or f"{obj_name} is not null" in preceding_text or f"{obj_name}?" in preceding_text:
                continue  # Has null guard

            hits.append(RuleHit(
                rule=POSSIBLE_NONE_DEREF,
                file_path=document.relative_path,
                line_start=node.start_point[0] + 1,
                line_end=node.end_point[0] + 1,
                message=f"'{obj_name}' may be null (from nullable source) but used without null check.",
                language=language,
            ))

        return hits

    # ── FOREACH-COLLECTION-MUTATE (C#) ──────────────────────────────────
    # foreach (var x in coll) { coll.Add/Remove/Clear/...(...); }
    _CSHARP_MUTATING_METHODS = frozenset({"Add", "AddRange", "Remove", "RemoveAt",
                                           "RemoveAll", "RemoveRange", "Clear", "Insert", "InsertRange"})

    def _scan_csharp_foreach_collection_mutate(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.tree.root_node):
            if node.type != "foreach_statement":
                continue
            # tree-sitter-c-sharp foreach_statement fields:
            #   type=<T>, left=<loopvar>, right=<collection>, body=<block>
            iterable_node = node.child_by_field_name("right")
            body_node = node.child_by_field_name("body")
            if iterable_node is None or body_node is None:
                continue
            coll_text = (iterable_node.text or b"").decode("utf-8", errors="ignore").strip()
            if not re.fullmatch(r"[A-Za-z_][\w]*", coll_text):
                continue
            for inner in self._walk_nodes(body_node):
                if inner.type != "invocation_expression":
                    continue
                fn = inner.child_by_field_name("function") or (
                    inner.named_children[0] if inner.named_children else None
                )
                if fn is None or fn.type != "member_access_expression":
                    continue
                obj_node = fn.child_by_field_name("expression") or (
                    fn.named_children[0] if fn.named_children else None
                )
                name_node = fn.child_by_field_name("name") or (
                    fn.named_children[1] if len(fn.named_children) > 1 else None
                )
                if obj_node is None or name_node is None:
                    continue
                obj_text = (obj_node.text or b"").decode("utf-8", errors="ignore").strip()
                method_text = (name_node.text or b"").decode("utf-8", errors="ignore").strip()
                if obj_text != coll_text or method_text not in self._CSHARP_MUTATING_METHODS:
                    continue
                hits.append(RuleHit(
                    rule=FOREACH_COLLECTION_MUTATE,
                    file_path=document.relative_path,
                    line_start=inner.start_point[0] + 1,
                    line_end=inner.end_point[0] + 1,
                    message=(
                        f"`{coll_text}.{method_text}(...)` inside foreach over `{coll_text}` "
                        f"— InvalidOperationException at runtime."
                    ),
                    language=language,
                ))
        return hits

    def _find_enclosing_method_csharp(self, node) -> "Node | None":
        """Find enclosing method/property/constructor for a C# node."""
        current = node.parent
        depth = 0
        while current and depth < 20:
            if current.type in {"method_declaration", "constructor_declaration", "property_declaration", "accessor_declaration"}:
                return current
            current = current.parent
            depth += 1
        return None

    @staticmethod
    def _walk_nodes(node: Node) -> list[Node]:

        """Iterative pre-order traversal of the tree-sitter AST (avoids deep recursion)."""
        result: list[Node] = []
        stack = [node]
        while stack:
            current = stack.pop()
            result.append(current)
            # Push children in reverse order so leftmost child is processed first
            children = current.named_children
            for i in range(len(children) - 1, -1, -1):
                stack.append(children[i])
        return result

    @staticmethod
    def _first_named_child(node: Node) -> Node | None:
        return node.named_children[0] if node.named_children else None

    @staticmethod
    def _find_child(node: Node, child_type: str) -> Node | None:
        for child in node.named_children:
            if child.type == child_type:
                return child
        return None

    @staticmethod
    def _python_call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = DefectEngine._python_call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _python_exception_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _python_except_is_empty(node: ast.ExceptHandler) -> bool:
        if not node.body:
            return True
        if len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, ast.Pass):
                return True
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                return stmt.value.value in {Ellipsis, None}
        return False

    @staticmethod
    def _python_except_only_logs(node: ast.ExceptHandler) -> bool:
        if not node.body:
            return False
        return all(DefectEngine._python_stmt_is_log_only(stmt) for stmt in node.body)

    @staticmethod
    def _python_stmt_is_log_only(stmt: ast.stmt) -> bool:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return DefectEngine._python_expr_is_log_call(stmt.value)
        return False

    @staticmethod
    def _python_expr_is_log_call(node: ast.Call) -> bool:
        call_name = DefectEngine._python_call_name(node.func)
        if call_name == "print":
            return True
        if isinstance(node.func, ast.Attribute):
            return node.func.attr.lower() in {"debug", "info", "warning", "warn", "error", "exception", "critical"}
        return False

    @staticmethod
    def _first_event_after(lines: list[int], start_line: int, stop_line: int | None) -> int | None:
        for line_no in sorted(lines):
            if line_no < start_line:
                continue
            if stop_line is not None and line_no >= stop_line:
                break
            return line_no
        return None

    @staticmethod
    def _python_resource_factory_name(node: ast.Call) -> str | None:
        call_name = DefectEngine._python_call_name(node.func)
        if call_name in _PYTHON_RESOURCE_FACTORY_CALLS:
            return call_name
        if isinstance(node.func, ast.Attribute) and node.func.attr == "open":
            return call_name or "open"
        return None

    @staticmethod
    def _python_resource_close_name(node: ast.Call) -> str | None:
        if not isinstance(node.func, ast.Attribute):
            return None
        if node.func.attr not in _PYTHON_RESOURCE_CLOSE_METHODS:
            return None
        if isinstance(node.func.value, ast.Name):
            return node.func.value.id
        return None

    @staticmethod
    def _python_transferred_resource_names(node: ast.expr | None) -> set[str]:
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            return {node.id}
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            names: set[str] = set()
            for element in node.elts:
                names.update(DefectEngine._python_transferred_resource_names(element))
            return names
        if isinstance(node, ast.Dict):
            names: set[str] = set()
            for key in node.keys:
                names.update(DefectEngine._python_transferred_resource_names(key))
            for value in node.values:
                names.update(DefectEngine._python_transferred_resource_names(value))
            return names
        return set()

    @staticmethod
    def _python_assignment_names(target: ast.expr) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            names: set[str] = set()
            for element in target.elts:
                names.update(DefectEngine._python_assignment_names(element))
            return names
        return set()

    @staticmethod
    def _scan_tree_syntax_errors(document: TreeSitterDocument, language: str) -> list[RuleHit]:

        root = document.root_node
        if not getattr(root, "has_error", False):
            return []
        for node in DefectEngine._walk_nodes(root):
            if getattr(node, "is_error", False) or getattr(node, "is_missing", False) or node.type == "ERROR":
                line_start, line_end = document.line_range(node)
                return [
                    RuleHit(
                        SYNTAX_ERROR,
                        document.relative_path,
                        line_start,
                        line_end,
                        language=language,
                        message=f"{language} parser found invalid or incomplete syntax near this node.",
                    )
                ]
        return [
            RuleHit(
                SYNTAX_ERROR,
                document.relative_path,
                1,
                1,
                language=language,
                message=f"{language} parser reported syntax errors in this file.",
            )
        ]


class _PythonResourceScopeCollector(ast.NodeVisitor):
    """Collect resource lifecycle events from a single Python scope."""

    def __init__(self) -> None:
        self.acquisitions: list[tuple[str, int, str]] = []
        self.reassignments: dict[str, list[int]] = {}
        self.closes: dict[str, list[int]] = {}
        self.transfers: dict[str, list[int]] = {}

    def collect(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.visit(stmt)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        names: set[str] = set()
        for target in node.targets:
            names.update(DefectEngine._python_assignment_names(target))
        self._record_reassignments(names, node.lineno)
        if isinstance(node.value, ast.Call):
            factory_name = DefectEngine._python_resource_factory_name(node.value)
            if factory_name is not None:
                for name in sorted(names):
                    self.acquisitions.append((name, node.lineno, factory_name))
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        names = DefectEngine._python_assignment_names(node.target)
        self._record_reassignments(names, node.lineno)
        if isinstance(node.value, ast.Call):
            factory_name = DefectEngine._python_resource_factory_name(node.value)
            if factory_name is not None:
                for name in sorted(names):
                    self.acquisitions.append((name, node.lineno, factory_name))
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._record_reassignments(DefectEngine._python_assignment_names(node.target), node.lineno)
        self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        close_name = DefectEngine._python_resource_close_name(node)
        if close_name is not None:
            self.closes.setdefault(close_name, []).append(node.lineno)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        for name in DefectEngine._python_transferred_resource_names(node.value):
            self.transfers.setdefault(name, []).append(node.lineno)
        if node.value is not None:
            self.visit(node.value)

    def _record_reassignments(self, names: set[str], line_no: int) -> None:
        for name in names:
            self.reassignments.setdefault(name, []).append(line_no)

