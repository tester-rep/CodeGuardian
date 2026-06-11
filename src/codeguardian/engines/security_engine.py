"""SecurityEngine — detects security vulnerabilities.

Dimension 10: Security Analyzer
Uses AST-enhanced rules with regex fallback for broad language coverage.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from codeguardian.core.context import ScanContext
from codeguardian.engines.python_taint import PythonTaintAnalyzer, PythonTaintRules
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


SUPPORTED_SECURITY_LANGUAGES = {
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "cpp",
    "csharp",
    "lua",
    "rust",
    "ruby",
}
LANGUAGE_BY_SUFFIX = {
    suffix: language
    for suffix, language in EXTENSION_LANGUAGE_MAP.items()
    if language in SUPPORTED_SECURITY_LANGUAGES
}
SUPPORTED_EXTENSIONS = set(LANGUAGE_BY_SUFFIX)
SENSITIVE_NAME_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|credential|api[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)
SQL_CALL_RE = re.compile(r"(?:^|\.)(?:execute|executeQuery|executeUpdate|query|raw|exec|sqlite3_exec|ExecuteNonQuery|ExecuteReader|ExecuteScalar)$", re.IGNORECASE)
STRING_LITERAL_RE = re.compile(r"^\s*(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')\s*$")
BACKTICK_LITERAL_RE = re.compile(r"^\s*`(?:\\.|[^`$]|\$(?!\{))*`\s*$")
C_LIKE_SYSTEM_DECLARATION_RE = re.compile(
    r"^\s*(?:extern\s+)?(?:[\w:<>]+\s+)*[\w:<>]+\s*(?:\*+\s*)?(?:std::)?system\s*\([^;{}]*\)\s*;\s*$",
    re.IGNORECASE,
)
JS_EXEC_CALL_RE = re.compile(r"\b(?:exec|execSync)\s*\((?P<arg>[^)]*)\)", re.IGNORECASE)
JAVA_RUNTIME_EXEC_RE = re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\((?P<arg>[^)]*)\)", re.IGNORECASE)
C_SYSTEM_CALL_RE = re.compile(r"\b(?:std::)?system\s*\((?P<arg>[^)]*)\)", re.IGNORECASE)
GO_EXEC_COMMAND_RE = re.compile(
    r"\bexec\.Command\s*\(\s*[\"']sh[\"']\s*,\s*[\"']-c[\"']\s*,\s*(?P<arg>[^)]*)\)",
    re.IGNORECASE,
)
CSHARP_PROCESS_START_RE = re.compile(r"\bProcess\.Start\s*\((?P<arg>[^)]*)\)", re.IGNORECASE)
LUA_OS_EXECUTE_RE = re.compile(r"\bos\.execute\s*\((?P<arg>[^)]*)\)", re.IGNORECASE)
RUST_COMMAND_NEW_RE = re.compile(r"\bCommand::new\s*\(\s*[\"']sh[\"']\s*\)(?P<chain>.*)", re.IGNORECASE)
RUST_ARG_CALL_RE = re.compile(r"\.arg\s*\(\s*(?P<arg>[^)]*)\)")


HARDCODED_PASSWORD = RuleSpec(
    rule_id="HARDCODED-PASSWORD",
    title="检测到硬编码凭据 (Hardcoded credential or secret detected)",
    category="security",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    fix_suggestion="将凭据移到环境变量、密钥管理服务或未提交到版本控制的 .env 文件中。",
    blocks_release=True,
    risk_priority="must-fix",
    tags=("security", "secrets"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp", "lua", "rust", "ruby"),
    cwe_ids=("CWE-798",),
    owasp=("A07:2021",),
    description_zh="代码中硬编码了密码、API 密钥或其他敏感凭据。一旦代码被泄露（如上传到公开仓库），攻击者可以直接获取这些凭据，造成数据泄露或系统被入侵。",
    reference_url="https://cwe.mitre.org/data/definitions/798.html",
)
SQL_INJECTION_RISK = RuleSpec(
    rule_id="SQL-INJECTION-RISK",
    title="潜在 SQL 注入风险 (Potential SQL injection)",
    category="security",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    fix_suggestion="使用参数化查询或预编译语句（Prepared Statement），避免通过字符串拼接/格式化构建 SQL。",
    risk_priority="must-fix",
    blocks_release=True,
    tags=("security", "sql"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp", "lua", "rust", "ruby"),
    cwe_ids=("CWE-89",),
    owasp=("A03:2021",),
    description_zh="通过字符串拼接或格式化构造 SQL 查询语句，外部输入可能被注入恶意 SQL 片段。SQL 注入（SQL Injection）是 Web 安全最常见也最危险的漏洞之一，可导致数据泄露、篡改甚至整个数据库被删除。",
    reference_url="https://cwe.mitre.org/data/definitions/89.html",
)
EVAL_USAGE = RuleSpec(
    rule_id="EVAL-USAGE",
    title="使用了动态代码执行 API (Dynamic code execution)",
    category="security",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="用更安全的解析方式或显式分发逻辑替代 eval/exec/new Function。",
    risk_priority="must-fix",
    tags=("security", "code-injection"),
    applicable_languages=("python", "javascript", "typescript", "lua"),
    cwe_ids=("CWE-95",),
    owasp=("A03:2021",),
    description_zh="使用了 eval()/exec()/new Function() 等动态代码执行 API。如果传入参数可被外部控制，攻击者可以注入任意代码执行（Remote Code Execution），这是最高危的安全漏洞类型之一。",
    reference_url="https://cwe.mitre.org/data/definitions/95.html",
)
WEAK_HASH = RuleSpec(
    rule_id="WEAK-HASH",
    title="检测到弱哈希算法 (Weak hash algorithm)",
    category="security",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="在安全敏感场景中使用 SHA-256 或更强的哈希算法。",
    risk_priority="should-fix",
    tags=("security", "crypto"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp"),
    cwe_ids=("CWE-327",),
    owasp=("A02:2021",),
    description_zh="使用了已知存在碰撞攻击的弱哈希算法（如 MD5、SHA-1）。在密码存储、数字签名、完整性校验等安全场景中，弱哈希算法已不再安全，攻击者可以伪造哈希碰撞。",
    reference_url="https://cwe.mitre.org/data/definitions/327.html",
)
INSECURE_RANDOM = RuleSpec(
    rule_id="INSECURE-RANDOM",
    title="安全场景使用了不安全的伪随机数生成器 (Insecure PRNG)",
    category="security",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="使用密码学安全的随机数生成器，如 secrets、crypto.randomBytes 或 SecureRandom。",
    risk_priority="should-fix",
    tags=("security", "crypto"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp", "lua"),
    cwe_ids=("CWE-338",),
    owasp=("A02:2021",),
    description_zh="在可能涉及安全的场景中使用了非密码学安全的伪随机数生成器（如 random.random()、Math.random()）。这类 PRNG 的输出可被预测，不应用于生成 token、密钥、验证码等安全敏感值。",
    reference_url="https://cwe.mitre.org/data/definitions/338.html",
)
PATH_TRAVERSAL_RISK = RuleSpec(
    rule_id="PATH-TRAVERSAL-RISK",
    title="潜在路径穿越风险 (Potential path traversal)",
    category="security",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="在文件访问前对用户可控路径进行校验和归一化，使用白名单限制可访问范围。",
    risk_priority="must-fix",
    tags=("security", "filesystem"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp", "lua", "rust"),
    cwe_ids=("CWE-22",),
    owasp=("A01:2021",),
    description_zh="文件路径由外部输入动态构造，攻击者可通过 ../（路径遍历）访问系统任意文件。路径穿越（Path Traversal）可导致敏感文件泄露（如 /etc/passwd、配置文件中的密钥等）。",
    reference_url="https://cwe.mitre.org/data/definitions/22.html",
)
COMMAND_INJECTION_RISK = RuleSpec(
    rule_id="COMMAND-INJECTION-RISK",
    title="潜在命令注入风险 (Potential command injection)",
    category="security",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    fix_suggestion="避免对用户可控数据执行 shell 命令；优先使用参数数组并进行显式校验。",
    risk_priority="must-fix",
    blocks_release=True,
    tags=("security", "command-exec"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp", "lua", "rust"),
    cwe_ids=("CWE-78",),
    owasp=("A03:2021",),
    description_zh="通过 shell 执行 API（如 os.system()、subprocess + shell=True、exec()）执行了包含外部输入的命令。攻击者可注入任意系统命令（Command Injection / OS Command Injection），完全控制服务器。",
    reference_url="https://cwe.mitre.org/data/definitions/78.html",
)
UNSAFE_DESERIALIZATION = RuleSpec(
    rule_id="UNSAFE-DESERIALIZATION",
    title="检测到不安全的反序列化 API (Unsafe deserialization)",
    category="security",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="使用安全的加载器/解析器；切勿对不可信数据使用 pickle/yaml.load；Java 中禁用 fastjson autoType、关闭 Jackson enableDefaultTyping/TypeNameHandling，避免 ObjectInputStream 反序列化外部输入。",
    risk_priority="must-fix",
    blocks_release=True,
    tags=("security", "deserialization"),
    applicable_languages=("python", "java", "csharp", "javascript", "typescript"),
    cwe_ids=("CWE-502",),
    owasp=("A08:2021",),
    description_zh="使用了不安全的反序列化 API（如 pickle.load、yaml.load 无 SafeLoader、fastjson autoType、Jackson enableDefaultTyping、Java ObjectInputStream、.NET BinaryFormatter）。如果反序列化的数据来自不可信来源，攻击者可以构造恶意 payload 实现远程代码执行（Insecure Deserialization / RCE）。",
    reference_url="https://cwe.mitre.org/data/definitions/502.html",
)

WEAK_CIPHER = RuleSpec(
    rule_id="WEAK-CIPHER",
    title="检测到弱加密算法或不安全的分组模式 (Weak cipher or insecure mode)",
    category="security",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="使用 AES-GCM / AES-CBC + 随机 IV + HMAC，避免 DES/3DES/RC4 与 ECB 模式；Java 推荐 `Cipher.getInstance(\"AES/GCM/NoPadding\")`。",
    risk_priority="must-fix",
    tags=("security", "crypto"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "cpp", "csharp"),
    cwe_ids=("CWE-327", "CWE-326"),
    owasp=("A02:2021",),
    description_zh="使用了已被证明不安全的对称加密算法（DES/3DES/RC4）或不安全的分组模式（ECB）。这些算法/模式存在已知攻击（密钥太短、明文模式泄漏、字典攻击），不适用于任何敏感数据加密场景。",
    reference_url="https://cwe.mitre.org/data/definitions/327.html",
)

INSECURE_TLS_VERIFICATION = RuleSpec(
    rule_id="INSECURE-TLS-VERIFICATION",
    title="禁用了 TLS/SSL 证书校验 (TLS certificate verification disabled)",
    category="security",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    fix_suggestion="移除 TrustAll/InsecureSkipVerify/rejectUnauthorized=false 等绕过逻辑；使用系统 CA 校验或显式固定可信证书。",
    risk_priority="must-fix",
    blocks_release=True,
    tags=("security", "tls", "network"),
    applicable_languages=("python", "java", "javascript", "typescript", "go", "csharp"),
    cwe_ids=("CWE-295",),
    owasp=("A02:2021",),
    description_zh="代码中显式禁用了 TLS/SSL 证书校验（如 Java TrustManager 全信任、HostnameVerifier ALLOW_ALL、Go InsecureSkipVerify=true、Node rejectUnauthorized:false、Python verify=False、.NET ServerCertificateValidationCallback 始终返回 true）。这会让通信完全暴露于中间人攻击（MITM），攻击者可窃听甚至篡改流量。",
    reference_url="https://cwe.mitre.org/data/definitions/295.html",
)

SSRF_RISK = RuleSpec(
    rule_id="SSRF-RISK",
    title="服务端请求伪造风险 (Server-Side Request Forgery)",
    category="security",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="对用户提供的 URL 进行白名单校验（允许的域名/IP），禁止访问内网地址（127.0.0.1、10.x、172.16.x、169.254.x）。",
    blocks_release=False,
    risk_priority="should-fix",
    tags=("security", "ssrf", "network", "input-validation"),
    applicable_languages=("python", "java", "javascript", "typescript", "go"),
    cwe_ids=("CWE-918",),
    owasp=("A10:2021",),
    description_zh="将用户可控的输入直接作为 HTTP 请求目标 URL，攻击者可利用此漏洞访问内网服务、云元数据接口（如 169.254.169.254）或探测内部网络。",
    reference_url="https://cwe.mitre.org/data/definitions/918.html",
)

SECURITY_RULES = register_rules(
    "security",
    (
        HARDCODED_PASSWORD,
        SQL_INJECTION_RISK,
        EVAL_USAGE,
        WEAK_HASH,
        WEAK_CIPHER,
        INSECURE_RANDOM,
        PATH_TRAVERSAL_RISK,
        COMMAND_INJECTION_RISK,
        UNSAFE_DESERIALIZATION,
        INSECURE_TLS_VERIFICATION,
        SSRF_RISK,
    ),
)

PYTHON_TAINT_RULE_IDS = {
    SQL_INJECTION_RISK.rule_id,
    COMMAND_INJECTION_RISK.rule_id,
    PATH_TRAVERSAL_RISK.rule_id,
}

# HTTP calls that take a URL as first argument — for SSRF detection
_HTTP_SSRF_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.options", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.patch", "httpx.head", "httpx.options", "httpx.request",
    "urllib.request.urlopen", "urlopen",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
}
PYTHON_TAINT_RULES = PythonTaintRules(
    sql=SQL_INJECTION_RISK,
    command=COMMAND_INJECTION_RISK,
    path=PATH_TRAVERSAL_RISK,
)

REGEX_RULES: list[tuple[RuleSpec, re.Pattern[str]]] = [
    (
        HARDCODED_PASSWORD,
        re.compile(
            r"(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|credential)\w*\s*(?::=|[:=])\s*[\"'][^\"']{4,}[\"']",
            re.IGNORECASE,
        ),
    ),
    (
        SQL_INJECTION_RISK,
        re.compile(
            r"(?:(?:cursor|conn|connection|db|database|session|stmt|statement|command|cmd|ctx|tx|txn|repo|dao|mapper|jdbc|sqlite)\s*[\.\->]+\s*)?(?:execute|executeQuery|executeUpdate|executeNonQuery|rawQuery|query|raw|sqlite3_exec)\w*\s*\([^\n]*(?:\+|\.\.|fmt\.Sprintf|string\.Format|`[^`]*\$\{)",
            re.IGNORECASE,
        ),
    ),
    (
        SQL_INJECTION_RISK,
        re.compile(
            r"(?:commandtext|sql)\s*=\s*[\"'](?:select|insert|update|delete)[^\n]*(?:\+|\.\.|fmt\.Sprintf|string\.Format)",
            re.IGNORECASE,
        ),
    ),
    (
        EVAL_USAGE,
        re.compile(r"\beval\s*\(|\bexec\s*\(|\bnew\s+Function\s*\(|\bloadstring\s*\(", re.IGNORECASE),
    ),
    (
        WEAK_HASH,
        re.compile(
            r"hashlib\.(?:md5|sha1)|createHash\s*\(\s*[\"'](?:md5|sha1)[\"']|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-1)[\"']|\b(?:md5|sha1)\.(?:New|Sum)\s*\(|\b(?:MD5|SHA1)\.Create\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        INSECURE_RANDOM,
        re.compile(
            r"\brandom\.(?:random|randint|randrange|choice|choices)\s*\(|\bMath\.random\s*\(|\bnew\s+Random\s*\(|\brand\.(?:Int|Intn|Int31|Int63|Uint32|Uint64|Float32|Float64)\s*\(|\bmath\.random\s*\(|\brand\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        PATH_TRAVERSAL_RISK,
        re.compile(
            r"(?:open|readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|os\.Open|os\.ReadFile|File\.(?:OpenRead|ReadAllText|WriteAllText)|std::(?:ifstream|ofstream)|fopen|io\.open|fs::read_to_string|File::open)\s*\([^\n]*(?:\+|\.\.|fmt\.Sprintf|string\.Format|`[^`]*\$\{|to_string\(\)\s*\+)",
            re.IGNORECASE,
        ),
    ),

    (
        UNSAFE_DESERIALIZATION,
        re.compile(
            # Python: pickle / yaml.load(无 SafeLoader) / marshal
            r"\bpickle\.loads?\s*\("
            r"|\byaml\.load\s*\((?![^)]*Loader\s*=\s*[\w.]*Safe)"
            r"|\bmarshal\.loads?\s*\("
            # Java fastjson: JSON.parseObject(json, Object.class) / 启用 AutoType
            r"|\bJSON\.parseObject\s*\([^)]*,\s*Object\.class"
            r"|\bParserConfig\.getGlobalInstance\(\)\.setAutoTypeSupport\s*\(\s*true"
            # Java Jackson: enableDefaultTyping / TypeNameHandling.* / activateDefaultTyping
            r"|\benableDefaultTyping\s*\("
            r"|\bactivateDefaultTyping\s*\("
            r"|TypeNameHandling\s*\.\s*(?:All|Objects|Auto|Arrays)"
            # Java 原生反序列化
            r"|\bnew\s+ObjectInputStream\s*\("
            # .NET BinaryFormatter / NetDataContractSerializer / SoapFormatter / LosFormatter
            # 这几个类本身就是 .NET 已弃用 / 标记 [Obsolete] 的危险反序列化器
            r"|\bnew\s+(?:BinaryFormatter|SoapFormatter|LosFormatter|ObjectStateFormatter)\s*\("
            r"|\bNetDataContractSerializer\b"
            # Node.js node-serialize / unserialize
            r"|\bunserialize\s*\(",
            re.IGNORECASE,
        ),
    ),
    # WEAK-CIPHER: DES/3DES/RC4 与 ECB 模式（与 WEAK-HASH 区分：MD5/SHA1 仍归 WEAK-HASH）
    (
        WEAK_CIPHER,
        re.compile(
            # Java: Cipher.getInstance("DES" | "DESede" | "RC4" | "AES/ECB/...")
            r"Cipher\.getInstance\s*\(\s*[\"'](?:DES|DESede|TripleDES|RC4|ARCFOUR)\b"
            r"|Cipher\.getInstance\s*\(\s*[\"'][^\"']*?/ECB/"
            # Python pycryptodome / cryptography: DES.new / ARC4.new / mode=ECB
            r"|\b(?:DES|DES3|ARC4|RC4)\.new\s*\("
            r"|\bmodes?\.ECB\s*\("
            r"|\bMODE_ECB\b"
            # Go: des.NewCipher / des.NewTripleDESCipher / rc4.NewCipher
            r"|\bdes\.New(?:TripleDES)?Cipher\s*\("
            r"|\brc4\.NewCipher\s*\("
            # Node.js: crypto.createCipheriv("des-...", "rc4", "...-ecb")
            r"|createCipher(?:iv)?\s*\(\s*[\"'](?:des|des3|3des|rc4|arc4|[\w-]*-ecb)\b"
            # .NET: new DESCryptoServiceProvider() / TripleDESCryptoServiceProvider / RC2 / Mode = CipherMode.ECB
            r"|new\s+(?:DES|TripleDES|RC2|RC4)CryptoServiceProvider\s*\("
            r"|CipherMode\.ECB",
            re.IGNORECASE,
        ),
    ),
    # INSECURE-TLS-VERIFICATION: TrustAll / InsecureSkipVerify / rejectUnauthorized:false / verify=False
    (
        INSECURE_TLS_VERIFICATION,
        re.compile(
            # Go: tls.Config{InsecureSkipVerify: true}
            r"InsecureSkipVerify\s*:\s*true"
            # Node.js / fetch: rejectUnauthorized: false   或 NODE_TLS_REJECT_UNAUTHORIZED = "0"
            r"|rejectUnauthorized\s*:\s*false"
            r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0[\"']?"
            # Python requests / urllib3: verify=False / disable_warnings
            r"|requests?\.\w+\s*\([^)]*\bverify\s*=\s*False"
            r"|Session\s*\(\s*\)\.\w+\s*\([^)]*\bverify\s*=\s*False"
            r"|\bssl\._create_unverified_context\s*\("
            # Java: TrustManager 永远信任 / HostnameVerifier ALLOW_ALL / NoopHostnameVerifier
            r"|checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}"
            r"|ALLOW_ALL_HOSTNAME_VERIFIER"
            r"|new\s+NoopHostnameVerifier\s*\("
            r"|setHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true\s*\)"
            # .NET: ServicePointManager / HttpClientHandler 总返回 true
            r"|ServerCertificateValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true"
            r"|ServerCertificateCustomValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true",
            re.IGNORECASE,
        ),
    ),
]


class SecurityEngine:
    """Detect security vulnerabilities using AST-enhanced and regex rules."""

    name = "security"

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
            hits = filter_rule_hits(hits, ctx.config.rules)

            seen: set[tuple[str, str, int, int]] = set()
            for hit in hits:
                key = (hit.rule.rule_id, hit.file_path, hit.line_start, hit.line_end)
                if key in seen:
                    continue
                seen.add(key)
                counter += 1
                findings.append(build_finding(hit, lines, f"SEC-{counter:03d}", self.name))

        return EngineResult(engine_name=self.name, findings=findings)

    # Languages for which tree-sitter AST analysis already covers certain regex rules.
    # When a language is in this set, we skip regex-based detection for the corresponding
    # rule_ids to avoid double-counting.
    _AST_COVERED_LANGUAGES = frozenset({"java", "javascript", "typescript", "cpp", "go"})
    _AST_COVERED_RULES = frozenset({
        "HARDCODED-PASSWORD", "COMMAND-INJECTION-RISK", "WEAK-HASH", "INSECURE-RANDOM",
    })

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
        if language not in {"java", "javascript", "typescript", "cpp", "go"}:
            return []

        document = get_tree_sitter_document(src_file, root, language)
        if document is None:
            return []
        if language == "java":
            return self._scan_java_tree(document, language)
        if language in {"javascript", "typescript"}:
            return self._scan_javascript_tree(document, language)
        if language == "cpp":
            return self._scan_cpp_tree(document, language)
        if language == "go":
            return self._scan_go_tree(document, language)
        return []

    @classmethod
    def _scan_regex(cls, lines: list[str], rel_path: str, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for line_no, line in enumerate(lines, start=1):
            for rule, pattern in REGEX_RULES:
                if language == "python" and rule.rule_id in PYTHON_TAINT_RULE_IDS:
                    continue
                # Skip rules already covered by tree-sitter AST analysis for C++/Go
                if language in cls._AST_COVERED_LANGUAGES and rule.rule_id in cls._AST_COVERED_RULES:
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
            command_hit = cls._scan_command_injection_regex(line, rel_path, line_no, language)
            if command_hit is not None:
                hits.append(command_hit)
        return hits


    def _scan_python_ast(self, content: str, rel_path: str, language: str) -> list[RuleHit]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        hits = PythonTaintAnalyzer(rel_path, PYTHON_TAINT_RULES).analyze_module(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                names: list[str] = []
                for target in node.targets:
                    names.extend(self._python_assignment_names(target))
                if self._contains_sensitive_name(names) and self._is_string_literal(node.value):
                    hits.append(RuleHit(HARDCODED_PASSWORD, rel_path, node.lineno, node.lineno, language=language))
            elif isinstance(node, ast.AnnAssign):
                names = self._python_assignment_names(node.target)
                if self._contains_sensitive_name(names) and self._is_string_literal(node.value):
                    hits.append(RuleHit(HARDCODED_PASSWORD, rel_path, node.lineno, node.lineno, language=language))
            elif isinstance(node, ast.Call):
                call_name = self._python_call_name(node.func)
                if call_name in {"eval", "exec"}:
                    hits.append(RuleHit(EVAL_USAGE, rel_path, node.lineno, node.lineno, language=language))
                if call_name in {"pickle.load", "pickle.loads", "yaml.load", "marshal.load", "marshal.loads"}:
                    hits.append(RuleHit(UNSAFE_DESERIALIZATION, rel_path, node.lineno, node.lineno, language=language))
                if call_name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
                    hits.append(RuleHit(WEAK_HASH, rel_path, node.lineno, node.lineno, language=language))
                if call_name.startswith("random.") and call_name.rsplit(".", maxsplit=1)[-1] in {
                    "random",
                    "randint",
                    "randrange",
                    "choice",
                    "choices",
                }:
                    hits.append(RuleHit(INSECURE_RANDOM, rel_path, node.lineno, node.lineno, language=language))
                # SSRF: HTTP call with variable URL (not string literal)
                if call_name in _HTTP_SSRF_CALLS and node.args:
                    first_arg = node.args[0]
                    if not isinstance(first_arg, ast.Constant):
                        # URL is a variable/expression → potential SSRF
                        hits.append(RuleHit(SSRF_RISK, rel_path, node.lineno, node.lineno, language=language,
                                           message=f"HTTP call '{call_name}' with non-constant URL — potential SSRF"))
        return hits

    def _scan_javascript_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is not None and value_node is not None:
                    name = document.text_for(name_node).strip()
                    if self._contains_sensitive_name([name]) and self._is_js_literal(value_node, document):
                        hits.append(
                            RuleHit(HARDCODED_PASSWORD, document.relative_path, line_start, line_end, language=language)
                        )
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    name = document.text_for(left).strip()
                    if self._contains_sensitive_name([name]) and self._is_js_literal(right, document):
                        hits.append(
                            RuleHit(HARDCODED_PASSWORD, document.relative_path, line_start, line_end, language=language)
                        )
            elif node.type == "new_expression":
                constructor = node.child_by_field_name("constructor") or self._first_named_child(node)
                if constructor is not None and document.text_for(constructor).strip() == "Function":
                    hits.append(RuleHit(EVAL_USAGE, document.relative_path, line_start, line_end, language=language))
            elif node.type == "call_expression":
                function_node = node.child_by_field_name("function") or self._first_named_child(node)
                callee = document.text_for(function_node).strip() if function_node is not None else ""
                arguments = self._argument_nodes(node)
                if callee == "eval":
                    hits.append(RuleHit(EVAL_USAGE, document.relative_path, line_start, line_end, language=language))
                if callee.endswith(("exec", "execSync")) and self._is_js_command_argument_risky(arguments, document):
                    hits.append(
                        RuleHit(
                            COMMAND_INJECTION_RISK,
                            document.relative_path,
                            line_start,
                            line_end,
                            message="Detected shell execution with a non-literal command argument",
                            language=language,
                        )
                    )
                if callee == "Math.random":

                    hits.append(RuleHit(INSECURE_RANDOM, document.relative_path, line_start, line_end, language=language))
                if self._looks_like_sql_call(callee) and arguments and self._is_js_dynamic_value(arguments[0], document):
                    hits.append(
                        RuleHit(SQL_INJECTION_RISK, document.relative_path, line_start, line_end, language=language)
                    )
                if callee.endswith("createHash") and arguments and self._is_weak_hash_literal(arguments[0], document):
                    hits.append(RuleHit(WEAK_HASH, document.relative_path, line_start, line_end, language=language))
                if callee.endswith(("readFile", "readFileSync", "writeFile", "writeFileSync", "open", "createReadStream")) and arguments and self._is_js_dynamic_value(arguments[0], document):
                    hits.append(
                        RuleHit(PATH_TRAVERSAL_RISK, document.relative_path, line_start, line_end, language=language)
                    )

        return hits

    def _scan_java_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            text = document.text_for(node)
            if node.type in {"field_declaration", "local_variable_declaration"}:
                for child in node.named_children:
                    if child.type != "variable_declarator":
                        continue
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node is None or value_node is None:
                        continue
                    name = document.text_for(name_node).strip()
                    if self._contains_sensitive_name([name]) and self._is_java_literal(value_node, document):
                        hits.append(
                            RuleHit(HARDCODED_PASSWORD, document.relative_path, line_start, line_end, language=language)
                        )
            elif node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                callee = document.text_for(name_node).strip() if name_node is not None else text
                arguments = self._argument_nodes(node)
                if (callee == "exec" or "Runtime.getRuntime().exec" in text) and self._is_java_command_argument_risky(arguments, document):
                    hits.append(
                        RuleHit(
                            COMMAND_INJECTION_RISK,
                            document.relative_path,
                            line_start,
                            line_end,
                            message="Detected shell execution with a non-literal command argument",
                            language=language,
                        )
                    )
                if self._looks_like_sql_call(callee) and arguments and arguments[0].type == "binary_expression":

                    hits.append(
                        RuleHit(SQL_INJECTION_RISK, document.relative_path, line_start, line_end, language=language)
                    )
                if "MessageDigest.getInstance" in text and arguments and self._is_weak_hash_literal(arguments[0], document):
                    hits.append(RuleHit(WEAK_HASH, document.relative_path, line_start, line_end, language=language))
            elif node.type == "object_creation_expression":
                if "new Random(" in text:
                    hits.append(RuleHit(INSECURE_RANDOM, document.relative_path, line_start, line_end, language=language))
                if text.strip().startswith("new File("):
                    arguments = self._argument_nodes(node)
                    if arguments and arguments[0].type != "string_literal":
                        hits.append(
                            RuleHit(PATH_TRAVERSAL_RISK, document.relative_path, line_start, line_end, language=language)
                        )
        return hits

    # ════════════════════════════════════════════════════════════════════
    # C++ tree-sitter deep security analysis
    # ════════════════════════════════════════════════════════════════════

    # C++ weak hash function names
    _CPP_WEAK_HASH_CALLS = frozenset({"MD5", "SHA1", "md5", "sha1", "MD5_Init", "SHA1_Init"})
    # C++ insecure random calls
    _CPP_INSECURE_RANDOM_CALLS = frozenset({"rand", "srand", "random", "srandom"})

    def _scan_cpp_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Deep C++ security detection using tree-sitter."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            text = document.text_for(node)

            # 1. Hardcoded passwords in variable declarations
            if node.type == "declaration":
                for child in node.named_children:
                    if child.type != "init_declarator":
                        continue
                    decl_node = child.child_by_field_name("declarator")
                    value_node = child.child_by_field_name("value")
                    if decl_node is None or value_node is None:
                        continue
                    var_name = document.text_for(decl_node).strip().lstrip("*").strip()
                    if self._contains_sensitive_name([var_name]) and self._is_cpp_string_literal(value_node, document):
                        hits.append(RuleHit(
                            HARDCODED_PASSWORD, document.relative_path, line_start, line_end, language=language,
                        ))

            # 2. Command injection: system() with non-literal argument
            elif node.type == "call_expression":
                fn_node = node.child_by_field_name("function")
                if fn_node is None:
                    continue
                fn_text = document.text_for(fn_node).strip()
                arguments = self._argument_nodes(node)

                # system()/popen() with dynamic argument
                if fn_text in {"system", "std::system", "popen", "_popen"}:
                    if self._looks_like_c_system_declaration_node(node):
                        pass  # Skip function declarations
                    elif arguments and not self._is_cpp_literal_node(arguments[0], document):
                        hits.append(RuleHit(
                            COMMAND_INJECTION_RISK, document.relative_path, line_start, line_end,
                            language=language,
                            message=f"Detected `{fn_text}()` with a non-literal command argument.",
                        ))

                # Weak hash: MD5_Init, SHA1_Init, etc.
                if fn_text.split("::")[-1] in self._CPP_WEAK_HASH_CALLS:
                    hits.append(RuleHit(
                        WEAK_HASH, document.relative_path, line_start, line_end, language=language,
                    ))

                # Insecure random: rand(), srand(), random()
                if fn_text in self._CPP_INSECURE_RANDOM_CALLS:
                    hits.append(RuleHit(
                        INSECURE_RANDOM, document.relative_path, line_start, line_end, language=language,
                    ))

        return hits

    # ════════════════════════════════════════════════════════════════════
    # Go tree-sitter deep security analysis
    # ════════════════════════════════════════════════════════════════════

    # Go weak hash factory calls
    _GO_WEAK_HASH_CALLS = frozenset({"md5.New", "md5.Sum", "sha1.New", "sha1.Sum"})
    # Go insecure random calls
    _GO_INSECURE_RANDOM_CALLS = frozenset({
        "rand.Int", "rand.Intn", "rand.Int31", "rand.Int63",
        "rand.Uint32", "rand.Uint64", "rand.Float32", "rand.Float64",
    })

    def _scan_go_tree(self, document: TreeSitterDocument, language: str) -> list[RuleHit]:
        """Deep Go security detection using tree-sitter."""
        hits: list[RuleHit] = []
        for node in self._walk_nodes(document.root_node):
            line_start, line_end = document.line_range(node)
            text = document.text_for(node)

            # 1. Hardcoded passwords in short var declarations and assignments
            if node.type in {"short_var_declaration", "assignment_statement"}:
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    left_children = left.named_children if left.type == "expression_list" else [left]
                    right_children = right.named_children if right.type == "expression_list" else [right]
                    for l_node, r_node in zip(left_children, right_children):
                        var_name = document.text_for(l_node).strip()
                        if self._contains_sensitive_name([var_name]) and self._is_go_string_literal(r_node, document):
                            hits.append(RuleHit(
                                HARDCODED_PASSWORD, document.relative_path, line_start, line_end, language=language,
                            ))
                            break

            # Also check top-level var declarations: var password = "xxx"
            elif node.type == "var_declaration":
                for spec in node.named_children:
                    if spec.type != "var_spec":
                        continue
                    name_node = spec.child_by_field_name("name")
                    value_node = spec.child_by_field_name("value")
                    if name_node is None:
                        # var_spec may have multiple names in expression_list
                        for child in spec.named_children:
                            if child.type == "identifier":
                                name_node = child
                                break
                    if value_node is None:
                        # Value might be in expression_list
                        for child in spec.named_children:
                            if child.type == "expression_list":
                                value_children = child.named_children
                                if value_children:
                                    value_node = value_children[0]
                                break
                    if name_node is not None and value_node is not None:
                        var_name = document.text_for(name_node).strip()
                        if self._contains_sensitive_name([var_name]) and self._is_go_string_literal(value_node, document):
                            hits.append(RuleHit(
                                HARDCODED_PASSWORD, document.relative_path, line_start, line_end, language=language,
                            ))

            # 2. Call expressions for various checks
            elif node.type == "call_expression":
                fn_node = node.child_by_field_name("function")
                if fn_node is None:
                    continue
                fn_text = document.text_for(fn_node).strip()
                arguments = self._argument_nodes(node)

                # Command injection: exec.Command("sh", "-c", userInput)
                if fn_text == "exec.Command":
                    if self._is_go_shell_command_risky(arguments, document):
                        hits.append(RuleHit(
                            COMMAND_INJECTION_RISK, document.relative_path, line_start, line_end,
                            language=language,
                            message="Detected `exec.Command` with a non-literal shell command argument.",
                        ))

                # Weak hash: md5.New(), sha1.New()
                if fn_text in self._GO_WEAK_HASH_CALLS:
                    hits.append(RuleHit(
                        WEAK_HASH, document.relative_path, line_start, line_end, language=language,
                    ))

                # Insecure random: rand.Intn() etc.
                if fn_text in self._GO_INSECURE_RANDOM_CALLS:
                    hits.append(RuleHit(
                        INSECURE_RANDOM, document.relative_path, line_start, line_end, language=language,
                    ))

                # SQL injection: db.Query("SELECT ... " + variable)
                method_name = fn_text.split(".")[-1] if "." in fn_text else fn_text
                if self._looks_like_sql_call(method_name) and arguments:
                    first_arg = arguments[0]
                    if self._is_go_dynamic_string(first_arg, document):
                        hits.append(RuleHit(
                            SQL_INJECTION_RISK, document.relative_path, line_start, line_end, language=language,
                        ))

        return hits

    # ════════════════════════════════════════════════════════════════════
    # C++/Go tree-sitter helper methods
    # ════════════════════════════════════════════════════════════════════

    @staticmethod
    def _is_cpp_string_literal(node: Node, document: TreeSitterDocument) -> bool:
        """Check if a C++ node is a string literal (at least 4 chars)."""
        if node.type == "string_literal":
            content = document.text_for(node).strip().strip('"')
            return len(content) >= 4
        if node.type == "raw_string_literal":
            content = document.text_for(node)
            return len(content) >= 8  # R"(...)" minimum
        return False

    @staticmethod
    def _is_cpp_literal_node(node: Node, document: TreeSitterDocument) -> bool:
        """Check if a C++ node is any literal value (string, number, char)."""
        return node.type in {"string_literal", "raw_string_literal", "number_literal", "char_literal", "true", "false"}

    @staticmethod
    def _looks_like_c_system_declaration_node(node: Node) -> bool:
        """Check if a call_expression node is actually a function declaration."""
        parent = node.parent
        while parent is not None:
            if parent.type in {"function_definition", "compound_statement", "expression_statement"}:
                return False
            if parent.type in {"declaration", "translation_unit"}:
                return True
            parent = parent.parent
        return False

    @staticmethod
    def _is_go_string_literal(node: Node, document: TreeSitterDocument) -> bool:
        """Check if a Go node is a string literal (at least 4 chars)."""
        if node.type in {"interpreted_string_literal", "raw_string_literal"}:
            content = document.text_for(node).strip().strip('"').strip('`')
            return len(content) >= 4
        return False

    @staticmethod
    def _is_go_dynamic_string(node: Node, document: TreeSitterDocument) -> bool:
        """Check if a Go expression is a dynamically-built string (concatenation, Sprintf, etc)."""
        if node.type == "binary_expression":
            text = document.text_for(node)
            # String concatenation with +
            if "+" in text:
                return True
        if node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is not None:
                fn_text = document.text_for(fn_node).strip()
                if fn_text in {"fmt.Sprintf", "fmt.Sprint", "strings.Join"}:
                    return True
        return False

    @classmethod
    def _is_go_shell_command_risky(cls, arguments: list[Node], document: TreeSitterDocument) -> bool:
        """Check if exec.Command("sh", "-c", <dynamic>) is risky."""
        if len(arguments) < 3:
            return False
        # Pattern: exec.Command("sh", "-c", variable)
        first = document.text_for(arguments[0]).strip().strip('"').strip("'")
        second = document.text_for(arguments[1]).strip().strip('"').strip("'")
        if first in {"sh", "bash", "/bin/sh", "/bin/bash"} and second == "-c":
            third = arguments[2]
            # If third arg is a string literal, it's safe
            return third.type not in {"interpreted_string_literal", "raw_string_literal"}
        return False

    @staticmethod
    def _walk_nodes(node: Node) -> list[Node]:
        nodes = [node]
        for child in node.named_children:
            nodes.extend(SecurityEngine._walk_nodes(child))
        return nodes

    @staticmethod
    def _first_named_child(node: Node) -> Node | None:
        return node.named_children[0] if node.named_children else None

    @staticmethod
    def _argument_nodes(node: Node) -> list[Node]:
        arguments_node = node.child_by_field_name("arguments")
        if arguments_node is None:
            for child in node.named_children:
                if child.type in {"arguments", "argument_list"}:
                    arguments_node = child
                    break
        return list(arguments_node.named_children) if arguments_node is not None else []

    @staticmethod
    def _contains_sensitive_name(names: list[str]) -> bool:
        return any(SENSITIVE_NAME_RE.search(name or "") for name in names)

    @staticmethod
    def _is_string_literal(node: ast.expr | None) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 4

    @staticmethod
    def _python_assignment_names(target: ast.expr) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute):
            return [target.attr]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for child in target.elts:
                names.extend(SecurityEngine._python_assignment_names(child))
            return names
        return []

    @staticmethod
    def _python_call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = SecurityEngine._python_call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _looks_like_sql_call(call_name: str) -> bool:
        return bool(SQL_CALL_RE.search(call_name))

    @staticmethod
    def _is_python_dynamic_sql(node: ast.expr) -> bool:
        return isinstance(node, (ast.JoinedStr, ast.BinOp, ast.FormattedValue)) or (
            isinstance(node, ast.Call)
            and SecurityEngine._python_call_name(node.func).endswith(".format")
        )

    @staticmethod
    def _is_python_dynamic_path(node: ast.expr) -> bool:
        return isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Call, ast.Attribute, ast.Subscript))

    @staticmethod
    def _is_python_command_execution(call_name: str, node: ast.Call) -> bool:
        if call_name in {"os.system", "os.popen"}:
            return True
        if call_name not in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}:
            return False
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return True
        return False

    @classmethod
    def _scan_command_injection_regex(cls, line: str, rel_path: str, line_no: int, language: str) -> RuleHit | None:
        # Skip languages handled by tree-sitter AST analysis for command injection
        if language in {"python", "cpp", "go"} or cls._looks_like_c_system_declaration(line):
            return None

        for pattern in cls._command_patterns_for(language):
            match = pattern.search(line)
            if not match:
                continue
            arg = match.groupdict().get("arg")
            if arg is not None and cls._is_dynamic_command_text(arg):
                return RuleHit(
                    COMMAND_INJECTION_RISK,
                    rel_path,
                    line_no,
                    line_no,
                    message="Detected shell execution with a non-literal command argument",
                    language=language,
                )

        if language == "rust":
            rust_match = RUST_COMMAND_NEW_RE.search(line)
            if rust_match is None:
                return None
            args = [match.group("arg") for match in RUST_ARG_CALL_RE.finditer(rust_match.group("chain"))]
            if len(args) >= 2 and cls._is_shell_dash_c(args[0]) and cls._is_dynamic_command_text(args[1]):
                return RuleHit(
                    COMMAND_INJECTION_RISK,
                    rel_path,
                    line_no,
                    line_no,
                    message="Detected shell execution with a non-literal command argument",
                    language=language,
                )

        return None

    @staticmethod
    def _command_patterns_for(language: str) -> tuple[re.Pattern[str], ...]:
        if language in {"javascript", "typescript"}:
            return (JS_EXEC_CALL_RE,)
        if language == "java":
            return (JAVA_RUNTIME_EXEC_RE,)
        if language == "cpp":
            return (C_SYSTEM_CALL_RE,)
        if language == "go":
            return (GO_EXEC_COMMAND_RE,)
        if language == "csharp":
            return (CSHARP_PROCESS_START_RE,)
        if language == "lua":
            return (LUA_OS_EXECUTE_RE,)
        return ()

    @staticmethod
    def _looks_like_c_system_declaration(line: str) -> bool:
        return bool(C_LIKE_SYSTEM_DECLARATION_RE.match(line.strip()))

    @classmethod
    def _is_dynamic_command_text(cls, text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return False
        if cls._is_string_literal_text(stripped):
            return False
        return True

    @staticmethod
    def _is_string_literal_text(text: str) -> bool:
        return bool(STRING_LITERAL_RE.match(text) or BACKTICK_LITERAL_RE.match(text))

    @classmethod
    def _is_shell_dash_c(cls, text: str) -> bool:
        return text.strip().strip("\"'") == "-c"

    @classmethod
    def _is_js_command_argument_risky(cls, arguments: list[Node], document: TreeSitterDocument) -> bool:
        return bool(arguments) and cls._is_js_dynamic_value(arguments[0], document)

    @classmethod
    def _is_java_command_argument_risky(cls, arguments: list[Node], document: TreeSitterDocument) -> bool:
        return bool(arguments) and cls._is_java_dynamic_value(arguments[0], document)

    @classmethod
    def _is_java_dynamic_value(cls, node: Node, document: TreeSitterDocument) -> bool:
        text = document.text_for(node).strip()
        if not text:
            return False
        if cls._is_string_literal_text(text):
            return False
        if node.type in {"array_creation_expression", "array_initializer"} or text.startswith("new String[]"):
            return cls._java_array_contains_dynamic_content(text)
        return True

    @staticmethod
    def _java_array_contains_dynamic_content(text: str) -> bool:
        simplified = re.sub(r'"(?:\\.|[^"])*"', "", text)
        simplified = re.sub(r"\bnew\b|\bString\b", "", simplified)
        simplified = re.sub(r"[\s\[\]\{\},]", "", simplified)
        return bool(simplified)

    @staticmethod
    def _is_js_literal(node: Node, document: TreeSitterDocument) -> bool:

        if node.type in {"string", "string_fragment", "string_literal"}:
            return True
        if node.type == "template_string":
            return "${" not in document.text_for(node)
        return False

    @staticmethod
    def _is_js_dynamic_value(node: Node, document: TreeSitterDocument) -> bool:
        if node.type == "template_string":
            return "${" in document.text_for(node)
        return node.type in {
            "binary_expression",
            "identifier",
            "member_expression",
            "call_expression",
            "subscript_expression",
        }

    @staticmethod
    def _is_java_literal(node: Node, document: TreeSitterDocument) -> bool:
        return node.type == "string_literal" and len(document.text_for(node).strip("\"'")) >= 4

    @staticmethod
    def _is_weak_hash_literal(node: Node, document: TreeSitterDocument) -> bool:
        return document.text_for(node).strip().strip("\"'").lower() in {"md5", "sha1", "sha-1"}
