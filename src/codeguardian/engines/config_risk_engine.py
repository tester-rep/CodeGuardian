"""ConfigRiskEngine — detects configuration and deployment security risks.

COMBINED.md §3.5: Config & Deployment Risk Analyzer
Scans configuration files, Dockerfiles, K8s manifests, and project metadata
for deployment-related security and reliability issues.
"""

from __future__ import annotations

import re
from pathlib import Path

from codeguardian.core.context import ScanContext
from codeguardian.engines.rule_helpers import (
    RuleHit,
    RuleSpec,
    build_finding,
    is_placeholder_secret,
)
from codeguardian.engines.rule_registry import filter_rule_hits, register_rules
from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.scan import EngineResult
from codeguardian.utils.ignore import should_ignore


# ══════════════════════════════════════════════════════════════
# Rule Definitions
# ══════════════════════════════════════════════════════════════

HARDCODED_SECRET = RuleSpec(
    rule_id="CONFIG-HARDCODED-SECRET",
    title="配置文件中硬编码了敏感凭据 (Hardcoded secret in config file)",
    category="security",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    fix_suggestion="将敏感凭据移至环境变量或密钥管理服务（如 Vault/AWS Secrets Manager），配置文件中仅引用变量名。",
    blocks_release=True,
    risk_priority="must-fix",
    tags=("security", "config", "credential-leak"),
    cwe_ids=("CWE-798",),
    description_zh="配置文件中直接写入了 API Key、密码或 Token 等敏感信息，一旦代码泄露将导致凭据被滥用。",
)

DEBUG_MODE_ENABLED = RuleSpec(
    rule_id="DEBUG-MODE-ENABLED",
    title="生产配置中 Debug 模式未关闭 (Debug mode enabled in production config)",
    category="config_risk",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    fix_suggestion="在生产环境配置中关闭 Debug 模式，确保 DEBUG=False / debug=false。",
    blocks_release=True,
    risk_priority="must-fix",
    tags=("security", "config", "debug"),
    cwe_ids=("CWE-489",),
    description_zh="Debug 模式在生产环境开启会暴露详细错误堆栈、内部路径等敏感信息，增加攻击面。",
)

ENV_FILE_TRACKED = RuleSpec(
    rule_id="ENV-FILE-TRACKED",
    title=".env 文件未被 .gitignore 排除 (Sensitive .env file potentially tracked)",
    category="config_risk",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="将 .env 添加到 .gitignore，并从 git 历史中移除（git filter-branch 或 BFG）。",
    risk_priority="must-fix",
    tags=("security", "config", "credential-leak"),
    cwe_ids=("CWE-538",),
    description_zh=".env 文件通常包含 API 密钥和数据库密码。如果被 Git 追踪，推送到远程仓库会导致凭据泄露。",
)

DOCKERFILE_ROOT_USER = RuleSpec(
    rule_id="DOCKERFILE-ROOT-USER",
    title="Dockerfile 以 root 用户运行容器 (Container runs as root)",
    category="config_risk",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="在 Dockerfile 中添加 USER non-root 指令，使用非特权用户运行应用。",
    risk_priority="should-fix",
    tags=("security", "docker", "least-privilege"),
    cwe_ids=("CWE-250",),
    description_zh="容器以 root 运行时，若应用被攻破，攻击者将获得宿主机 root 权限，严重扩大影响面。",
)

DOCKER_LATEST_TAG = RuleSpec(
    rule_id="DOCKER-LATEST-TAG",
    title="Dockerfile 使用 :latest 标签 (Non-deterministic base image tag)",
    category="config_risk",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="使用具体版本标签（如 python:3.11-slim）代替 :latest，确保构建可复现。",
    risk_priority="should-fix",
    tags=("reliability", "docker", "reproducibility"),
    description_zh="使用 :latest 标签导致构建不可复现，上游镜像更新可能引入兼容性问题或安全漏洞。",
)

CORS_WILDCARD = RuleSpec(
    rule_id="CORS-WILDCARD",
    title="CORS 配置允许任意来源 (Overly permissive CORS: Access-Control-Allow-Origin: *)",
    category="security",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    fix_suggestion="将 CORS 限制为具体的受信域名列表，避免使用通配符 *。",
    risk_priority="should-fix",
    tags=("security", "config", "cors", "web"),
    cwe_ids=("CWE-942",),
    owasp=("A05:2021",),
    description_zh="CORS 配置为 * 允许任意网站发起跨域请求，可能被利用进行 CSRF 或数据窃取攻击。",
)

MISSING_RESOURCE_LIMIT = RuleSpec(
    rule_id="MISSING-RESOURCE-LIMIT",
    title="容器或线程池缺少资源限制 (Missing resource limits)",
    category="config_risk",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    fix_suggestion="为容器添加 memory/cpu limits，为线程池/连接池设置最大值。",
    risk_priority="should-fix",
    tags=("reliability", "config", "resource-management"),
    description_zh="无资源限制可能导致单个服务耗尽宿主资源，引发级联故障或 OOM Kill。",
)

SENSITIVE_LOG_OUTPUT = RuleSpec(
    rule_id="SENSITIVE-LOG-OUTPUT",
    title="日志中输出敏感字段 (Sensitive data in log output)",
    category="security",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    fix_suggestion="对日志中的敏感字段做脱敏处理（mask/redact），或从日志对象中排除敏感属性。",
    risk_priority="should-fix",
    tags=("security", "config", "data-leak", "logging"),
    cwe_ids=("CWE-532",),
    description_zh="将密码、Token、身份证号等敏感信息写入日志，可能被运维人员或日志系统旁路获取。",
)

CONFIG_RISK_RULES = register_rules(
    "config_risk",
    (
        HARDCODED_SECRET,
        DEBUG_MODE_ENABLED,
        ENV_FILE_TRACKED,
        DOCKERFILE_ROOT_USER,
        DOCKER_LATEST_TAG,
        CORS_WILDCARD,
        MISSING_RESOURCE_LIMIT,
        SENSITIVE_LOG_OUTPUT,
    ),
)

# ══════════════════════════════════════════════════════════════
# Patterns
# ══════════════════════════════════════════════════════════════

# Config file extensions to scan
CONFIG_EXTENSIONS = {
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".json", ".env",
}
DOCKERFILE_NAMES = {"dockerfile", "containerfile"}

# Hardcoded secret patterns in config files
_SECRET_KEY_PATTERN = re.compile(
    r"""(?ix)
    (?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|
    private[_-]?key|auth[_-]?token|client[_-]?secret|
    db[_-]?pass|database[_-]?password|redis[_-]?pass|
    smtp[_-]?pass|mail[_-]?password)
    """,
)
_SECRET_VALUE_PATTERN = re.compile(
    r"""(?x)
    [\s:=]+\s*['"]?
    (?P<value>[^\s'"#\n]{8,})  # at least 8 chars, no whitespace/quotes/comments
    """,
)
# Placeholder / env-reference filtering is shared via
# codeguardian.engines.rule_helpers.is_placeholder_secret.

# Debug mode patterns
_DEBUG_PATTERNS = [
    re.compile(r"(?i)^\s*debug\s*[=:]\s*(?:true|1|yes|on)\s*$", re.MULTILINE),
    re.compile(r"(?i)^\s*DEBUG\s*=\s*True\s*$", re.MULTILINE),
    re.compile(r"(?i)\"debug\"\s*:\s*true", re.MULTILINE),
]

# CORS wildcard
_CORS_WILDCARD_PATTERNS = [
    re.compile(r"""(?i)(?:access[_-]?control[_-]?allow[_-]?origin|cors[_-]?origin|allowed[_-]?origins?)\s*[=:]\s*['"]?\*['"]?"""),
    re.compile(r"""(?i)allow_all_origins\s*[=:]\s*(?:true|1|yes)"""),
    re.compile(r"""(?i)CORS_ORIGIN_ALLOW_ALL\s*=\s*True"""),
]

# Sensitive log patterns
_LOG_SENSITIVE_PATTERNS = [
    re.compile(r"""(?i)(?:log|logger|logging|console)\s*\.(?:info|debug|warn|error|print)\s*\([^)]*(?:password|token|secret|api[_-]?key|credential)"""),
    re.compile(r"""(?i)print\s*\([^)]*(?:password|token|secret|api[_-]?key)"""),
]

# K8s / Docker Compose resource limit check
_K8S_RESOURCE_PATTERN = re.compile(r"(?i)(?:resources|limits|requests)\s*:", re.MULTILINE)


# ══════════════════════════════════════════════════════════════
# Engine Implementation
# ══════════════════════════════════════════════════════════════

class ConfigRiskEngine:
    """Detects configuration and deployment security/reliability risks."""

    name = "config_risk"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        """Scan config files, Dockerfiles, and source for config-related risks."""
        root = Path(ctx.project_root).resolve()
        hits: list[RuleHit] = []

        # Collect candidate files
        candidates = ctx.collect_candidate_files(root)

        for file_path in candidates:
            if should_ignore(file_path):
                continue

            suffix = file_path.suffix.lower()
            name_lower = file_path.name.lower()

            # Dockerfile checks
            if name_lower in DOCKERFILE_NAMES or name_lower.startswith("dockerfile"):
                self._scan_dockerfile(file_path, root, hits)
            # Config files
            elif suffix in CONFIG_EXTENSIONS or name_lower == ".env":
                self._scan_config_file(file_path, root, hits)
            # Source files for log/cors patterns
            elif suffix in {".py", ".java", ".js", ".ts", ".go", ".rb", ".cs"}:
                self._scan_source_for_config_risks(file_path, root, hits)

        # Check .gitignore for .env exclusion
        self._check_env_gitignore(root, hits)

        # Apply rule filters
        filtered_hits = filter_rule_hits(hits, ctx.config.rules)

        # Build findings
        findings = []
        for idx, hit in enumerate(filtered_hits, start=1):
            try:
                lines = Path(root / hit.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
            findings.append(build_finding(hit, lines, f"CFG-{idx:03d}", self.name))

        return EngineResult(engine_name=self.name, findings=findings)

    def _scan_config_file(self, path: Path, root: Path, hits: list[RuleHit]) -> None:
        """Scan config/env files for hardcoded secrets and debug mode."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        rel_path = str(path.relative_to(root)).replace("\\", "/")
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check hardcoded secrets
            if _SECRET_KEY_PATTERN.search(stripped):
                match = _SECRET_VALUE_PATTERN.search(stripped)
                if match:
                    value = match.group("value").strip("'\"")
                    # Filter out placeholders and env var references
                    if not is_placeholder_secret(value) and len(value) >= 8:
                        hits.append(RuleHit(
                            rule=HARDCODED_SECRET,
                            file_path=rel_path,
                            line_start=line_no,
                            line_end=line_no,
                            message=f"Hardcoded secret value in config: key pattern matched at line {line_no}",
                        ))

        # Check debug mode
        for pattern in _DEBUG_PATTERNS:
            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                hits.append(RuleHit(
                    rule=DEBUG_MODE_ENABLED,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    message="Debug mode is enabled in configuration file",
                ))
                break  # One hit per file per pattern

        # Check CORS wildcard
        for pattern in _CORS_WILDCARD_PATTERNS:
            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                hits.append(RuleHit(
                    rule=CORS_WILDCARD,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    message="CORS allows all origins (*)",
                ))
                break

    def _scan_dockerfile(self, path: Path, root: Path, hits: list[RuleHit]) -> None:
        """Scan Dockerfile for security issues."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        rel_path = str(path.relative_to(root)).replace("\\", "/")
        lines = content.splitlines()

        has_user_directive = False
        from_lines: list[tuple[int, str]] = []

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            upper = stripped.upper()

            if upper.startswith("USER ") and not upper.startswith("USER ROOT"):
                has_user_directive = True

            if upper.startswith("FROM "):
                from_lines.append((line_no, stripped))

        # Check :latest tag
        for line_no, from_line in from_lines:
            image_ref = from_line[5:].strip().split()[0] if len(from_line) > 5 else ""
            # FROM image:latest or FROM image (no tag = implicit latest)
            if ":latest" in image_ref or (":" not in image_ref and "/" not in image_ref.split("@")[0].split(" ")[0] and image_ref.lower() not in {"scratch"}):
                # Check if it has a tag at all
                if ":latest" in image_ref:
                    hits.append(RuleHit(
                        rule=DOCKER_LATEST_TAG,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        message=f"Base image uses :latest tag: {image_ref}",
                    ))

        # Check no USER directive (runs as root)
        if not has_user_directive and from_lines:
            hits.append(RuleHit(
                rule=DOCKERFILE_ROOT_USER,
                file_path=rel_path,
                line_start=from_lines[-1][0],
                line_end=from_lines[-1][0],
                message="Dockerfile has no USER directive — container runs as root",
            ))

    def _scan_source_for_config_risks(self, path: Path, root: Path, hits: list[RuleHit]) -> None:
        """Scan source files for CORS wildcard and sensitive logging."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        rel_path = str(path.relative_to(root)).replace("\\", "/")

        # CORS wildcard in source
        for pattern in _CORS_WILDCARD_PATTERNS:
            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                hits.append(RuleHit(
                    rule=CORS_WILDCARD,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    message="CORS allows all origins (*) in source code",
                ))
                break

        # Sensitive data in logs
        for pattern in _LOG_SENSITIVE_PATTERNS:
            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                hits.append(RuleHit(
                    rule=SENSITIVE_LOG_OUTPUT,
                    file_path=rel_path,
                    line_start=line_no,
                    line_end=line_no,
                    message="Potentially logging sensitive data (password/token/secret/key)",
                ))

    def _check_env_gitignore(self, root: Path, hits: list[RuleHit]) -> None:
        """Check if .env file exists but is not in .gitignore."""
        env_file = root / ".env"
        gitignore_file = root / ".gitignore"

        if not env_file.exists():
            return

        env_excluded = False
        if gitignore_file.exists():
            try:
                gitignore_content = gitignore_file.read_text(encoding="utf-8", errors="replace")
                for line in gitignore_content.splitlines():
                    stripped = line.strip()
                    if stripped in {".env", "*.env", ".env*", ".env.*"}:
                        env_excluded = True
                        break
            except OSError:
                pass

        if not env_excluded:
            hits.append(RuleHit(
                rule=ENV_FILE_TRACKED,
                file_path=".env",
                line_start=1,
                line_end=1,
                message=".env file exists but is not excluded in .gitignore — secrets may be committed",
            ))
