"""Issue Clustering — groups individual findings into systemic issues.

COMBINED.md §4.5.4: "问题聚类（系统性归纳）"
Groups 200+ individual findings into ~10 actionable systemic issues,
making reports look like professional audit output rather than scanner noise.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from codeguardian.models.finding import Finding


@dataclass
class SystemicIssue:
    """A cluster of related findings representing a systemic problem."""

    cluster_id: str
    title: str
    category: str
    description: str
    severity: str  # Highest severity among members
    finding_count: int
    affected_modules: list[str]
    affected_files: list[str]
    representative_findings: list[str]  # IDs of top representative findings
    suggested_action: str
    estimated_effort: str  # e.g. "2-4 hours", "1-2 days"


# Cluster definitions: (cluster_key, title, description, action, effort)
_CLUSTER_DEFINITIONS: dict[str, tuple[str, str, str, str]] = {
    # Security clusters
    "security:injection": (
        "输入注入类安全风险集群",
        "多处代码存在注入风险（SQL/命令/路径），缺乏统一的输入校验层。",
        "引入统一输入校验中间件/过滤器，所有外部输入在入口层做清洗和白名单校验。",
        "1-3 天",
    ),
    "security:credential": (
        "凭据管理安全风险集群",
        "多处代码或配置中存在硬编码凭据或敏感信息暴露。",
        "将所有敏感配置迁移到密钥管理服务（Vault/AWS Secrets Manager），代码中仅引用环境变量。",
        "0.5-1 天",
    ),
    "security:crypto": (
        "加密与随机数安全风险集群",
        "使用了弱哈希/不安全随机数，密码学操作不符合安全标准。",
        "统一升级到 SHA-256+/bcrypt/argon2 和 secrets/SecureRandom。",
        "2-4 小时",
    ),
    # Performance clusters
    "performance:database": (
        "数据库访问性能反模式集群",
        "存在 N+1 查询、SELECT *、缺少分页等数据库性能问题。",
        "引入批量查询替代循环查询，指定具体字段，添加分页参数。",
        "1-2 天",
    ),
    "performance:concurrency": (
        "并发与资源管理风险集群",
        "存在忙等待、无退避重试、锁管理不当等并发安全问题。",
        "引入 sleep/条件变量替代自旋等待，增加指数退避和最大重试次数，使用 RAII 管理锁。",
        "1-3 天",
    ),
    "performance:timeout": (
        "超时与网络调用风险集群",
        "HTTP/RPC 调用缺少超时设置，可能导致线程挂死。",
        "为所有出站调用统一配置超时（建议 30s），引入熔断器。",
        "2-4 小时",
    ),
    # Defect clusters
    "defect:exception": (
        "异常处理策略缺陷集群",
        "多处代码存在空 catch、宽泛异常捕获、异常吞没等问题。",
        "建立统一异常处理策略：具体类型捕获 → 结构化日志 → 恢复或重抛。",
        "1-2 天",
    ),
    "defect:resource": (
        "资源泄露风险集群",
        "文件/连接/流等资源创建后未确保关闭，存在泄露路径。",
        "统一使用 context manager / try-with-resources / defer 确保资源释放。",
        "0.5-1 天",
    ),
    "defect:logic": (
        "逻辑缺陷风险集群",
        "存在无限循环/递归、不可达代码、除零等逻辑安全问题。",
        "为高风险逻辑路径补充单元测试和边界条件验证。",
        "1-3 天",
    ),
    # Architecture/Design clusters
    "architecture:coupling": (
        "模块耦合与依赖问题集群",
        "存在循环依赖、高扇出、稳定性违规等架构问题。",
        "提取公共接口、引入依赖反转，拆分高耦合模块。",
        "3-5 天",
    ),
    "architecture:design": (
        "面向对象设计问题集群",
        "存在上帝类、数据类、深层继承等设计反模式。",
        "按职责拆分大类，用组合替代深层继承，将行为移入数据类。",
        "2-5 天",
    ),
    # Config/Deployment clusters
    "config:deployment": (
        "配置与部署安全风险集群",
        "存在 Debug 模式开启、.env 泄露、Docker 安全问题等配置风险。",
        "建立环境分离策略：生产配置自动验证、密钥注入、容器最小权限。",
        "0.5-1 天",
    ),
    # Maintainability clusters
    "maintainability:complexity": (
        "代码复杂度过高集群",
        "多个函数/类超过复杂度阈值，维护成本高、易出错。",
        "拆分复杂函数（Extract Method），降低圈复杂度至 15 以下。",
        "2-5 天",
    ),
}

# Rule-to-cluster mapping
_RULE_CLUSTER_MAP: dict[str, str] = {
    # Security → injection
    "SQL-INJECTION-RISK": "security:injection",
    "COMMAND-INJECTION-RISK": "security:injection",
    "PATH-TRAVERSAL-RISK": "security:injection",
    "SSRF-RISK": "security:injection",
    # Security → credential
    "HARDCODED-PASSWORD": "security:credential",
    "CONFIG-HARDCODED-SECRET": "security:credential",
    "ENV-FILE-TRACKED": "security:credential",
    "SENSITIVE-LOG-OUTPUT": "security:credential",
    # Security → crypto
    "WEAK-HASH": "security:crypto",
    "INSECURE-RANDOM": "security:crypto",
    # Performance → database
    "SQL-IN-LOOP": "performance:database",
    "SELECT-STAR-NO-LIMIT": "performance:database",
    "MISSING-PAGINATION": "performance:database",
    "TRANSACTION-SCOPE-TOO-LARGE": "performance:database",
    # Performance → concurrency
    "BUSY-WAIT": "performance:concurrency",
    "RETRY-WITHOUT-BACKOFF": "performance:concurrency",
    "MUTEX-LOCK-NO-UNLOCK": "performance:concurrency",
    "UNBOUNDED-GOROUTINE": "performance:concurrency",
    # Performance → timeout
    "HTTP-NO-TIMEOUT": "performance:timeout",
    "BLOCKING-CALL-IN-ASYNC": "performance:timeout",
    # Defect → exception
    "EMPTY-EXCEPT": "defect:exception",
    "BROAD-EXCEPT": "defect:exception",
    "BARE-EXCEPT": "defect:exception",
    "LOG-ONLY-EXCEPT": "defect:exception",
    "SWALLOWED-EXCEPTION-FLOW": "defect:exception",
    "EXCEPTION-LOST-CONTEXT": "defect:exception",
    # Defect → resource
    "RESOURCE-LEAK": "defect:resource",
    "RESOURCE-CLOSE-NOT-GUARANTEED": "defect:resource",
    # Defect → logic
    "INFINITE-RECURSION-RISK": "defect:logic",
    "INFINITE-LOOP-RISK": "defect:logic",
    "ASYNC-VOID": "defect:exception",
    "DIVISION-BY-ZERO-RISK": "defect:logic",
    "UNREACHABLE-CODE": "defect:logic",
    "POSSIBLE-NONE-DEREF": "defect:logic",
    # Architecture
    "CIRCULAR-DEPENDENCY": "architecture:coupling",
    "HIGH-FAN-OUT": "architecture:coupling",
    "UNSTABLE-DEPENDENCY": "architecture:coupling",
    "GOD-CLASS": "architecture:design",
    "DATA-CLASS": "architecture:design",
    "DEEP-INHERITANCE": "architecture:design",
    "HIGH-CLASS-COUPLING": "architecture:coupling",
    "ISP-VIOLATION": "architecture:design",
    "DIP-VIOLATION": "architecture:coupling",
    "FEATURE-ENVY": "architecture:design",
    # Config
    "DEBUG-MODE-ENABLED": "config:deployment",
    "DOCKERFILE-ROOT-USER": "config:deployment",
    "DOCKER-LATEST-TAG": "config:deployment",
    "CORS-WILDCARD": "config:deployment",
    "MISSING-RESOURCE-LIMIT": "config:deployment",
    # Maintainability
    "HIGH-CC-FUNCTION": "maintainability:complexity",
    "REDOS-RISK": "performance:concurrency",
}

# Category-based fallback mapping
_CATEGORY_CLUSTER_FALLBACK: dict[str, str] = {
    "security": "security:injection",
    "performance": "performance:concurrency",
    "defect": "defect:exception",
    "architecture": "architecture:coupling",
    "config_risk": "config:deployment",
    "maintainability": "maintainability:complexity",
}


def cluster_findings(findings: list[Finding]) -> list[SystemicIssue]:
    """Group findings into systemic issue clusters.

    Returns clusters sorted by severity and finding count.
    Only returns clusters with 2+ findings.
    """
    # Assign each finding to a cluster
    cluster_members: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        cluster_key = _RULE_CLUSTER_MAP.get(finding.rule_id or "")
        if not cluster_key:
            cluster_key = _CATEGORY_CLUSTER_FALLBACK.get(finding.category, "")
        if cluster_key:
            cluster_members[cluster_key].append(finding)

    # Build systemic issues from clusters with 2+ members
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    issues: list[SystemicIssue] = []

    for cluster_key, members in cluster_members.items():
        if len(members) < 2:
            continue

        definition = _CLUSTER_DEFINITIONS.get(cluster_key)
        if not definition:
            continue

        title, description, action, effort = definition

        # Determine highest severity
        worst_severity = min(
            (severity_rank.get(f.severity.value, 5) for f in members),
            default=5,
        )
        severity_name = next(
            (k for k, v in severity_rank.items() if v == worst_severity),
            "medium",
        )

        # Collect affected modules/files
        affected_files = sorted(set(f.location.file_path for f in members))
        affected_modules = sorted(set(
            f.location.file_path.split("/")[0]
            for f in members
            if "/" in f.location.file_path
        ))

        # Pick top representative findings
        sorted_members = sorted(
            members,
            key=lambda f: severity_rank.get(f.severity.value, 5),
        )
        representative_ids = [f.id for f in sorted_members[:3]]

        issues.append(SystemicIssue(
            cluster_id=cluster_key,
            title=title,
            category=cluster_key.split(":")[0],
            description=description,
            severity=severity_name,
            finding_count=len(members),
            affected_modules=affected_modules[:5],
            affected_files=affected_files[:10],
            representative_findings=representative_ids,
            suggested_action=action,
            estimated_effort=effort,
        ))

    # Sort: highest severity first, then by finding count
    issues.sort(key=lambda i: (severity_rank.get(i.severity, 5), -i.finding_count))
    return issues


def estimate_tech_debt(findings: list[Finding]) -> dict[str, object]:
    """Estimate total technical debt in person-hours.

    Returns a dict with total hours, per-category breakdown, and top modules.
    """
    # Effort weights per severity (in person-hours per finding)
    severity_hours = {
        "critical": 4.0,
        "high": 2.0,
        "medium": 1.0,
        "low": 0.5,
        "info": 0.1,
    }

    total_hours = 0.0
    category_hours: dict[str, float] = Counter()
    module_hours: dict[str, float] = Counter()

    for finding in findings:
        hours = severity_hours.get(finding.severity.value, 1.0)
        total_hours += hours
        category_hours[finding.category] += hours

        # Module = first path segment
        path = finding.location.file_path
        module = path.split("/")[0] if "/" in path else "root"
        module_hours[module] += hours

    # Convert to person-days
    total_days = total_hours / 8.0

    return {
        "total_hours": round(total_hours, 1),
        "total_days": round(total_days, 1),
        "by_category": dict(category_hours.most_common()),
        "by_module": dict(Counter(module_hours).most_common(10)),
        "finding_count": len(findings),
    }
