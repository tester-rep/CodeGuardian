"""Explain command: AI deep-dive explanation of a specific finding."""

import asyncio
from pathlib import Path

import typer

from codeguardian.ai.providers.dummy import DummyAIProvider
from codeguardian.ai.router import AIRouter
from codeguardian.cli.common import (
    resolve_app_config_path,
    resolve_project_path,
    validate_path_exists,
)
from codeguardian.cli.output import console
from codeguardian.config.loader import load_app_config
from codeguardian.models.finding import Finding
from codeguardian.models.scan import ScanResult
from codeguardian.storage.snapshots import load_latest_snapshot


def _default_impact(finding: Finding) -> str:
    category = finding.category.lower()
    if category == "security":
        return "这类问题可能带来真实的安全风险，建议优先确认输入边界、敏感操作与防护措施。"
    if category in {"defect", "defects"}:
        return "这类问题更容易在边界条件、异常路径或维护阶段演变成线上故障。"
    if category in {"complexity", "maintainability"}:
        return "这类问题会抬高理解和修改成本，后续需求迭代时更容易引入回归。"
    if category == "evolution":
        return "这类问题说明代码区域变化频繁，后续继续改动时需要重点回归。"
    return "这类问题会降低代码质量稳定性，建议尽快确认影响范围。"


def _default_fix(finding: Finding) -> str:
    if finding.rule_id:
        return f"先围绕规则 `{finding.rule_id}` 对应位置做最小修复，并补一条回归验证。"
    return "先在问题位置做最小可验证修复，再确认是否需要抽象、拆分或增加保护逻辑。"


def _default_test(finding: Finding) -> str:
    location = f"{finding.location.file_path}:{finding.location.line_start}"
    return f"至少补一条覆盖 `{location}` 附近行为的回归测试，包含正常路径、边界输入和异常路径。"


def _build_local_explanation(finding: Finding, ai_enabled: bool) -> str:
    evidence_lines = []
    for evidence in finding.evidences[:3]:
        label = evidence.type.replace("_", " ")
        snippet = evidence.content.strip().replace("\n", " ")[:140]
        evidence_lines.append(f"- {label}: {snippet}")

    lines = [
        "[yellow]使用本地解释模式。[/yellow]",
        (
            "[dim]当前 AI 能力未启用；如果你后续接入真实 provider，可再补充更深入的自然语言分析。[/dim]"
            if not ai_enabled
            else "[dim]当前仓库还没有真正接入可用 AI provider，已回退为本地解释。[/dim]"
        ),
        "",
        "[bold]问题概述[/bold]",
        f"- 标题: {finding.title}",
        f"- 分类: {finding.category}",
        f"- 严重级别: {finding.severity.value}",
        f"- 置信度: {finding.confidence.value}",
        f"- 优先级: {finding.risk_priority}",
        f"- 位置: {finding.location.file_path}:{finding.location.line_start}",
    ]

    if finding.rule_id:
        lines.append(f"- 规则: {finding.rule_id}")

    if finding.root_cause:
        lines.extend(["", "[bold]Bug 原因[/bold]"])
        for rc_line in finding.root_cause.split("\n"):
            lines.append(f"  {rc_line}")

    lines.extend(
        [
            "",
            "[bold]为什么值得处理[/bold]",
            f"- {finding.impact or _default_impact(finding)}",
            "",
            "[bold]建议怎么修[/bold]",
            f"- {finding.fix_suggestion or _default_fix(finding)}",
            "",
            "[bold]建议补什么验证[/bold]",
            f"- {finding.test_suggestion or _default_test(finding)}",
        ]
    )

    if finding.evidences:
        lines.extend(["", "[bold]证据摘要[/bold]", *evidence_lines])

    return "\n".join(lines)


def explain_command(
    finding_id: str = typer.Argument(..., help="Finding ID to explain (e.g., SEC-001, DEFECT-003)"),
    project: str | None = typer.Option(
        None,
        "--project",
        "-p",
        help="Project path used to locate .codeguardian/latest.json",
    ),
    snapshot: str | None = typer.Option(
        None,
        "--snapshot",
        "-s",
        help="Explicit JSON snapshot path",
    ),
) -> None:
    """Get AI-powered detailed explanation of a specific finding."""
    project_path = resolve_project_path(project) if project else None
    if project_path is not None:
        validate_path_exists(project_path)

    scan_snapshot: ScanResult | None
    if snapshot:
        scan_snapshot = ScanResult.model_validate_json(Path(snapshot).read_text(encoding="utf-8"))
    else:
        scan_snapshot = load_latest_snapshot(project_path=project_path)


    if scan_snapshot is None:
        lookup_scope = str(project_path) if project_path else "current working directory"
        console.print(
            "[red]No snapshot found.[/red] "
            f"Expected `.codeguardian/latest.json` under {lookup_scope}. "
            "Run 'codeguardian scan' first or pass --snapshot."
        )
        raise typer.Exit(code=1)

    finding = next((f for f in scan_snapshot.findings if f.id == finding_id), None)
    if finding is None:
        console.print(f"[red]Finding not found:[/red] {finding_id}")
        available = ", ".join(f.id for f in scan_snapshot.findings[:10])
        if available:
            console.print(f"[dim]Available findings: {available}[/dim]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Finding:[/cyan] {finding.title}")
    console.print(f"[dim]Location: {finding.location.file_path}:{finding.location.line_start}[/dim]")
    console.print(f"[dim]Severity: {finding.severity.value} | Priority: {finding.risk_priority}[/dim]\n")

    effective_project_path = project_path
    if effective_project_path is None and scan_snapshot.project_path:
        effective_project_path = Path(scan_snapshot.project_path).resolve()

    app_config = load_app_config(resolve_app_config_path(effective_project_path))

    router = AIRouter.from_config(app_config.ai)
    if not app_config.ai.enabled or isinstance(router.provider, DummyAIProvider):
        console.print(_build_local_explanation(finding, ai_enabled=app_config.ai.enabled))
        return


    with console.status("[bold green]Generating explanation..."):
        finding_context = {
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "risk_priority": finding.risk_priority,
            "location": f"{finding.location.file_path}:{finding.location.line_start}",
            "rule_id": finding.rule_id,
            "root_cause": finding.root_cause,
            "evidence_snippets": "; ".join(
                e.content.strip()[:100] for e in finding.evidences[:3]
            ),
        }
        explanation = asyncio.run(router.explain_finding(finding.id, context=finding_context))

    console.print(explanation)
