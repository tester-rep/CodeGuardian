"""TerminalReporter — renders a summary table to the terminal using Rich."""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from codeguardian.models.report import ReportArtifact
from codeguardian.models.scan import ScanResult


class TerminalReporter:
    """Rich-based terminal output with tables and color coding."""

    def __init__(self) -> None:
        self.console = Console()

    @staticmethod
    def _severity_label(value: str) -> str:
        mapping = {"critical": "严重", "high": "高危", "medium": "中等", "low": "低危", "info": "提示"}
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _priority_label(value: str) -> str:
        mapping = {
            "must-fix": "必须修复", "should-fix": "建议修复", "can-fix": "可选修复",
            "must": "必须处理", "recommended": "建议处理", "optional": "可选处理",
        }
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _risk_level_label(value: str) -> str:
        mapping = {"good": "良好", "medium": "中等", "high": "高风险", "critical": "严重风险"}
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _recommendation_label(value: str) -> str:
        mapping = {
            "immediate_refactor": "立即重构", "plan_refactor": "计划重构",
            "continue_observing": "持续观察", "no_action": "无需处理",
        }
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _verdict_label(value: str) -> str:
        mapping = {
            "recommended": "建议发布", "conditional": "有条件发布",
            "not_recommended": "不建议发布", "blocked": "阻塞发布",
        }
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _review_source_label(value: str) -> str:
        mapping = {"local": "本地规则", "ai": "AI 评审"}
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _evidence_level_label(value: str) -> str:
        mapping = {
            "test-confirmed": "测试复现", "static-confirmed": "静态确认",
            "likely": "证据较强", "suspected": "疑似风险", "needs-review": "需要复核",
        }
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _source_engine_label(value: str) -> str:

        mapping = {
            "security": "本地引擎/安全", "defect": "本地引擎/缺陷",
            "complexity": "本地引擎/复杂度", "performance": "本地引擎/性能",
            "testing": "本地引擎/测试", "git_evolution": "本地引擎/演进",
            "deep_review": "AI/深度审查",
        }
        if value.startswith("ai"):
            return f"AI/{value}"
        return mapping.get(value, value)

    def render(self, result: ScanResult, output_dir: Path | None) -> ReportArtifact | None:

        profile = result.project_profile

        # Header
        self.console.print()
        self.console.print(
            Panel(
                "[bold cyan]CodeGuardian[/bold cyan] v0.1.0 "
                "— AI 驱动的代码质量审计工具",
                subtitle="扫描完成",
            )
        )

        # Project info
        self.console.print(f"\n[bold]项目:[/bold] {profile.project_name}")
        self.console.print(f"[bold]评分:[/bold] {self._score_badge(profile.overall_score)}")
        self.console.print(f"[bold]状态:[/bold] {self._status_badge(profile.health_status)}")

        if profile.languages:
            self.console.print(f"[bold]语言:[/bold] {', '.join(profile.languages)}")

        # Findings summary
        critical = sum(1 for f in result.findings if f.severity.value == "critical")
        high = sum(1 for f in result.findings if f.severity.value == "high")
        medium = sum(1 for f in result.findings if f.severity.value == "medium")
        low = sum(1 for f in result.findings if f.severity.value == "low")
        total = len(result.findings)

        findings_table = Table(title="问题统计")
        findings_table.add_column("严重度", style="bold")
        findings_table.add_column("数量")
        findings_table.add_row("[red]严重 (Critical)[/red]", str(critical))
        findings_table.add_row("[yellow]高危 (High)[/yellow]", str(high))
        findings_table.add_row("中等 (Medium)", str(medium))
        findings_table.add_row("[dim]低危 (Low)[/dim]", str(low))
        findings_table.add_row("[bold]合计[/bold]", str(total))

        self.console.print(findings_table)

        if profile.dimension_scores:
            dim_zh = {
                "scale": "规模 (scale)",
                "complexity": "复杂度 (complexity)",
                "defects": "缺陷 (defects)",
                "security": "安全 (security)",
                "performance": "性能 (performance)",
                "testing": "测试 (testing)",
                "maintainability": "可维护性 (maintainability)",
                "evolution": "演进 (evolution)",
            }
            dimension_table = Table(title="维度评分")
            dimension_table.add_column("维度")
            dimension_table.add_column("评分")
            dimension_table.add_column("状态")
            dimension_table.add_column("问题数")
            for dimension in profile.dimension_scores:
                dimension_table.add_row(
                    dim_zh.get(dimension.dimension, dimension.dimension),
                    f"{dimension.score:.0f}",
                    self._status_badge(dimension.status),
                    str(dimension.findings_count),
                )
            self.console.print(dimension_table)

        if result.ai_summary:
            self.console.print("\n[bold]总体摘要:[/bold]")
            self.console.print(result.ai_summary)

        if result.release_conclusion is not None:
            self.console.print(
                f"\n[bold]发布结论:[/bold] {self._verdict_label(result.release_conclusion.verdict)}"
            )
            if result.release_conclusion.review_summary:
                self.console.print(
                    f"[bold]发布评审（{self._review_source_label(result.release_conclusion.review_source)}）:[/bold] "
                    f"{result.release_conclusion.review_summary}"
                )
            if result.release_conclusion.blocking_items:
                self.console.print("\n[bold]阻塞项:[/bold]")
                for item in result.release_conclusion.blocking_items[:5]:
                    self.console.print(f"  [red]-[/red] {item['title']} ({item['location']})")
            if result.release_conclusion.residual_risks:
                self.console.print("\n[bold]残余风险:[/bold]")
                for item in result.release_conclusion.residual_risks[:5]:
                    self.console.print(f"  - {item['title']} ({self._severity_label(item['severity'])})")
            if result.release_conclusion.suggested_verifications:
                self.console.print("\n[bold]建议验证项:[/bold]")
                for item in result.release_conclusion.suggested_verifications[:3]:
                    self.console.print(f"  - {item['suggestion']}")
            if result.release_conclusion.post_release_monitoring:
                self.console.print("\n[bold]发布后监控:[/bold]")
                for item in result.release_conclusion.post_release_monitoring[:3]:
                    self.console.print(f"  - {item['suggestion']}")

        if profile.modules:
            module_table = Table(title="高风险模块")
            module_table.add_column("模块")
            module_table.add_column("评分")
            module_table.add_column("风险等级")
            module_table.add_column("问题数")
            module_table.add_column("覆盖率")
            module_table.add_column("关键维度")
            module_table.add_column("建议")

            dim_zh = {
                "scale": "规模", "complexity": "复杂度", "defects": "缺陷", "security": "安全",
                "performance": "性能", "testing": "测试", "maintainability": "可维护性", "evolution": "演进",
            }
            for module in profile.modules[:5]:
                dimensions = ", ".join(
                    f"{dim_zh.get(name, name)}:{score:.0f}"
                    for name, score in list(module.dimension_scores.items())[:3]
                ) or "-"
                coverage = f"{module.test_coverage:.0f}%" if module.test_coverage is not None else "-"
                module_table.add_row(
                    module.path,
                    f"{module.risk_score:.0f}",
                    self._risk_level_label(module.risk_level),
                    str(len(module.findings)),
                    coverage,
                    dimensions,
                    self._recommendation_label(module.recommendation),
                )
            self.console.print(module_table)

            self.console.print("\n[bold]模块专项报告:[/bold]")
            status_zh_map = {
                "unavailable": "未接入", "good": "良好",
                "warning": "警告", "critical": "严重",
            }
            trend_zh_map = {
                "unknown": "未知", "rising": "上升", "stable": "稳定",
            }
            for module in profile.modules[:3]:
                testing_bits = [
                    f"行覆盖 {module.testing_profile.line_coverage:.0f}%" if module.testing_profile.line_coverage is not None else "行覆盖 —",
                    f"分支覆盖 {module.testing_profile.branch_coverage:.0f}%" if module.testing_profile.branch_coverage is not None else "分支覆盖 —",
                    f"函数覆盖 {module.testing_profile.function_coverage:.0f}%" if module.testing_profile.function_coverage is not None else "函数覆盖 —",
                    f"状态: {status_zh_map.get(module.testing_profile.status, module.testing_profile.status)}",
                ]
                stability_bits = [
                    f"变更频率 {module.historical_stability.churn_score:.0f}" if module.historical_stability.churn_score is not None else "变更频率 —",
                    f"趋势: {trend_zh_map.get(module.historical_stability.churn_trend, module.historical_stability.churn_trend)}",
                    f"热点: {'是' if module.historical_stability.hotspot else '否'}",
                ]
                self.console.print(
                    f"\n[bold]{module.path}[/bold] "
                    f"({self._risk_level_label(module.risk_level)}, {module.risk_score:.0f}/100)"
                )
                self.console.print(
                    f"  概览: {module.file_count} 文件 / {module.class_count} 类 / "
                    f"{module.function_count} 函数 / LOC {module.loc} / SLOC {module.sloc}"
                )
                self.console.print(f"  测试覆盖: {', '.join(testing_bits)}")
                self.console.print(f"  历史稳定性: {', '.join(stability_bits)}")
                self.console.print(
                    "  架构: "
                    + (module.architecture_profile.notes[0] if module.architecture_profile.notes else "暂无架构摘要")
                )

                if module.top_findings:
                    self.console.print("  主要问题:")
                    for finding_item in module.top_findings[:3]:
                        self.console.print(
                            f"    - {finding_item.title} [{self._severity_label(finding_item.severity)}/{self._priority_label(finding_item.priority)}] ({finding_item.location})"
                        )
                if module.action_items:
                    self.console.print("  待办事项:")
                    for action_item in module.action_items[:3]:
                        self.console.print(f"    - [{self._priority_label(action_item.priority)}] {action_item.summary}")



        # Top issues (if any)

        if result.findings:

            top_issues = sorted(result.findings, key=lambda f: (f.severity.weight, f.evidence_rank), reverse=True)[:10]



            sev_zh = {"critical": "严重", "high": "高危", "medium": "中等", "low": "低危", "info": "提示"}
            pri_zh = {"must-fix": "必须修复", "should-fix": "建议修复", "can-fix": "可选修复"}

            self.console.print("\n[bold]主要问题:[/bold]")
            issue_table = Table()
            issue_table.add_column("ID")
            issue_table.add_column("标题")
            issue_table.add_column("规则说明")
            issue_table.add_column("严重度")
            issue_table.add_column("优先级")
            issue_table.add_column("位置")
            issue_table.add_column("证据")
            issue_table.add_column("修复建议")

            for finding in top_issues:
                sev_color = {
                    "critical": "red", "high": "yellow",
                    "medium": "green", "low": "blue", "info": "dim",
                }.get(finding.severity.value, "white")
                sev_label = sev_zh.get(finding.severity.value, finding.severity.value)
                pri_label = pri_zh.get(finding.risk_priority, finding.risk_priority)

                # Rule description or brief root_cause
                desc = finding.rule_description or ""
                if not desc and finding.root_cause:
                    desc = finding.root_cause.split("\n")[0][:60]

                fix = (finding.fix_suggestion or "")[:60]
                evidence_label = self._evidence_level_label(finding.evidence_level)

                issue_table.add_row(
                    finding.id,
                    finding.title[:50],
                    desc[:50],
                    f"[{sev_color}]{sev_label}[/]",
                    pri_label,
                    f"{finding.location.file_path[:35]}:{finding.location.line_start or 0}",
                    evidence_label,
                    fix,
                )


            self.console.print(issue_table)

        if result.supplementary_findings:
            self.console.print(
                f"\n[dim]AI 补充发现: {len(result.supplementary_findings)} 个低置信线索，详见 JSON 报告。[/dim]"

            )

        # Systemic issues (clustering)
        if result.systemic_issues:
            self.console.print("\n[bold]系统性问题集群:[/bold]")
            cluster_table = Table()
            cluster_table.add_column("集群", style="bold")
            cluster_table.add_column("问题数", justify="right")
            cluster_table.add_column("严重度")
            cluster_table.add_column("建议动作")
            cluster_table.add_column("预估工时")
            for issue in result.systemic_issues[:8]:
                sev_color = {"critical": "red", "high": "yellow", "medium": "green"}.get(
                    issue.get("severity", ""), "white"
                )
                cluster_table.add_row(
                    issue.get("title", "")[:40],
                    str(issue.get("finding_count", 0)),
                    f"[{sev_color}]{issue.get('severity', '')}[/]",
                    issue.get("suggested_action", "")[:50],
                    issue.get("estimated_effort", ""),
                )
            self.console.print(cluster_table)

        # Tech debt estimate
        if result.tech_debt_estimate:
            td = result.tech_debt_estimate
            self.console.print(
                f"\n[bold]技术债估算:[/bold] {td.get('total_hours', 0)} 人时 "
                f"({td.get('total_days', 0)} 人天) | "
                f"涉及 {td.get('finding_count', 0)} 个问题"
            )

        if result.engine_errors:
            self.console.print("\n[red]引擎错误:[/red]")
            for error in result.engine_errors[:5]:
                self.console.print(f"  [red]-[/red] {error}")

        if result.engine_warnings:
            self.console.print("\n[yellow]引擎警告:[/yellow]")
            for warning in result.engine_warnings[:5]:
                self.console.print(f"  [yellow]-[/yellow] {warning}")

        # Duration
        if result.duration_seconds:
            self.console.print(f"\n[dim]耗时: {result.duration_seconds:.1f}s[/dim]")


        # AI Token Usage
        if result.ai_token_usage:
            self._render_token_usage(result.ai_token_usage)

        return None  # Terminal reporter doesn't produce a file artifact

    def _render_token_usage(self, usage: dict) -> None:
        """Render AI token usage statistics as a Rich table."""
        self.console.print()
        token_table = Table(title="🔢 AI Token 消耗明细")
        token_table.add_column("阶段", style="bold")
        token_table.add_column("使用模型", style="cyan")
        token_table.add_column("提示词 Tokens", justify="right")
        token_table.add_column("生成 Tokens", justify="right")
        token_table.add_column("总 Tokens", justify="right")
        token_table.add_column("API 调用次数", justify="right")

        deep = usage.get("deep_review", {})
        enh = usage.get("enhancement", {})
        budget = usage.get("budget", {})
        models = usage.get("models", {})

        if deep.get("total_tokens", 0) > 0:
            token_table.add_row(
                "AI 深度审查 (Deep Review)",
                models.get("deep_review", "-"),
                f"{deep.get('prompt_tokens', 0):,}",
                f"{deep.get('completion_tokens', 0):,}",
                f"{deep.get('total_tokens', 0):,}",
                str(deep.get("api_calls", 0)),
            )

        if enh.get("total_tokens", 0) > 0:
            # Show summary and release review models if they differ
            summary_model = models.get("summary", "-")
            release_model = models.get("release_review", "-")
            if summary_model == release_model:
                model_display = summary_model
            else:
                model_display = f"{summary_model} / {release_model}"
            token_table.add_row(
                "AI 增强 (Enhancement)",
                model_display,
                f"{enh.get('prompt_tokens', 0):,}",
                f"{enh.get('completion_tokens', 0):,}",
                f"{enh.get('total_tokens', 0):,}",
                str(enh.get("api_calls", 0)),
            )

        total_tokens = usage.get("total_tokens", 0)
        if total_tokens > 0:
            token_table.add_row(
                "[bold]合计[/bold]",
                "",
                f"[bold]{usage.get('total_prompt_tokens', 0):,}[/bold]",
                f"[bold]{usage.get('total_completion_tokens', 0):,}[/bold]",
                f"[bold]{total_tokens:,}[/bold]",
                f"[bold]{usage.get('total_api_calls', 0)}[/bold]",
            )

        self.console.print(token_table)

        # Budget info
        if budget.get("max_tokens", 0) > 0:
            spent = budget.get("spent_tokens", 0)
            max_tok = budget.get("max_tokens", 0)
            pct = (spent / max_tok * 100) if max_tok > 0 else 0
            bar_color = "green" if pct < 70 else "yellow" if pct < 90 else "red"
            self.console.print(
                f"  [dim]Token 预算: [{bar_color}]{spent:,}[/{bar_color}] / {max_tok:,} "
                f"([{bar_color}]{pct:.1f}%[/{bar_color}] 已使用)[/dim]"
            )

    @staticmethod
    def _score_badge(score: float) -> str:
        if score >= 80:
            return f"[green]{score:.0f}/100[/green] [green]良好[/green]"
        elif score >= 50:
            return f"[yellow]{score:.0f}/100[/yellow] [yellow]警告[/yellow]"
        else:
            return f"[red]{score:.0f}/100[/red] [red]严重[/red]"

    @staticmethod
    def _status_badge(status: str) -> str:
        colors = {"good": "[green]健康[/green]", "warning": "[yellow]警告[/yellow]",
                 "critical": "[red]严重[/red]"}
        return colors.get(status, status)
