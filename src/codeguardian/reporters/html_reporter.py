"""HtmlReporter — generates an interactive HTML report with findings table and charts."""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from typing import TYPE_CHECKING

from codeguardian.models.report import ReportArtifact

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from codeguardian.models.finding import Finding
    from codeguardian.models.metric import Metric
    from codeguardian.models.profile import (
        DimensionScore,
        ModuleActionItem,
        ModuleProfile,
        ModuleReportIssue,
        ReleaseConclusion,
    )
    from codeguardian.models.scan import ScanResult



class HtmlReporter:
    """Generates a styled HTML report with CSS styling."""

    def render(self, result: ScanResult, output_dir: Path | None) -> ReportArtifact | None:
        if output_dir is None:
            return None

        target = output_dir / "report.html"
        profile = result.project_profile

        findings_html = self._render_findings(result.findings)

        dimension_html = self._render_dimensions(profile.dimension_scores)
        module_html = self._render_modules(profile.modules)
        module_reports_html = self._render_module_special_reports(profile.modules)
        release_html = self._render_release_conclusion(result.release_conclusion)

        severity_counts = self._count_severities(result.findings)
        metrics_summary = self._render_metrics(result.metrics)



        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeGuardian Report — {escape(profile.project_name)}</title>
    <style>
        :root {{
            --color-bg: #ffffff;
            --color-text: #333;
            --color-border: #ddd;
            --color-header-bg: #f4f4f4;
            --color-critical: #dc3545;
            --color-high: #ffc107;
            --color-medium: #28a745;
            --color-low: #17a2b8;
            --font-main: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}
        body {{ font-family: var(--font-main); margin: 24px; color: var(--color-text); background: var(--color-bg); line-height: 1.6; }}
        h1 {{ border-bottom: 3px solid #2563eb; padding-bottom: 12px; color: #2563eb; }}
        h2 {{ margin-top: 32px; color: #444; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }}
        .summary-card {{ background: var(--color-header-bg); border: 1px solid var(--color-border); border-radius: 8px; padding: 16px; text-align: center; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; }}
        .summary-card .label {{ font-size: 14px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        th, td {{ border: 1px solid var(--color-border); padding: 10px 12px; text-align: left; }}
        th {{ background: var(--color-header-bg); font-weight: 600; position: sticky; top: 0; }}
        tr:nth-child(even) {{ background: #fafafa; }}
        .severity-critical {{ color: var(--color-critical); font-weight: bold; }}
        .severity-high {{ color: #b8860b; font-weight: bold; }}
        .severity-medium {{ color: #22863d; }}
        .severity-low {{ color: #17a2b8; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; white-space: nowrap; }}
        .badge-must-fix {{ background: #ffe5e5; color: #c00; }}
        .badge-should-fix {{ background: #fff3cd; color: #856404; }}
        .badge-can-fix {{ background: #d1ecf1; color: #0c5460; }}
        .module-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-top: 16px; }}
        .module-card {{ border: 1px solid var(--color-border); border-radius: 10px; padding: 16px; background: #fff; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04); }}
        .module-card h3 {{ margin: 0 0 8px; }}
        .module-meta {{ color: #555; margin: 6px 0 10px; font-size: 14px; }}
        .subtle {{ color: #666; font-size: 14px; }}
        .reason-cell {{ font-size: 13px; line-height: 1.5; max-width: 480px; word-break: break-word; }}
        .reason-cell a {{ color: #2563eb; text-decoration: none; }}
        .reason-cell a:hover {{ text-decoration: underline; }}
        .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--color-border); color: #999; font-size: 13px; }}

    </style>
</head>
<body>
    <h1>{escape(profile.project_name)} — CodeGuardian 审计报告</h1>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="value">{self._score_style(profile.overall_score)}</div>
            <div class="label">综合评分</div>
        </div>
        <div class="summary-card">
            <div class="value">{len(result.findings)}</div>
            <div class="label">问题总数</div>
        </div>
        <div class="summary-card">
            <div class="value">{severity_counts['critical']}</div>
            <div class="label">严重 (Critical)</div>
        </div>
        <div class="summary-card">
            <div class="value">{severity_counts['high']}</div>
            <div class="label">高危 (High)</div>
        </div>
        <div class="summary-card">
            <div class="value">{profile.total_files}</div>
            <div class="label">扫描文件数</div>
        </div>
        <div class="summary-card">
            <div class="value">{profile.total_loc}</div>
            <div class="label">代码行数</div>
        </div>
    </div>

    <h2>维度评分</h2>
    {dimension_html}

    <h2>总体摘要</h2>
    <p>{escape(result.ai_summary or '暂无总体摘要。')}</p>

    <h2>发布结论</h2>
    {release_html}

    <h2>高风险模块</h2>
    {module_html}

    <h2>模块专项报告</h2>
    {module_reports_html}

    <h2>问题列表（共 {len(result.findings)} 项）</h2>



    {findings_html}

    <h2>关键指标</h2>
    {metrics_summary}

    {self._render_token_usage(result.ai_token_usage)}

    <div class="footer">
        由 CodeGuardian CLI v{result.schema_version} 于 {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC 生成。
        Schema 版本: {result.schema_version}
    </div>
</body>
</html>
"""
        target.write_text(html, encoding="utf-8")
        return ReportArtifact(format="html", path=str(target),
                           size_bytes=target.stat().st_size,
                           generated_at=datetime.now(UTC).isoformat())


    @staticmethod
    def _score_style(score: float) -> str:
        if score >= 80:
            return f'<span style="color:#28a745">{score:.0f}</span>'
        elif score >= 50:
            return f'<span style="color:#ffc107">{score:.0f}</span>'
        else:
            return f'<span style="color:#dc3545">{score:.0f}</span>'

    @staticmethod
    def _count_severities(findings: Sequence[Finding]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            s = f.severity.value
            if s in counts:
                counts[s] += 1
        return counts

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
            "test-confirmed": "测试复现",
            "static-confirmed": "静态确认",
            "likely": "证据较强",
            "suspected": "疑似风险",
            "needs-review": "需要复核",
        }
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _verification_status_label(value: str) -> str:
        mapping = {
            "unverified": "未测试验证",
            "test-generated": "已生成测试资产",
            "syntax-checked": "语法已检查",
            "static-confirmed": "静态已确认",
            "test-confirmed": "测试已复现",
            "not-reproduced": "测试未复现",
            "inconclusive": "验证不确定",
            "skipped": "已跳过验证",
            "skipped-unsafe": "因安全风险跳过",
            "skipped-no-runner": "缺少运行器",
            "skipped-needs-network": "需要网络已跳过",
            "skipped-has-side-effects": "可能有副作用已跳过",
            "skipped-no-safe-test": "无安全自包含测试",


        }
        return f"{mapping[value]} ({value})" if value in mapping else value

    @staticmethod
    def _render_findings(findings: Sequence[Finding]) -> str:

        # ── Severity / Priority 中文映射 ──
        sev_zh = {"critical": "严重", "high": "高危", "medium": "中等", "low": "低危", "info": "提示"}
        pri_zh = {"must-fix": "必须修复", "should-fix": "建议修复", "can-fix": "可选修复"}
        engine_zh = {
            "security": "安全引擎", "defect": "缺陷引擎",
            "complexity": "复杂度引擎", "performance": "性能引擎",
            "testing": "测试引擎", "git_evolution": "演进引擎",
            "deep_review": "AI 深度审查",
        }

        sorted_findings = sorted(findings, key=lambda f: (f.severity.weight, f.evidence_rank), reverse=True)


        rows = ""
        for f in sorted_findings[:100]:  # Limit to first 100 for HTML size
            sev_class = f"severity-{f.severity.value}"

            badge_class = f"badge-{f.risk_priority}"
            sev_label = sev_zh.get(f.severity.value, f.severity.value)
            pri_label = pri_zh.get(f.risk_priority, f.risk_priority)
            source_group = "ai" if f.source_engine == "deep_review" or f.source_engine.startswith("ai") else "local"
            source_prefix = "AI" if source_group == "ai" else "本地引擎"
            source_label = f"{source_prefix} / {engine_zh.get(f.source_engine, f.source_engine)}"
            location = f"{f.location.file_path}:{f.location.line_start or ''}"
            evidence_label = HtmlReporter._evidence_level_label(f.evidence_level)
            verification_label = HtmlReporter._verification_status_label(f.verification_status)
            evidence_html = f"{escape(evidence_label)}<br><small>{escape(verification_label)}</small>"
            if f.verification_summary:
                evidence_html += f"<br><small>{escape(f.verification_summary[:120])}</small>"
            if f.verification_artifacts:
                first_artifact = f.verification_artifacts[0]
                artifact_code = str(first_artifact.get("code", ""))[:1200]
                artifact_kind = str(first_artifact.get("kind", "verification-asset"))
                artifact_conclusion = str(first_artifact.get("conclusion", "not-run"))
                evidence_html += (
                    f"<details><summary>验证资产: {escape(artifact_kind)} / {escape(artifact_conclusion)}</summary>"
                    f"<pre style=\"white-space: pre-wrap; max-width: 520px;\">{escape(artifact_code)}</pre></details>"
                )
            # Build reason: prefer root_cause, fall back to first evidence content


            reason = f.root_cause or ""
            if not reason and f.evidences:
                for ev in f.evidences:
                    if ev.type == "rule_match" and ev.content:
                        reason = ev.content
                        break
            # Format reason as multi-line HTML
            reason_html = "<br>".join(escape(line) for line in reason.split("\n")) if reason else "<span class=\"subtle\">—</span>"
            # Fix suggestion
            fix_html = "<br>".join(escape(line) for line in f.fix_suggestion.split("\n")) if f.fix_suggestion else "<span class=\"subtle\">—</span>"
            rows += f"""
            <tr data-source="{source_group}">
                <td><code>{f.id}</code></td>
                <td>{escape(f.title[:120])}</td>
                <td class="{sev_class}">{sev_label} ({f.severity.value})</td>
                <td><span class="{badge_class}">{pri_label}</span></td>
                <td class="reason-cell">{evidence_html}</td>
                <td><small>{escape(location)}</small></td>
                <td class="reason-cell">{reason_html}</td>

                <td class="reason-cell">{fix_html}</td>
                <td><small>{source_label}</small></td>
            </tr>"""

        if not rows:
            return "<p>暂无问题。</p>"

        filter_html = """
        <div style="margin: 12px 0; display: flex; gap: 8px; align-items: center;">
            <label for="source-filter"><strong>按检测来源过滤：</strong></label>
            <select id="source-filter" onchange="cgFilterSource(this.value)">
                <option value="all">全部</option>
                <option value="local">仅本地引擎</option>
                <option value="ai">仅 AI</option>
            </select>
        </div>
        """
        table_html = (
            "<table id=\"findings-table\"><thead><tr>"
            "<th>ID</th><th>标题</th><th>严重度</th><th>优先级</th><th>证据等级</th>"
            "<th>位置</th><th>原因分析</th><th>修复建议</th><th>检测来源</th>"

            "</tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
        script_html = """
        <script>
        function cgFilterSource(value) {
            document.querySelectorAll('#findings-table tbody tr').forEach(function(row) {
                row.style.display = (value === 'all' || row.dataset.source === value) ? '' : 'none';
            });
        }
        </script>
        """
        return filter_html + table_html + script_html

    @staticmethod
    def _render_dimensions(dimension_scores: Sequence[DimensionScore]) -> str:
        if not dimension_scores:
            return "<p>暂无维度评分。</p>"

        dim_zh = {
            "scale": "规模 (scale) — 代码体量与文件数",
            "complexity": "复杂度 (complexity) — 函数分支与嵌套复杂程度",
            "defects": "缺陷 (defects) — 潜在 bug 和代码问题",
            "security": "安全 (security) — 安全漏洞与敏感信息",
            "performance": "性能 (performance) — 性能隐患与资源使用",
            "testing": "测试 (testing) — 测试覆盖与质量",
            "maintainability": "可维护性 (maintainability) — 代码整洁与可维护程度",
            "evolution": "演进 (evolution) — 代码变更历史与热点",
        }
        status_zh = {
            "good": "✅ 良好 (good)",
            "warning": "⚠️ 警告 (warning)",
            "critical": "❌ 严重 (critical)",
        }

        rows = ""
        for ds in dimension_scores:
            dim_label = dim_zh.get(ds.dimension, ds.dimension)
            status_label = status_zh.get(ds.status, ds.status)
            rows += f"""
            <tr>
                <td>{escape(dim_label)}</td>
                <td>{ds.score:.0f}</td>
                <td>{status_label}</td>
                <td>{ds.findings_count}</td>
            </tr>"""
        return f"<table><thead><tr><th>维度</th><th>评分</th><th>状态</th><th>问题数</th></tr></thead><tbody>{rows}</tbody></table>"

    @staticmethod
    def _render_metrics(metrics: Sequence[Metric]) -> str:

        if not metrics:
            return "<p>暂无指标数据。</p>"

        metric_zh = {
            "loc": "代码总行数 (LOC)",
            "sloc": "有效代码行数 (SLOC)",
            "file_count": "文件数 (file_count)",
            "comment_ratio": "注释率 (comment_ratio)",
            "duplication_rate": "重复率 (duplication_rate)",
            "cyclomatic_complexity": "圈复杂度 (cyclomatic_complexity)",
            "cognitive_complexity": "认知复杂度 (cognitive_complexity)",
            "nesting_depth": "嵌套深度 (nesting_depth)",
            "param_count": "参数数量 (param_count)",
            "line_coverage": "行覆盖率 (line_coverage)",
            "branch_coverage": "分支覆盖率 (branch_coverage)",
            "function_coverage": "函数覆盖率 (function_coverage)",
            "change_line_coverage": "变更行覆盖率 (change_line_coverage)",
            "churn_score": "变更频率 (churn_score)",
            "risk_score": "风险评分 (risk_score)",
            "core_module_score": "核心模块评分 (core_module_score)",
            "maintainability_index": "可维护性指数 (maintainability_index)",
        }
        engine_zh = {
            "structure": "结构分析", "metrics": "度量分析",
            "security": "安全引擎", "defect": "缺陷引擎",
            "complexity": "复杂度引擎", "performance": "性能引擎",
            "testing": "测试引擎", "git_evolution": "演进引擎",
        }

        key_metrics = [m for m in metrics if m.target_id == "project"][:15]
        rows = ""
        for m in key_metrics:
            name_label = metric_zh.get(m.metric_name, m.metric_name)
            engine_label = engine_zh.get(m.source_engine, m.source_engine)
            val_str = f"{m.value}" + (f" {m.unit}" if m.unit else "")
            rows += f"<tr><td>{escape(name_label)}</td><td>{val_str}</td><td>{engine_label}</td></tr>"
        return f"<table><thead><tr><th>指标</th><th>值</th><th>来源</th></tr></thead><tbody>{rows}</tbody></table>"

    @classmethod
    def _render_modules(cls, modules: Sequence[ModuleProfile]) -> str:

        if not modules:
            return "<p>暂无模块信息。</p>"
        dim_zh = {
            "scale": "规模", "complexity": "复杂度", "defects": "缺陷", "security": "安全",
            "performance": "性能", "testing": "测试", "maintainability": "可维护性", "evolution": "演进",
        }
        rows = ""
        for module in modules[:8]:
            dimensions = ", ".join(
                f"{dim_zh.get(name, name)}:{score:.0f}"
                for name, score in list(module.dimension_scores.items())[:3]
            ) or "-"
            coverage = f"{module.test_coverage:.0f}%" if module.test_coverage is not None else "-"
            rows += f"""
            <tr>
                <td><code>{escape(module.path)}</code></td>
                <td>{module.risk_score:.0f}</td>
                <td>{escape(cls._risk_level_label(module.risk_level))}</td>
                <td>{len(module.findings)}</td>
                <td>{coverage}</td>
                <td>{escape(dimensions)}</td>
                <td>{escape(cls._recommendation_label(module.recommendation))}</td>
            </tr>"""
        return (
            "<table><thead><tr><th>模块</th><th>评分</th><th>风险等级</th><th>问题数</th>"
            "<th>覆盖率</th><th>关键维度</th><th>建议</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    @classmethod
    def _render_module_special_reports(cls, modules: Sequence[ModuleProfile]) -> str:

        if not modules:
            return "<p>暂无模块专项报告。</p>"
        cards = []
        for module in modules[:4]:
            status_zh_map = {
                "unavailable": "未接入", "good": "良好",
                "warning": "警告", "critical": "严重",
            }
            trend_zh_map = {
                "unknown": "未知", "rising": "上升", "stable": "稳定",
            }
            testing_bits = [
                f"行覆盖率 {module.testing_profile.line_coverage:.0f}%" if module.testing_profile.line_coverage is not None else "行覆盖率 —",
                f"分支覆盖率 {module.testing_profile.branch_coverage:.0f}%" if module.testing_profile.branch_coverage is not None else "分支覆盖率 —",
                f"函数覆盖率 {module.testing_profile.function_coverage:.0f}%" if module.testing_profile.function_coverage is not None else "函数覆盖率 —",
                f"状态: {status_zh_map.get(module.testing_profile.status, module.testing_profile.status)}",
            ]
            stability_bits = [
                f"变更频率 {module.historical_stability.churn_score:.0f}" if module.historical_stability.churn_score is not None else "变更频率 —",
                f"趋势: {trend_zh_map.get(module.historical_stability.churn_trend, module.historical_stability.churn_trend)}",
                f"热点: {'是' if module.historical_stability.hotspot else '否'}",
            ]
            top_findings = cls._render_module_issue_list(module.top_findings)
            actions = cls._render_module_action_items(module.action_items)
            architecture_note = escape(module.architecture_profile.notes[0]) if module.architecture_profile.notes else "暂无架构摘要"
            cards.append(
                f"""
                <section class=\"module-card\">
                    <h3><code>{escape(module.path)}</code></h3>
                    <div class=\"module-meta\">{escape(cls._risk_level_label(module.risk_level))} · {module.risk_score:.0f}/100 · {module.file_count} 文件 · {module.function_count} 函数 · LOC {module.loc} / SLOC {module.sloc}</div>
                    <p><strong>测试覆盖：</strong> {escape(', '.join(testing_bits))}</p>
                    <p><strong>历史稳定性：</strong> {escape(', '.join(stability_bits))}</p>
                    <p><strong>架构：</strong> <span class=\"subtle\">{architecture_note}</span></p>
                    <h4>主要问题</h4>
                    {top_findings}
                    <h4>待办事项</h4>
                    {actions}
                </section>
                """
            )
        return f"<div class=\"module-grid\">{''.join(cards)}</div>"

    @staticmethod
    def _render_module_issue_list(items: Sequence[ModuleReportIssue]) -> str:
        if not items:
            return "<p class=\"subtle\">暂无集中性问题。</p>"

        rows = [
            f"<li><strong>{escape(item.title)}</strong> <small>({escape(HtmlReporter._severity_label(item.severity))}/{escape(HtmlReporter._priority_label(item.priority))} · {escape(item.location)})</small></li>"
            for item in items[:3]
        ]
        return f"<ul>{''.join(rows)}</ul>"

    @staticmethod
    def _render_module_action_items(items: Sequence[ModuleActionItem]) -> str:
        if not items:
            return "<p class=\"subtle\">暂无待办事项。</p>"
        rows = [
            f"<li><strong>{escape(HtmlReporter._priority_label(item.priority))}</strong> · {escape(item.summary)}</li>"
            for item in items[:4]
        ]
        return f"<ul>{''.join(rows)}</ul>"

    @classmethod
    def _render_release_conclusion(cls, release_conclusion: ReleaseConclusion | None) -> str:

        if release_conclusion is None:

            return "<p>未知</p>"
        summary = escape(release_conclusion.review_summary or "暂无发布评审摘要。")
        blocking = cls._render_release_items(
            release_conclusion.blocking_items,
            primary_key="title",
            secondary_key="location",
        )
        residual = cls._render_release_items(
            release_conclusion.residual_risks,
            primary_key="title",
            secondary_key="severity",
        )
        verifications = cls._render_release_items(
            release_conclusion.suggested_verifications,
            primary_key="suggestion",
        )
        monitoring = cls._render_release_items(
            release_conclusion.post_release_monitoring,
            primary_key="suggestion",
        )
        return f"""
        <p><strong>{escape(cls._verdict_label(release_conclusion.verdict))}</strong></p>
        <p><strong>评审（{escape(cls._review_source_label(release_conclusion.review_source))}）：</strong> {summary}</p>
        <h3>阻塞项</h3>
        {blocking}
        <h3>残余风险</h3>
        {residual}
        <h3>建议验证项</h3>
        {verifications}
        <h3>发布后监控</h3>
        {monitoring}
        """

    @staticmethod
    def _render_release_items(
        items: Sequence[Mapping[str, object]],
        primary_key: str,
        secondary_key: str | None = None,
    ) -> str:

        if not items:
            return "<p>暂无补充说明。</p>"
        rows = []
        for item in items[:5]:
            primary = item.get(primary_key)
            if not primary:
                continue
            text = escape(str(primary))
            secondary = item.get(secondary_key) if secondary_key else None
            if secondary:
                secondary_text = str(secondary)
                if secondary_key == "severity":
                    secondary_text = HtmlReporter._severity_label(secondary_text)
                elif secondary_key == "priority":
                    secondary_text = HtmlReporter._priority_label(secondary_text)
                text = f"{text} <small>({escape(secondary_text)})</small>"
            rows.append(f"<li>{text}</li>")
        return f"<ul>{''.join(rows)}</ul>" if rows else "<p>暂无补充说明。</p>"

    @staticmethod
    def _render_token_usage(ai_token_usage: dict | None) -> str:
        """Render AI token usage statistics as an HTML section."""
        if not ai_token_usage:
            return ""

        deep = ai_token_usage.get("deep_review", {})
        enh = ai_token_usage.get("enhancement", {})
        budget = ai_token_usage.get("budget", {})
        models = ai_token_usage.get("models", {})
        total_tokens = ai_token_usage.get("total_tokens", 0)

        if total_tokens == 0:
            return ""

        rows = ""
        if deep.get("total_tokens", 0) > 0:
            deep_model = models.get("deep_review", "-")
            rows += f"""
            <tr>
                <td>AI 深度审查 (Deep Review)</td>
                <td>{deep_model}</td>
                <td>{deep.get('prompt_tokens', 0):,}</td>
                <td>{deep.get('completion_tokens', 0):,}</td>
                <td>{deep.get('total_tokens', 0):,}</td>
                <td>{deep.get('api_calls', 0)}</td>
            </tr>"""

        if enh.get("total_tokens", 0) > 0:
            summary_model = models.get("summary", "-")
            release_model = models.get("release_review", "-")
            if summary_model == release_model:
                enh_model = summary_model
            else:
                enh_model = f"{summary_model} / {release_model}"
            rows += f"""
            <tr>
                <td>AI 增强 (Enhancement)</td>
                <td>{enh_model}</td>
                <td>{enh.get('prompt_tokens', 0):,}</td>
                <td>{enh.get('completion_tokens', 0):,}</td>
                <td>{enh.get('total_tokens', 0):,}</td>
                <td>{enh.get('api_calls', 0)}</td>
            </tr>"""

        rows += f"""
            <tr style="font-weight:bold; background:#e8f4fd;">
                <td>合计</td>
                <td></td>
                <td>{ai_token_usage.get('total_prompt_tokens', 0):,}</td>
                <td>{ai_token_usage.get('total_completion_tokens', 0):,}</td>
                <td>{total_tokens:,}</td>
                <td>{ai_token_usage.get('total_api_calls', 0)}</td>
            </tr>"""

        budget_html = ""
        max_tok = budget.get("max_tokens", 0)
        spent = budget.get("spent_tokens", 0)
        if max_tok > 0:
            pct = spent / max_tok * 100 if max_tok > 0 else 0
            bar_color = "#28a745" if pct < 70 else "#ffc107" if pct < 90 else "#dc3545"
            budget_html = f"""
            <p style="margin-top:8px; color:#666; font-size:14px;">
                Token 预算: <span style="color:{bar_color}; font-weight:bold;">{spent:,}</span> / {max_tok:,}
                (<span style="color:{bar_color};">{pct:.1f}%</span> 已使用)
            </p>"""

        return f"""
        <h2>🔢 AI Token 消耗明细</h2>
        <table>
            <thead><tr>
                <th>阶段</th><th>使用模型</th><th>提示词 Tokens</th><th>生成 Tokens</th>
                <th>总 Tokens</th><th>API 调用次数</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
        {budget_html}
        """


