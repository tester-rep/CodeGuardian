"""Scan command: execute full or incremental code quality audit."""

import asyncio
import shutil

import typer

from codeguardian.cli.common import (
    clone_repo,
    is_git_url,
    resolve_app_config_path,
    resolve_project_path,
    validate_path_exists,
)
from codeguardian.cli.output import console
from codeguardian.config.loader import load_app_config
from codeguardian.core.orchestrator import SUPPORTED_REPORT_FORMATS, Orchestrator
from codeguardian.core.planner import VALID_DIMENSIONS, find_unsupported_dimensions
from codeguardian.models.enums import Severity
from codeguardian.models.scan import ScanRequest


def scan_command(
    path: str = typer.Argument(
        ".",
        help="Path to the project directory or git repo URL (https/ssh) to scan",
    ),
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file (codeguardian.toml)",
    ),
    report: str | None = typer.Option(
        None,
        "--report",
        "-r",
        help=(
            "Report format(s): "
            f"{', '.join(SUPPORTED_REPORT_FORMATS)} (comma-separated, default from config)"
        ),
    ),
    depth: str | None = typer.Option(
        None,
        "--depth",
        "-d",
        help="[deprecated] 已废弃并忽略；引擎恒为全量。AI 强度用 --review-mode，覆盖度用 --incremental。",
    ),

    dimensions: str | None = typer.Option(
        None,
        "--dimensions",
        help=(
            "Comma-separated list of dimensions to analyze "
            f"(supported: {', '.join(VALID_DIMENSIONS)}, or all)"

        ),
    ),
    lang: str | None = typer.Option(
        None,
        "--lang",
        "-l",
        help="Comma-separated languages to include (e.g., python,java)",
    ),
    include_rule: str | None = typer.Option(
        None,
        "--include-rule",
        help="Comma-separated rule IDs to enable exclusively (e.g., SQL-INJECTION-RISK,EVAL-USAGE)",
    ),
    exclude_rule: str | None = typer.Option(
        None,
        "--exclude-rule",
        help="Comma-separated rule IDs to suppress",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Only include rules/findings at or above this severity: info, low, medium, high, critical",
    ),
    baseline: str | None = typer.Option(
        None,
        "--baseline",
        help="Path to a JSON report/baseline file used to suppress existing findings",
    ),
    incremental: bool = typer.Option(
        False,
        "--incremental",
        help="Only analyze files changed in the current Git diff scope",
    ),
    since: str | None = typer.Option(
        None,
        "--since",
        help="Git revision or date boundary for incremental scans (e.g. HEAD~5, 2026-04-01)",
    ),
    branch: str | None = typer.Option(
        None,
        "--branch",
        "-b",
        help="Git branch to checkout when cloning from a URL",
    ),
    clone_depth: int | None = typer.Option(
        None,
        "--clone-depth",
        help="Shallow clone depth (for faster cloning of large repos)",
    ),
    verify: str = typer.Option(
        "off",
        "--verify",
        help="Verification mode: off / generate / syntax / safe. safe runs only self-contained generated tests in a temporary sandbox.",
    ),
    review_mode: str | None = typer.Option(
        None,
        "--review-mode",
        help="AI review mode: ai_off (禁用AI) / standard (单-pass) / ultra (多探索+验证). Default from config.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Bypass AI deep review cache and force re-running AI on all chunks (cache file at .codeguardian/deep_review_cache.json is still updated with fresh results).",
    ),
    drop_false_positives: bool = typer.Option(
        False,
        "--drop-false-positives",
        help="Drop findings the AI verifier judges as false positives instead of keeping them downgraded to info. Findings with verdict=uncertain are always kept.",
    ),
) -> None:


    """Run a full code quality audit on the given project."""
    # Initialize logging so AI/provider messages are visible
    from codeguardian.utils.logging import setup_logging
    setup_logging()

    # Handle git URL: clone to temp directory
    cloned_dir = None
    if is_git_url(path):
        cloned_dir = clone_repo(path, branch=branch, depth=clone_depth)
        project_path = cloned_dir
    else:
        project_path = resolve_project_path(path)
        validate_path_exists(project_path)

    try:
        _run_scan(
            project_path=project_path,
            config=config,
            report=report,
            depth=depth,
            dimensions=dimensions,
            lang=lang,
            include_rule=include_rule,
            exclude_rule=exclude_rule,
            min_severity=min_severity,
            baseline=baseline,
            incremental=incremental,
            since=since,
            verify=verify,
            review_mode=review_mode,
            no_cache=no_cache,
            drop_false_positives=drop_false_positives,
        )
    finally:
        # Cleanup cloned repo
        if cloned_dir is not None:
            shutil.rmtree(cloned_dir.parent, ignore_errors=True)


def _run_scan(
    *,
    project_path,
    config,
    report,
    depth,
    dimensions,
    lang,
    include_rule,
    exclude_rule,
    min_severity,
    baseline,
    incremental,
    since,
    verify,
    review_mode=None,
    no_cache=False,
    drop_false_positives=False,
) -> None:
    """Internal scan execution (extracted for cleanup handling)."""
    from codeguardian.models.enums import Severity

    app_config = load_app_config(resolve_app_config_path(project_path, config))
    if include_rule is not None:
        app_config.rules.enabled = [rule.strip() for rule in include_rule.split(",") if rule.strip()]
    if exclude_rule is not None:
        app_config.rules.disabled = [rule.strip() for rule in exclude_rule.split(",") if rule.strip()]
    if min_severity is not None:
        try:
            app_config.rules.min_severity = Severity(min_severity.strip().lower())
        except ValueError:
            console.print(
                f"[red]Invalid severity:[/red] {min_severity}\n"
                "Valid options: info, low, medium, high, critical"
            )
            raise typer.Exit(code=1) from None


    if baseline is not None:
        app_config.rules.baseline_path = baseline

    if depth is not None:
        console.print(
            "[yellow][deprecated][/yellow] --depth 已废弃并忽略；引擎恒为全量。"
            "AI 强度请用 --review-mode，覆盖度请用 --incremental。"
        )

    if review_mode is not None:
        mode = review_mode.strip().lower()
        if mode not in {"ai_off", "standard", "ultra"}:
            console.print(
                f"[red]Invalid review mode:[/red] {review_mode}\n"
                "Valid options: ai_off, standard, ultra"
            )
            raise typer.Exit(code=1)
        app_config.apply_review_mode(mode)

    requested_dimensions = (
        [d.strip() for d in dimensions.split(",") if d.strip()]
        if dimensions
        else app_config.scan.dimensions
    )
    unsupported_dimensions = find_unsupported_dimensions(requested_dimensions)
    if unsupported_dimensions:
        console.print(
            "[red]Unsupported dimension(s):[/red] "
            f"{', '.join(sorted(set(unsupported_dimensions)))}\n"
            f"Supported: {', '.join(VALID_DIMENSIONS)}"
        )
        raise typer.Exit(code=1)

    report_formats = (
        [r.strip().lower() for r in report.split(",") if r.strip()]
        if report is not None
        else [fmt.strip().lower() for fmt in app_config.reports.formats if fmt.strip()]
    )
    if not report_formats:
        report_formats = ["terminal"]

    unsupported_formats = [fmt for fmt in report_formats if fmt not in SUPPORTED_REPORT_FORMATS]
    if unsupported_formats:
        console.print(
            "[red]Unsupported report format(s):[/red] "
            f"{', '.join(sorted(set(unsupported_formats)))}\n"
            f"Supported: {', '.join(SUPPORTED_REPORT_FORMATS)}"
        )
        raise typer.Exit(code=1)

    verify_mode = verify.strip().lower()
    if verify_mode not in {"off", "generate", "syntax", "safe"}:
        console.print(
            f"[red]Unsupported verification mode:[/red] {verify}\n"
            "当前支持: off, generate, syntax, safe。full 将在后续阶段实现。"
        )


        raise typer.Exit(code=1)

    request = ScanRequest(

        project_path=project_path,
        report_formats=report_formats,
        review_mode=app_config.scan.review_mode,
        dimensions=requested_dimensions,
        languages=[ln.strip() for ln in lang.split(",")] if lang else None,
        incremental=incremental or since is not None,
        since=since.strip() if since else None,
        verify_mode=verify_mode,
        no_cache=no_cache,
        drop_false_positives=drop_false_positives,
    )




    # Display AI configuration status
    if app_config.ai.enabled:
        console.print(f"  [green][OK][/green] AI 已启用 (provider={app_config.ai.provider}, model={app_config.ai.model})")
        if app_config.ai_verify.enabled:
            v_model = app_config.ai_verify.verify_model or app_config.ai.summary_model or app_config.ai.model
            drop_label = "丢弃 FP" if (drop_false_positives or app_config.ai_verify.drop_false_positives) else "降级保留 FP"
            console.print(f"  [green][OK][/green] AI Verifier 已启用 (model={v_model}, 策略={drop_label})")
        dr_model = app_config.deep_review.review_model or app_config.ai.model
        rm = app_config.deep_review.review_mode
        mode_label = "Ultra (多维探索+验证)" if rm == "ultra" else "Standard (单 pass)"
        console.print(f"  [green][OK][/green] AI Deep Review 已启用 (model={dr_model}, mode={mode_label})")
        if no_cache:
            console.print("  [yellow][!][/yellow] Deep Review 缓存已禁用 (--no-cache) — 所有 chunk 将重新调用 AI")
    else:
        console.print("  [yellow][!][/yellow] AI 未启用 (review_mode=ai_off) — 使用 --review-mode standard/ultra 开启 AI 检测")

    orchestrator = Orchestrator(app_config)
    result = asyncio.run(orchestrator.run_scan(request))

    console.print("\n[green]扫描完成[/green]")
    console.print(f"  项目: [cyan]{result.project_profile.project_name}[/cyan]")
    console.print(f"  综合评分: [bold]{result.project_profile.overall_score:.0f}[/bold]/100")
    console.print(f"  问题总数: {len(result.findings)}")
    if request.incremental:
        scope = request.since or app_config.git.since or "HEAD~1"
        console.print(f"  增量扫描范围: [magenta]{scope}[/magenta]")
    if request.verify_mode != "off":
        generated = sum(1 for finding in result.findings if finding.verification_artifacts)
        console.print(f"  验证模式: [cyan]{request.verify_mode}[/cyan]，已生成验证资产: {generated}")

    if result.report_artifacts:


        console.print("\n[bold]已生成报告:[/bold]")
        for artifact in result.report_artifacts:
            console.print(f"  [cyan]{artifact.format}[/cyan]: {artifact.path}")
