"""CLI application entry point using Typer."""

import typer

from codeguardian.cli.commands.analyze import analyze_command
from codeguardian.cli.commands.baseline import baseline_command
from codeguardian.cli.commands.config import config_command
from codeguardian.cli.commands.diff import diff_command
from codeguardian.cli.commands.doctor import doctor_command
from codeguardian.cli.commands.explain import explain_command
from codeguardian.cli.commands.gate import gate_command
from codeguardian.cli.commands.init import init_command
from codeguardian.cli.commands.report import report_command
from codeguardian.cli.commands.scan import scan_command
from codeguardian.cli.commands.trend import trend_command
from codeguardian.cli.commands.watch import watch_command

app = typer.Typer(
    name="codeguardian",
    help="CodeGuardian — AI-driven code quality auditing and engineering diagnostics",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.command("scan")(scan_command)
app.command("doctor")(doctor_command)
app.command("init")(init_command)
app.command("gate")(gate_command)
app.command("diff")(diff_command)
app.command("report")(report_command)
app.command("explain")(explain_command)
app.command("analyze")(analyze_command)
app.command("baseline")(baseline_command)
app.command("trend")(trend_command)
app.command("watch")(watch_command)
app.command("config")(config_command)

