"""Init command: create initial configuration file."""

from pathlib import Path

from codeguardian.cli.output import console


def init_command() -> None:
    """Initialize a new CodeGuardian configuration file in current directory."""
    target = Path("codeguardian.toml")
    if target.exists():
        console.print("[yellow]codeguardian.toml already exists[/yellow]")
        return

    target.write_text(
        """[scan]
# Single AI switch (SSOT): ai_off | standard | ultra.
# Coverage (full vs incremental) is controlled by --incremental/--since, not here.
review_mode = "ai_off"
# languages = ["cpp", "java", "go", "lua", "python", "csharp", "javascript", "typescript", "rust"]

[reports]
formats = ["terminal", "json"]

[ai]
# ai.enabled is derived from scan.review_mode (standard/ultra enable AI).
provider = "openai"
model = "gpt-4o"
api_key_env = "CODEGUARDIAN_API_KEY"
# base_url = "https://api.openai.com/v1"

[risk]
default_threshold = 60.0

[gate]
config_path = "gate.yaml"

[test]
# coverage_files = ["coverage.json", "coverage.xml"]
# mutation_enabled = false

[rules]
# enabled = ["SQL-INJECTION-RISK", "COMMAND-INJECTION-RISK"]

# disabled = ["PRINT-DEBUG"]
# include_tags = ["sql"]
# exclude_tags = ["cleanup"]
# min_severity = "medium"
# baseline_path = ".codeguardian/latest.json"
""",
        encoding="utf-8",
    )
    console.print(f"[green]Created[/green] {target}")

    gate_example = Path("gate.yaml.example")
    if not gate_example.exists():
        gate_example.write_text(
            """quality_gate:
  rules:
    - name: "minimum_score"
      condition: "project.overall_score >= 60"
      action: fail
      message: "Project overall score is below 60"

    - name: "no_blocking_findings"
      condition: "findings.blocking == 0"
      action: fail
      message: "There are blocking findings"
""",
            encoding="utf-8",
        )
        console.print(f"[green]Created[/green] {gate_example} (example)")
