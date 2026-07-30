<p align="center">
  <h1 align="center">CodeGuardian CLI</h1>
  <p align="center">
    <strong>Multi-language static analysis with cross-function intelligence and AI-powered deep review</strong>
  </p>
  <p align="center">
    <a href="https://pypi.org/project/codeguardian/"><img src="https://img.shields.io/pypi/v/codeguardian?color=blue&label=PyPI" alt="PyPI version"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License"></a>
    <a href="https://github.com/nicq-codeguardian/CodeGuardian-CLI/actions"><img src="https://img.shields.io/github/actions/workflow/status/nicq-codeguardian/CodeGuardian-CLI/ci.yml?label=tests" alt="Tests"></a>
    <a href="https://github.com/nicq-codeguardian/CodeGuardian-CLI/stargazers"><img src="https://img.shields.io/github/stars/nicq-codeguardian/CodeGuardian-CLI?style=flat" alt="Stars"></a>
  </p>
  <p align="center">
    <a href="README.md">English</a> | <a href="README_zh.md">中文文档</a>
  </p>
</p>

---

CodeGuardian is a **static code analysis CLI** that goes beyond single-file lint checks. It builds a **Project Call Graph Index (PCI)** to detect bugs spanning function and file boundaries — null propagation, resource leaks, taint flow, exception safety violations — then optionally feeds high-risk findings through an **AI verification and deep review pipeline** to suppress false positives and surface architectural issues that traditional tools miss.

One command gives you a full audit across code quality, security, performance, architecture, testing coverage, and evolution risk — with actionable findings scored by severity, confidence, and blast-radius impact.

## Why CodeGuardian?

| Traditional Linters | CodeGuardian |
|---|---|
| Single-file, single-function scope | Cross-function, cross-file call graph analysis |
| Pattern matching on syntax | Dataflow tracking (null, taint, resources, exceptions) |
| Fixed rule sets | 12 parallel engines + pluggable AI review |
| Binary pass/fail | Severity + confidence + impact scoring with blast-radius |
| No business context | Business process flow analysis (transactions, auth, timeouts) |
| Manual triage | AI-powered false positive suppression |

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Architecture](#architecture)
- [Usage](#usage)
- [Review Modes & Coverage](#review-modes--coverage)
- [Supported Languages](#supported-languages)
- [Analysis Engines](#analysis-engines)
- [Cross-Function Detection](#cross-function-detection)
- [Business Process Analysis](#business-process-analysis)
- [AI Features](#ai-features)
- [CI/CD Integration](#cicd-integration)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

```bash
# 1. Install
pip install codeguardian

# 2. Scan your project
codeguardian scan .

# 3. Check release readiness
codeguardian gate .
```

That's it. No configuration required for basic usage — CodeGuardian auto-detects languages, frameworks, and build systems.

### From Source

```bash
git clone https://github.com/tester-rep/CodeGuardian.git
cd CodeGuardian-CLI
pip install -e ".[dev]"
codeguardian doctor   # verify installation
```

---

## Features

### Core Analysis

- **12 parallel analysis engines** — structure, metrics, complexity, defect, security, performance, testing, git evolution, config risk, OO design, dependency, cross-function
- **Project Call Graph Index (PCI)** — resolves call targets across files with confidence-weighted edges, propagates function summaries (null/throw/resource/taint) along call chains
- **Business process analysis** — BFS from entry points (HTTP handlers, MQ consumers, CLI commands) to detect flow-level architectural issues
- **Impact scoring** — blast-radius per finding using caller count from the call graph
- **Incremental caching** — content-hash based PCI cache for fast re-scans on large codebases

### Intelligence Layer

- **AI Verifier** — two-pass false-positive re-check with severity-tiered context windows and call-graph evidence collection
- **AI Deep Review** — LLM-powered code review with two modes: standard (single pass) and ultra (3 parallel explorers + 1 critic agent)
- **Rule system** — configurable rule registry with enabled/disabled lists, tag filters, severity thresholds, and baseline suppression

### Developer Experience

- **Multi-format output** — Rich terminal, JSON, HTML, SARIF (for CI), PDF
- **Quality gate** — YAML-based release gate evaluation with fail/warn conditions
- **Auto-detection** — language, framework, build system, test framework detection from project files
- **Semgrep integration** — optional additional SAST coverage via external Semgrep CLI

---

## Architecture

```
                                    codeguardian scan .
                                           |
                                           v
+---------------------------------------------------------------------------+
|                              CLI (Typer + Rich)                            |
+-------------------------------------+-------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------+
|                             Orchestrator                                   |
|                                                                           |
|  +--------------+  +---------+  +------------+  +-----------------------+ |
|  |   Project    |  | Planner |  |PCI Builder |  |      Scheduler        | |
|  |   Detector   |->|         |->| (CallGraph)|->| (async concurrency)   | |
|  +--------------+  +---------+  +------------+  +-----------+-----------+ |
|                                                             |             |
|  +----------------------------------------------------------v----------+  |
|  |                   12 Analysis Engines (parallel)                     |  |
|  |  structure | metrics | complexity | defect | security | performance |  |
|  |  testing | git_evolution | config_risk | oo_design | dependency     |  |
|  |  cross_function                                                     |  |
|  +----------------------------------------------------------+----------+  |
|                                                             |             |
|  +------------+  +------------+  +-------------+  +---------v----------+  |
|  | Normalizer |->| Validator  |->| Prioritizer |->|  Impact Scorer     |  |
|  +------------+  +------------+  +-------------+  +---------+----------+  |
|                                                             |             |
|  +-------------------+  +---------------------+  +----------v---------+   |
|  | Process Enricher  |->|    AI Verifier      |->|  AI Deep Review    |   |
|  | (biz flow context)|  | (2-pass FP filter)  |  | (LLM code review)  |   |
|  +-------------------+  +---------------------+  +----------+---------+   |
|                                                             |             |
|  +----------------------------------------------------------v----------+  |
|  |             Reporters: Terminal | JSON | HTML | SARIF | PDF          |  |
|  +---------------------------------------------------------------------+  |
+---------------------------------------------------------------------------+
```

---

## Usage

### Basic Scan

```bash
# Scan current directory with default settings (standard depth)
codeguardian scan .

# Scan a specific path
codeguardian scan /path/to/project
```

### Scan with Options

```bash
# Full scan with AI review + multiple output formats
codeguardian scan . --review-mode standard --report terminal,json,html

# Incremental scan (only changed files; call graph stays full for cross-function)
codeguardian scan . --incremental --since HEAD~1

# Ultra review mode (3 explorers + 1 critic)
codeguardian scan . --review-mode ultra

# Disable AI entirely (static engines still run in full)
codeguardian scan . --review-mode ai_off

# Drop AI-confirmed false positives from report
codeguardian scan . --review-mode standard --drop-false-positives

# Bypass cache for fresh analysis
codeguardian scan . --no-cache
```

### Quality Gate

```bash
# Evaluate release readiness against gate.yaml rules
codeguardian gate .
```

Example output:

```
 GATE RESULT: FAIL

  x critical_findings <= 0          actual: 2    FAIL
  x high_findings <= 5              actual: 8    FAIL
  . test_coverage >= 60%            actual: 73%  PASS
  . security_score >= 70            actual: 82   PASS
```

### Other Commands

```bash
# Check environment setup and dependencies
codeguardian doctor

# Initialize codeguardian.toml with defaults
codeguardian init

# Explain a specific rule
codeguardian explain NULL-PROP-UNCHECKED

# Diff analysis between two commits/branches
codeguardian diff main..feature-branch

# Watch mode (re-scan on file changes)
codeguardian watch .

# Generate a report from a previous scan
codeguardian report --format sarif --output results.sarif

# Set a baseline (suppress existing findings)
codeguardian baseline .

# View finding trends over time
codeguardian trend .
```

---

## Review Modes & Coverage

Two orthogonal axes replace the old single `--depth` flag:

**AI review mode** (`--review-mode`, or `scan.review_mode`) — the single AI switch:

| Mode | Static Engines | PCI | AI Deep Review | Use Case |
|------|----------------|-----|----------------|----------|
| `ai_off` | All 11 | Yes | No | Fast, offline, no API key |
| `standard` | All 11 | Yes | Single-pass | Default CI pipeline scan |
| `ultra` | All 11 | Yes | Multi-explorer + critic | Release candidate review |

**Coverage** (`--incremental` / `--since`) — independent of review mode:

| Flag | Files analyzed | Notes |
|------|----------------|-------|
| _(none)_ | Full project | Default |
| `--incremental [--since REV]` | Changed files only | Call graph (PCI) is still built on the **full** project so cross-function analysis stays complete; cross-function findings are then narrowed to changed files |

```bash
codeguardian scan . --review-mode ai_off              # static-only
codeguardian scan . --review-mode standard            # default
codeguardian scan . --review-mode ultra --incremental # deep AI on a diff
```

---

## Supported Languages

| Language | AST Parser | Cross-Function | Import Resolution | Maturity |
|----------|-----------|----------------|-------------------|----------|
| C++ | tree-sitter | Yes | Header includes | Stable |
| Java | tree-sitter | Yes | Package imports | Stable |
| Go | tree-sitter | Yes | Module imports | Stable |
| Python | tree-sitter | Yes | Module imports | Stable |
| JavaScript | tree-sitter | Yes | ES/CommonJS imports | Stable |
| TypeScript | tree-sitter | Yes | ES imports + types | Stable |
| Lua | tree-sitter | Yes | require() | Stable |
| C# | tree-sitter | Yes | using/namespace | Stable |
| Rust | tree-sitter | Partial | use/mod | Beta |

CodeGuardian auto-detects project languages from file extensions and build system configuration. No manual language selection needed.

---

## Analysis Engines

Each engine implements the `AnalyzerEngine` protocol and runs concurrently:

| Engine | Focus | Key Findings |
|--------|-------|--------------|
| **structure** | Code organization | Module coupling, circular dependencies, god classes |
| **metrics** | Quantitative measures | LOC, function count, nesting depth, cognitive complexity |
| **complexity** | Cyclomatic/cognitive complexity | Over-complex functions, deeply nested logic |
| **defect** | Common bug patterns | Null derefs, off-by-one, dead code, type confusion |
| **security** | Vulnerability detection | Injection, hardcoded secrets, unsafe deserialization |
| **performance** | Runtime efficiency | N+1 queries, unbounded allocations, blocking I/O in async |
| **testing** | Test quality | Low coverage indicators, missing edge cases, flaky patterns |
| **git_evolution** | Change risk | Hotspot files, churn correlation, recent breakage zones |
| **config_risk** | Configuration issues | Exposed secrets, insecure defaults, missing validation |
| **oo_design** | Design quality | SOLID violations, anemic models, deep inheritance |
| **dependency** | Supply chain | Outdated deps, known CVEs, license conflicts |
| **cross_function** | Inter-procedural bugs | Null propagation, resource leaks, taint flow (see below) |

---

## Cross-Function Detection

The cross-function engine uses the **Project Call Graph Index (PCI)** to detect bugs that span multiple functions and files — the class of bugs that single-file linters fundamentally cannot catch.

### How PCI Works

```
1. Parse all files        -> extract structure (tree-sitter AST), incl. class extends/implements
2. Build SymbolTable      -> all functions/methods/classes + inheritance, O(1) lookup
3. Resolve imports        -> language-specific import resolvers
4. Extract call sites     -> from all function bodies
5. Resolve targets        -> build CallGraph with confidence-weighted edges (uses inheritance to resolve super/interface virtual calls)
6. Compute summaries      -> null/throw/resource/taint per function
7. Propagate              -> fixpoint along call edges (max 3 passes)
```

> Inheritance (`extends`/`implements`) is extracted by the parsers and registered in the symbol table, so `self.method()` / `this.method()` calls resolve to methods defined in a parent class (virtual-call resolution). Extraction currently covers Python / Java / JavaScript / TypeScript / Go / C++. Go has no `extends`, so struct/interface **embedding** is treated as a base; C++ supports multiple inheritance, so every base in a `base_class_clause` is registered.

### Debug: export the call graph

Set `CODEGUARDIAN_PCI_DUMP=<path>` before a scan to dump the call graph as JSON
(nodes, `call_edges`, `type_edges` (inherits/implements)) for troubleshooting
cross-function resolution. Off by default; no effect on scan performance.

```bash
CODEGUARDIAN_PCI_DUMP=graph.json codeguardian scan ./src
```

### Detection Rules

| Rule ID | Category | What It Catches |
|---------|----------|-----------------|
| `NULL-PROP-UNCHECKED` | null-safety | Callee may return null, caller uses result without null check |
| `RESOURCE-NEVER-CLOSED-XFUNC` | resource-leak | Resource acquired but never released in any reachable call path |
| `RESOURCE-LEAK-ON-EXCEPTION` | exception-safety | Resource acquired, callee may throw, no finally/defer/with guard |
| `TAINT-CROSS-FUNCTION` | injection | User input reaches dangerous sink via call chain without sanitization |
| `UNCAUGHT-EXCEPTION-PROPAGATION` | exception-safety | Exception escapes to entry point with no catch on any path |
| `LOCK-LEAKED-ON-CALLEE-THROW` | concurrency | Lock held when callee may throw, no finally protecting release |
| `ERROR-RETURN-IGNORED` | api-contract | Error return type (Go `error`, Java `Optional`) silently ignored |

### Example

```java
// FileA.java
public Connection getConnection() {
    return pool.acquire();  // may return null when pool exhausted
}

// FileB.java - called 3 levels deep in the call chain
public void processOrder(String orderId) {
    Connection conn = service.getConnection();
    conn.execute(query);  // <- NULL-PROP-UNCHECKED: conn may be null
}
```

CodeGuardian traces this through the call graph and reports:

```
CRITICAL  NULL-PROP-UNCHECKED  FileB.java:42
  Null returned by FileA.getConnection() used without check at FileB.processOrder()
  Call chain: processOrder -> service.getConnection -> pool.acquire [may-return-null]
  Impact: 7 callers affected (blast radius: high)
```

---

## Business Process Analysis

CodeGuardian performs BFS traversal from detected entry points (HTTP handlers, message queue consumers, CLI commands, scheduled jobs) to analyze complete business flows for architectural issues.

### Detection Rules

| Rule ID | Category | What It Catches |
|---------|----------|-----------------|
| `BIZ-NO-TRANSACTION-BOUNDARY` | consistency | Multi-step write flow with no transaction demarcation |
| `BIZ-PARTIAL-FAILURE-RISK` | consistency | Sequential operations where mid-flow failure leaves inconsistent state |
| `BIZ-CASCADING-TIMEOUT` | performance | Chained service calls without timeout propagation |
| `BIZ-SENSITIVE-NO-AUDIT` | security | Sensitive operation (payment, deletion) with no audit log |
| `BIZ-MULTI-ENTRY-NO-AUTH` | security | Business logic reachable from multiple entry points, some lacking auth |
| `BIZ-NOT-IDEMPOTENT` | retry-safety | Non-idempotent operation exposed to retry/replay |
| `BIZ-ERROR-SWALLOWED-MIDFLOW` | error-handling | Error caught and suppressed mid-flow, downstream assumes success |
| `BIZ-READ-WRITE-NO-LOCK` | concurrency | Read-then-write pattern with no concurrency control |
| `BIZ-IO-IN-LOOP` | performance | Database/network call inside a loop (N+1 pattern) |
| `BIZ-SENSITIVE-DATA-LEAK` | security | PII/credentials flowing to logs, responses, or external services |

Findings include the **full business flow path** so you can see exactly which operational process is affected.

---

## AI Features

AI features are **optional** and require an OpenAI-compatible API endpoint. CodeGuardian works fully offline without them — the 12 engines and PCI analysis are pure static analysis.

### Setup

```toml
# codeguardian.toml
[scan]
review_mode = "standard"        # ai_off | standard | ultra (the single AI switch)

[ai]
# ai.enabled is derived from scan.review_mode; no need to set it here.
provider = "openai"             # Any OpenAI-compatible endpoint
api_base = "https://api.openai.com/v1"
default_model = "gpt-4o"
summary_model = "gpt-4o-mini"   # Used for lightweight verification pass
```

```bash
# .env
OPENAI_API_KEY=sk-...
```

### AI Verifier (2-Pass False Positive Filter)

Runs after prioritization to reduce false positives by 40-60% on typical codebases.

**Pass 1** (light): Minimal context (+-10 lines), lightweight model — quick triage.

**Pass 2** (heavy): Triggered for uncertain, critical, or high-severity findings. Includes:
- Full function body (severity-tiered: up to 400 lines for critical)
- File imports and type context
- Cross-file callers/callees (up to 2 hops for critical findings)
- Enhanced evidence for high-FP-prone rules (shared state usage, catch bodies, lifecycle tokens)

Verdicts:
| Verdict | Action |
|---------|--------|
| `true` | Finding confirmed real, tagged `ai-confirmed` |
| `false` | False positive — severity downgraded, tagged `ai-fp` |
| `uncertain` | Kept as-is, tagged `ai-uncertain` |

### AI Deep Review (review_mode=standard/ultra)

A 7-step pipeline that performs LLM-powered code review:

1. **Index** — Build project index (function/class signatures via tree-sitter)
2. **Chunk** — Split source into reviewable units (file -> class -> function)
3. **Filter** — Prioritize chunks by findings, recent changes, complexity
4. **Budget** — Allocate token budget across chunks
5. **Context** — Pack signatures, local findings, and custom rules
6. **Review** — AI review with retry and concurrency control
7. **Merge** — Combine results into primary + supplementary findings

**Ultra mode** (`--review-mode ultra`) for higher recall:
- 3 Explorer agents run in parallel, each focused on one dimension:
  - Security Explorer
  - Logic Explorer
  - Resource/Error Explorer
- 1 Critic agent verifies combined findings, filtering ~60-70% of false positives

```bash
codeguardian scan . --review-mode ultra
```

---

## CI/CD Integration

### SARIF Output

Export findings in [SARIF](https://sarifweb.azurewebsites.net/) format for integration with GitHub Code Scanning, Azure DevOps, and other platforms:

```bash
codeguardian scan . --report sarif --output results.sarif
```

### GitHub Actions

```yaml
# .github/workflows/codeguardian.yml
name: CodeGuardian Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install CodeGuardian
        run: pip install codeguardian

      - name: Run Analysis
        run: codeguardian scan . --report sarif --output results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Quality Gate
        run: codeguardian gate .
```

### Quality Gate

Define pass/fail criteria in `gate.yaml`:

```yaml
# gate.yaml
rules:
  - metric: critical_findings
    operator: "<="
    threshold: 0
    action: fail

  - metric: high_findings
    operator: "<="
    threshold: 5
    action: fail

  - metric: security_score
    operator: ">="
    threshold: 70
    action: warn

  - metric: test_coverage_indicator
    operator: ">="
    threshold: 60
    action: warn
```

```bash
# Returns exit code 1 on failure - use directly in CI pipelines
codeguardian gate .
```

### Baseline Suppression

Adopt CodeGuardian incrementally — baseline existing findings so only new issues block CI:

```bash
# Record current findings as baseline
codeguardian baseline .

# Future scans only report NEW findings above baseline
codeguardian scan .  # baseline applied automatically
```

### Static False-Positive Suppression

Before baseline and AI verification, the scanner applies four deterministic false-positive reductions (no configuration needed):

- **Placeholder / env-reference credential filtering** — `HARDCODED-PASSWORD` only reports real credentials. Placeholder values such as `changeme`, `your_password_here`, `xxx`, and environment references like `$VAR` / `${VAR}` / `%VAR%` are not flagged (applied uniformly across Python / Java / JavaScript / Go / C++ and the regex fallback path).
- **Low-entropy credential filtering** — `HARDCODED-PASSWORD` also skips low-entropy values: common weak/default words (`admin`, `localhost`, `123456`, ...) and short single-character-class strings (all digits / all lowercase, length < 8) — almost certainly not real credentials; high-entropy values are still reported.
- **Test-path exemption** — test files (`tests/`, `test/`, `spec/`, `__tests__/` directories, and names like `test_*`, `*_test.go`, `*.spec.ts`) are not part of the deployed attack surface: security rules (hardcoded secrets, injection, etc.) and performance heuristic rules (`SQL-IN-LOOP`, `MISSING-PAGINATION`, `SELECT-STAR-NO-LIMIT`) are suppressed there, so fixtures/mocks do not flood the report.
- **Context-aware triage (Python)** — `WEAK-HASH` and `INSECURE-RANDOM` use the enclosing function name to judge intent: clearly non-security contexts (`checksum`/`cache`/`etag`/`sample`/`shuffle`/`jitter`/`backoff`, ...) are not reported; security contexts (`password`/`token`/`secret`/`verify`, ...) or undecidable ones still are (conservative). On Python these two rules run only on the AST path so the context-free regex cannot re-report them.

The net effect of these reductions is continuously measured by `benchmark/fp_corpus` (a synthetic labeled false-positive corpus); run `pytest tests/test_fp_benchmark.py` for precision/recall.

---

## Configuration

### `codeguardian.toml`

```toml
[scan]
review_mode = "standard"              # ai_off | standard | ultra (single AI switch)
languages = ["java", "go", "python"]  # auto-detected if omitted
exclude = ["vendor/", "generated/"]

[engines]
enabled = ["all"]                     # or list specific engines
# disabled = ["git_evolution"]        # skip specific engines

[rules]
min_severity = "low"                  # filter out info-level findings
# enabled = ["NULL-*", "BIZ-*"]      # glob patterns
# disabled = ["STYLE-*"]
# tags = ["security", "reliability"]

[ai]
provider = "openai"
api_base = "https://api.openai.com/v1"
default_model = "gpt-4o"
summary_model = "gpt-4o-mini"

[ai.deep_review]
# review_mode is derived from scan.review_mode (standard/ultra); do not set here.
max_chunks = 50
token_budget = 100000

[ai.ai_verify]
enabled = true
max_tokens_per_scan = 50000

[risk]
score_threshold = 60                  # findings below this score are must-fix

[report]
formats = ["terminal"]                # terminal, json, html, sarif, pdf
output_dir = "./reports"
```

### Configuration Priority

```
CLI arguments  >  Environment variables  >  codeguardian.toml  >  Built-in defaults
```

---

## Optional Dependencies

```bash
# Git evolution analysis (commit history, churn)
pip install codeguardian[git]

# PDF report generation
pip install codeguardian[report-pdf]

# Semgrep integration (additional SAST rules)
pip install codeguardian[semgrep]

# Everything
pip install codeguardian[dev,git,report-pdf,semgrep]
```

---

## Contributing

We welcome contributions! Here's how to get started:

```bash
# Clone and install in development mode
git clone https://github.com/tester-rep/CodeGuardian.git
cd CodeGuardian-CLI
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src tests

# Type check
mypy src
```

### Project Structure

```
src/codeguardian/
├── cli/            # Typer commands and output formatting
├── core/           # Orchestrator, ScanContext, Planner, Scheduler
│   └── call_graph/ # PCI: SymbolTable, CallGraph, FunctionSummary, PCIBuilder
├── engines/        # 12 analysis engines (AnalyzerEngine protocol)
├── parsers/        # Tree-sitter multi-language AST parsing
├── ai/             # AI router, verifier, deep review pipeline
│   ├── verifier/   # Two-pass FP filter with evidence collectors
│   └── deep_review/# 7-step LLM review pipeline
├── risk/           # RiskScorer, Prioritizer, release gate
├── models/         # Pydantic v2 data models (Finding, ScanResult, etc.)
├── reporters/      # Output formatters (terminal, JSON, HTML, SARIF, PDF)
├── config/         # TOML config loading and schema
├── detectors/      # Auto-detection (language, framework, build, test)
└── utils/          # Logging, helpers
```

### Adding a New Engine

Implement the `AnalyzerEngine` protocol:

```python
from codeguardian.engines.base import AnalyzerEngine
from codeguardian.core import ScanContext
from codeguardian.models import EngineResult

class MyEngine:
    @property
    def name(self) -> str:
        return "my_engine"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        # Your analysis logic here
        findings = []
        metrics = []
        # ... produce Finding and Metric objects ...
        return EngineResult(findings=findings, metrics=metrics)
```

Register your engine in the Planner and it will be scheduled alongside the built-in engines.

---

## Comparison

| Feature | CodeGuardian | SonarQube | Semgrep | CodeQL |
|---------|-------------|-----------|---------|--------|
| Cross-function call graph | Yes (PCI) | Limited | No | Yes |
| Business process analysis | Yes | No | No | No |
| AI false-positive filtering | Yes | No | No | No |
| AI deep review | Yes | No | No | No |
| Impact/blast-radius scoring | Yes | No | No | No |
| Setup complexity | `pip install` | Server + DB | `pip install` | Build required |
| Offline capable | Yes | Yes | Yes | Yes |
| Languages | 9 | 30+ | 30+ | 15+ |
| Custom rules | Rule registry | GUI/XML | YAML patterns | QL language |
| SARIF export | Yes | No | Yes | Yes |
| Quality gate | YAML-based | Built-in | CLI flags | Actions |

---

## License

[Apache License 2.0](LICENSE) — use freely in commercial and open-source projects.

---

<p align="center">
  <sub>Built for engineers who ship reliable software.</sub>
</p>
