"""SemgrepEngine — wraps the external ``semgrep`` CLI.

Optional engine (disabled by default). When enabled, runs Semgrep against the
project root, parses its JSON output, and emits standard ``Finding`` objects.

Design notes:
  * **Graceful skip**: if the ``semgrep`` binary is unavailable, the engine
    returns an empty result with a warning instead of failing the scan.
  * **Windows UTF-8 fix**: forces ``PYTHONUTF8=1`` in the subprocess
    environment so Semgrep won't crash on emoji output under GBK locale.
  * **stdout streaming**: we deliberately do NOT pass ``--output`` (which
    triggers the GBK file-write bug); JSON is captured from stdout.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path

from codeguardian.core.context import ScanContext
from codeguardian.engines.rule_helpers import build_finding
from codeguardian.engines.semgrep_adapter import filter_hits, parse_semgrep_results
from codeguardian.models.scan import EngineResult

logger = logging.getLogger(__name__)


class SemgrepEngine:
    """Run Semgrep as a subprocess and convert results into Findings."""

    name = "semgrep"

    async def analyze(self, ctx: ScanContext) -> EngineResult:
        cfg = ctx.config.semgrep
        if not cfg.enabled:
            return EngineResult(engine_name=self.name)

        binary = self._resolve_binary()
        if binary is None:
            return EngineResult(
                engine_name=self.name,
                warnings=[
                    "Semgrep CLI not found on PATH; install via "
                    "'pip install semgrep' or disable [semgrep] in codeguardian.toml.",
                ],
            )

        project_root = Path(ctx.project_root).resolve()
        started = time.perf_counter()
        try:
            payload = await self._run_semgrep(binary, project_root, cfg)
        except FileNotFoundError as exc:
            return EngineResult(
                engine_name=self.name,
                warnings=[f"Semgrep binary disappeared during execution: {exc}"],
            )
        except asyncio.TimeoutError:
            return EngineResult(
                engine_name=self.name,
                duration_ms=(time.perf_counter() - started) * 1000,
                warnings=[f"Semgrep timed out after {cfg.timeout:.0f}s; consider raising 'timeout'."],
            )
        except _SemgrepFailure as exc:
            return EngineResult(
                engine_name=self.name,
                duration_ms=(time.perf_counter() - started) * 1000,
                errors=[f"Semgrep execution failed: {exc}"],
            )

        hits = parse_semgrep_results(payload, project_root)
        hits = filter_hits(hits, ctx.config.rules)
        if cfg.severity_filter:
            allowed = {s.lower() for s in cfg.severity_filter}
            hits = [h for h in hits if h.rule.severity.value.lower() in allowed]

        findings = []
        counter = 0
        # Cache file contents we've already loaded for snippet rendering.
        content_cache: dict[str, list[str]] = {}
        for hit in hits:
            counter += 1
            lines = self._load_lines(project_root, hit.file_path, content_cache)
            findings.append(
                build_finding(hit, lines, f"SGR-{counter:03d}", self.name),
            )

        warnings = [
            f"Semgrep returned {len(payload.get('errors', []))} non-fatal warnings."
        ] if payload.get("errors") else []

        return EngineResult(
            engine_name=self.name,
            duration_ms=(time.perf_counter() - started) * 1000,
            findings=findings,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def is_available() -> bool:
        """Return True if the semgrep binary is callable from PATH."""
        return SemgrepEngine._resolve_binary() is not None

    @staticmethod
    def _resolve_binary() -> str | None:
        return shutil.which("semgrep")

    async def _run_semgrep(
        self,
        binary: str,
        project_root: Path,
        cfg,  # SemgrepConfig
    ) -> dict:
        cmd: list[str] = [binary, "scan", "--json", "--quiet", "--disable-version-check"]
        for rule_pack in cfg.config:
            cmd.extend(["--config", rule_pack])
        cmd.extend(["--max-target-bytes", str(cfg.max_target_bytes)])
        cmd.extend(["--jobs", str(max(1, cfg.jobs))])
        if cfg.extra_args:
            cmd.extend(cfg.extra_args)
        cmd.append(str(project_root))

        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

        logger.debug("Running semgrep: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(project_root),
            env=env,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.timeout,
            )
        except asyncio.TimeoutError:
            with _suppress_errors():
                proc.kill()
                await proc.wait()
            raise

        # Semgrep exit codes: 0 = no findings, 1 = findings reported, 2+ = error.
        rc = proc.returncode
        if rc not in (0, 1):
            stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
            raise _SemgrepFailure(
                f"semgrep exited with code {rc}: {stderr_text or '<no stderr>'}",
            )

        try:
            payload = json.loads(stdout_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise _SemgrepFailure(f"failed to parse semgrep JSON output: {exc}") from exc

        if not isinstance(payload, dict):
            raise _SemgrepFailure("semgrep JSON output is not an object")
        return payload

    @staticmethod
    def _load_lines(
        project_root: Path,
        rel_path: str,
        cache: dict[str, list[str]],
    ) -> list[str]:
        if rel_path in cache:
            return cache[rel_path]
        full = project_root / rel_path
        try:
            text = full.read_text(encoding="utf-8", errors="ignore")
            lines = text.splitlines()
        except (OSError, ValueError):
            lines = []
        cache[rel_path] = lines
        return lines


class _SemgrepFailure(RuntimeError):
    """Internal marker for non-zero semgrep exits / parse errors."""


class _suppress_errors:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return True
