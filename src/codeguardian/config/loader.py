"""Configuration loader — merges TOML file + env vars into AppConfig."""

import logging
import tomllib
from pathlib import Path
from typing import Any

from codeguardian.config.defaults import default_config
from codeguardian.config.schema import AppConfig

logger = logging.getLogger(__name__)


def _load_dotenv(extra_dirs: list[Path] | None = None) -> None:
    """Load ``.env`` file, searching multiple candidate directories.

    Search order (first found wins):
    1. Directories passed in *extra_dirs* (e.g. project root, config dir)
    2. Current working directory

    Uses ``python-dotenv`` when installed; otherwise a minimal built-in
    parser that handles ``KEY=VALUE`` lines with optional quoting / ``#``
    comments.
    """
    candidates = list(extra_dirs or []) + [Path.cwd()]
    env_path: Path | None = None
    for directory in candidates:
        candidate = Path(directory) / ".env"
        if candidate.exists():
            env_path = candidate
            break

    if env_path is None:
        return

    try:
        from dotenv import load_dotenv  # type: ignore[import-untyped]

        load_dotenv(env_path, override=False)
        logger.debug("Loaded %s via python-dotenv", env_path)
        return
    except ImportError:
        pass

    # Minimal fallback: parse KEY=VALUE lines ourselves
    import os

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        # Only set if not already present (don't override real env vars)
        if key and key not in os.environ:
            os.environ[key] = value

    logger.debug("Loaded %s via built-in fallback parser", env_path)


def load_app_config(path: str | None = None) -> AppConfig:
    """Load and merge configuration from file, falling back to defaults."""
    if path is None:
        # Auto-discover config in current directory and parent directories
        for candidate in [Path("codeguardian.toml"), Path(".codeguardian.toml")]:
            if candidate.exists():
                path = str(candidate)
                break

    # Build extra search directories for .env (config dir + parent)
    extra_dirs: list[Path] = []
    if path and Path(path).exists():
        config_dir = Path(path).resolve().parent
        extra_dirs.append(config_dir)

    # Load .env before reading config so API keys are available
    _load_dotenv(extra_dirs=extra_dirs)

    if path is None or not Path(path).exists():
        return default_config()

    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return _merge_toml_into_config(data)


def _merge_toml_into_config(data: dict[str, Any]) -> AppConfig:
    """Convert flat TOML sections to nested Pydantic model.

    Handles the special case where ``[ai.deep_review]`` in TOML becomes a
    nested dict under ``data["ai"]["deep_review"]`` but ``AppConfig`` expects
    ``deep_review`` as a **top-level** field (sibling of ``ai``).
    """
    raw: dict[str, Any] = {}

    if "scan" in data:
        raw["scan"] = data["scan"]
    if "reports" in data:
        raw["reports"] = data["reports"]
    if "ai" in data:
        ai_data = dict(data["ai"])  # shallow copy to avoid mutating input
        # Extract nested AI review sections from ai section → top-level fields
        if "deep_review" in ai_data:
            raw["deep_review"] = ai_data.pop("deep_review")
        if "free_review" in ai_data:
            raw["free_review"] = ai_data.pop("free_review")
        raw["ai"] = ai_data
    if "deep_review" in data:
        # Also support top-level [deep_review] section directly
        raw["deep_review"] = data["deep_review"]
    if "free_review" in data:
        raw["free_review"] = data["free_review"]

    if "risk" in data:
        raw["risk"] = data["risk"]
    if "git" in data:
        raw["git"] = data["git"]
    if "test" in data:
        raw["test"] = data["test"]
    if "gate" in data:
        raw["gate"] = data["gate"]
    if "rules" in data:
        raw["rules"] = data["rules"]
    if "semgrep" in data:
        raw["semgrep"] = data["semgrep"]

    _apply_deprecations(raw)

    return AppConfig.model_validate(raw) if raw else default_config()


def _apply_deprecations(raw: dict[str, Any]) -> None:
    """Map removed config keys onto ``scan.review_mode`` (SSOT), in place.

    Removed keys: ``scan.depth``, ``ai.enabled``, ``deep_review.enabled``,
    ``deep_review.review_mode``. When the user has not set ``scan.review_mode``
    explicitly, derive it from the legacy AI switches so old configs keep working.
    """
    scan = raw.setdefault("scan", {}) if isinstance(raw.get("scan", {}), dict) else {}
    raw["scan"] = scan
    ai = raw.get("ai", {}) if isinstance(raw.get("ai", {}), dict) else {}
    deep = raw.get("deep_review", {}) if isinstance(raw.get("deep_review", {}), dict) else {}

    if "depth" in scan:
        old_depth = str(scan.pop("depth", "")).strip().lower()
        logger.warning(
            "[deprecated] scan.depth 已废弃并忽略；引擎恒为全量，"
            "覆盖度用 --incremental/--since 控制，AI 用 scan.review_mode 控制。"
        )
        if old_depth == "quick":
            logger.warning("[deprecated] depth=quick 已移除；快速预检请改用 --incremental。")

    if "review_mode" not in scan:
        ai_on = ai.get("enabled")  # None if unset
        legacy_dr_mode = str(deep.get("review_mode", "standard")).strip().lower()
        if ai_on is False:
            scan["review_mode"] = "ai_off"
        elif ai_on is True:
            scan["review_mode"] = "ultra" if legacy_dr_mode == "ultra" else "standard"
        if ai_on is not None:
            logger.warning(
                "[deprecated] ai.enabled/deep_review.* 已合并为 scan.review_mode=%s",
                scan.get("review_mode"),
            )

    # Drop removed legacy fields so they don't linger (they'd be ignored anyway).
    ai.pop("enabled", None)
    deep.pop("enabled", None)
    if "review_mode" in scan:
        deep.pop("review_mode", None)



def load_gate_yaml(path: str | None = None) -> dict[str, Any]:
    """Load a gate.yaml rule definition file."""
    import yaml  # type: ignore[import-untyped]


    target = Path(path or "gate.yaml")
    if not target.exists():
        return {}

    return yaml.safe_load(target.read_text(encoding="utf-8")) or {}
