"""VerifyCache — disk cache for AI finding-verification verdicts.

Independent from deep_review cache:
  - Different file path: ``.codeguardian/ai_verify_cache.json``
  - Different key shape (finding fingerprint, not chunk content hash)
  - Stores final verdict only (Pass 1 + Pass 2 share a key; whichever wins, wins)

Cache key = sha256(file + line_start + rule_id + sha(±5-line code) + model + prompt_version).
Changing model OR prompt invalidates the entire cache automatically.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from codeguardian.models.finding import Finding

logger = logging.getLogger(__name__)

CACHE_DIR_NAME = ".codeguardian"
CACHE_FILE_NAME = "ai_verify_cache.json"
DEFAULT_TTL_SECONDS = 7 * 24 * 3600

# Bump this whenever the verifier prompt structure changes — old entries auto-evict.
# v2 (2026-05): added severity gate (high/critical force Pass 2) + call-graph context
PROMPT_VERSION = "v2"


@dataclass(slots=True)
class VerifyVerdict:
    """The cached unit: AI's final judgment over a single finding."""

    status: str  # "ai-verified-true" | "ai-verified-fp" | "ai-uncertain"
    summary: str
    pass_used: int  # 1 or 2 — which pass produced this verdict
    tokens_used: int = 0


def _code_window_hash(code_lines: list[str], line_start: int) -> str:
    """Hash the ±5 line window around the finding location.

    Using a small window (not the full file) keeps the cache resilient to
    unrelated edits elsewhere in the file while still invalidating when the
    actual flagged code changes.
    """
    if not code_lines:
        return "no-code"
    n = len(code_lines)
    start = max(0, line_start - 6)  # -5 inclusive (line is 1-based)
    end = min(n, line_start + 5)
    window = "\n".join(code_lines[start:end])
    return hashlib.sha256(window.encode("utf-8", errors="replace")).hexdigest()[:16]


def compute_cache_key(
    finding: Finding,
    *,
    code_lines: list[str],
    model: str,
) -> str:
    """Deterministic key per (finding × model × prompt version)."""
    parts = [
        finding.location.file_path or "",
        str(finding.location.line_start or 0),
        finding.rule_id or "",
        _code_window_hash(code_lines, finding.location.line_start or 0),
        model or "",
        PROMPT_VERSION,
    ]
    payload = "|".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class VerifyCache:
    """Disk-backed cache for AI verification verdicts."""

    def __init__(
        self,
        project_root: Path,
        *,
        enabled: bool = True,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._enabled = enabled
        self._ttl = ttl_seconds
        self._cache_path = project_root / CACHE_DIR_NAME / CACHE_FILE_NAME
        self._store: dict[str, dict[str, Any]] = {}
        if enabled:
            self._load()
            self._evict_expired()

    def _load(self) -> None:
        if not self._cache_path.is_file():
            return
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._store = data
                logger.info("Loaded AI verify cache: %d entries", len(self._store))
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to load AI verify cache, starting fresh")
            self._store = {}

    def lookup(self, key: str) -> VerifyVerdict | None:
        if not self._enabled:
            return None
        entry = self._store.get(key)
        if entry is None:
            return None
        if time.time() - entry.get("_created_at", 0) > self._ttl:
            del self._store[key]
            return None
        try:
            return VerifyVerdict(
                status=entry["status"],
                summary=entry.get("summary", ""),
                pass_used=int(entry.get("pass_used", 1)),
                tokens_used=0,  # cached → no fresh tokens consumed
            )
        except (KeyError, TypeError, ValueError):
            return None

    def store(self, key: str, verdict: VerifyVerdict) -> None:
        if not self._enabled:
            return
        # Never cache "uncertain" — uncertainty often resolves on re-run with
        # better context; locking it in would suppress future improvements.
        if verdict.status == "ai-uncertain":
            return
        record = asdict(verdict)
        record["_created_at"] = time.time()
        self._store[key] = record

    def save(self) -> None:
        if not self._enabled:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(
                json.dumps(self._store, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.info("Saved AI verify cache: %d entries", len(self._store))
        except OSError:
            logger.warning("Failed to save AI verify cache", exc_info=True)

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [
            k for k, v in self._store.items()
            if now - v.get("_created_at", 0) > self._ttl
        ]
        for k in expired:
            del self._store[k]
        if expired:
            logger.info("Evicted %d expired verify-cache entries", len(expired))

    def __len__(self) -> int:
        return len(self._store)
