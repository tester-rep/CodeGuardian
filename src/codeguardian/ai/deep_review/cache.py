"""ReviewCache — content-hash based result caching for deep review.

Avoids redundant AI calls for unchanged code chunks by caching
results keyed on a hash of the source code + prompt-relevant context.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from codeguardian.ai.deep_review.models import AIFindingRaw, CodeChunk, ReviewResult

logger = logging.getLogger(__name__)

CACHE_DIR_NAME = ".codeguardian"
CACHE_FILE_NAME = "deep_review_cache.json"

# Default TTL: 7 days in seconds
DEFAULT_TTL_SECONDS = 7 * 24 * 3600


def _chunk_cache_key(chunk: CodeChunk) -> str:
    """Compute a deterministic cache key for a chunk.

    The key is based on source code content + language, so that
    any code change invalidates the cache entry.
    """
    content = f"{chunk.language}:{chunk.source_code}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class ReviewCache:
    """Disk-backed cache mapping content hashes → AI review results.

    Cache file lives at ``<project_root>/.codeguardian/deep_review_cache.json``.
    """

    def __init__(
        self,
        project_root: Path,
        *,
        enabled: bool = True,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        namespace: str = "deep_review",
    ) -> None:
        self._enabled = enabled
        self._ttl = ttl_seconds
        cache_file = CACHE_FILE_NAME if namespace == "deep_review" else f"{namespace}_cache.json"
        self._cache_path = project_root / CACHE_DIR_NAME / cache_file

        self._store: dict[str, dict[str, Any]] = {}
        if enabled:
            self._load()
            self._evict_expired()

    def _load(self) -> None:
        """Load cache from disk if it exists."""
        if not self._cache_path.is_file():
            return
        try:
            raw = self._cache_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                self._store = data
                logger.info("Loaded deep review cache: %d entries", len(self._store))
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to load deep review cache, starting fresh")
            self._store = {}

    def lookup(self, chunk: CodeChunk) -> ReviewResult | None:
        """Return cached ReviewResult for the chunk, or None on miss."""
        if not self._enabled:
            return None
        key = _chunk_cache_key(chunk)
        entry = self._store.get(key)
        if entry is None:
            return None

        # TTL check — treat expired entries as cache miss
        created_at = entry.get("_created_at", 0)
        if time.time() - created_at > self._ttl:
            del self._store[key]
            return None

        # Reconstruct ReviewResult from serialized dict
        try:
            findings = [
                AIFindingRaw(**f) for f in entry.get("findings", [])
            ]
            result = ReviewResult(
                chunk_file_path=chunk.file_path,
                chunk_qualified_name=chunk.qualified_name,
                findings=findings,
                summary=entry.get("summary", ""),
                verified_local_findings=entry.get("verified_local_findings", []),
                status="done",
                tokens_used=0,  # cached — no tokens consumed
            )
            return result
        except (TypeError, KeyError):
            # Corrupted entry, ignore
            return None

    def store(self, chunk: CodeChunk, result: ReviewResult) -> None:
        """Store a successful review result in cache."""
        if not self._enabled:
            return
        if result.status != "done":
            return

        key = _chunk_cache_key(chunk)
        self._store[key] = {
            "_created_at": time.time(),
            "findings": [
                {
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "description": f.description,
                    "evidence": f.evidence,
                    "fix_suggestion": f.fix_suggestion,
                    "self_reflection": f.self_reflection,
                }
                for f in result.findings
            ],
            "summary": result.summary,
            "verified_local_findings": result.verified_local_findings,
        }

    def save(self) -> None:
        """Persist cache to disk."""
        if not self._enabled:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(
                json.dumps(self._store, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.info("Saved deep review cache: %d entries", len(self._store))
        except OSError:
            logger.warning("Failed to save deep review cache", exc_info=True)

    def _evict_expired(self) -> None:
        """Remove cache entries older than TTL."""
        now = time.time()
        expired_keys = [
            k for k, v in self._store.items()
            if now - v.get("_created_at", 0) > self._ttl
        ]
        if expired_keys:
            for k in expired_keys:
                del self._store[k]
            logger.info("Evicted %d expired cache entries", len(expired_keys))

    def __len__(self) -> int:
        return len(self._store)
