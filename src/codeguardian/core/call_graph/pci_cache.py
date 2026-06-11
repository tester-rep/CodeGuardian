"""PCI Cache — persists per-file PCI data with content-hash invalidation.

Cache location: .codeguardian/pci_cache.json
Strategy: per-file content hash (MD5). On rebuild, only re-parse files
whose hash changed. Deleted files are pruned from cache.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

CACHE_DIR = ".codeguardian"
CACHE_FILE = "pci_cache.json"
CACHE_VERSION = 1


@dataclass
class FileCacheEntry:
    """Cached PCI data for a single file."""

    content_hash: str
    language: str
    # Symbol data (serializable subset)
    symbols: list[dict]  # [{name, qualified_name, kind, start_line, end_line, ...}]
    # Raw call sites from this file
    call_sites: list[dict]  # [{caller, callee_name, line, form, receiver, ...}]
    # Function summary data
    summaries: list[dict]  # [{qualified_name, may_return_null, may_throw, ...}]


class PCICache:
    """Manages PCI cache persistence with per-file content-hash invalidation."""

    def __init__(self, project_root: Path, *, enabled: bool = True) -> None:
        self._project_root = project_root
        self._enabled = enabled
        self._cache_path = project_root / CACHE_DIR / CACHE_FILE
        self._entries: dict[str, dict] = {}  # rel_path -> serialized FileCacheEntry
        self._loaded = False

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def load(self) -> bool:
        """Load cache from disk. Returns True if loaded successfully."""
        if not self._enabled:
            return False
        if not self._cache_path.exists():
            return False
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
            if data.get("version") != CACHE_VERSION:
                logger.info("PCI cache version mismatch, rebuilding")
                return False
            self._entries = data.get("files", {})
            self._loaded = True
            logger.info("PCI cache loaded: %d files cached", len(self._entries))
            return True
        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.debug("PCI cache load failed: %s", e)
            return False

    def save(self) -> None:
        """Persist current cache entries to disk."""
        if not self._enabled:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": CACHE_VERSION,
                "timestamp": time.time(),
                "files": self._entries,
            }
            self._cache_path.write_text(
                json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            logger.info("PCI cache saved: %d files", len(self._entries))
        except OSError as e:
            logger.warning("PCI cache save failed: %s", e)

    def get_stale_files(
        self,
        candidate_files: dict[str, str],  # rel_path -> content_hash
    ) -> tuple[set[str], set[str]]:
        """Determine which files need re-parsing.

        Returns (stale_files, deleted_files):
        - stale_files: files that are new or have changed content hash
        - deleted_files: files in cache that no longer exist in project
        """
        stale: set[str] = set()
        deleted: set[str] = set()

        # Find new/changed files
        for rel_path, content_hash in candidate_files.items():
            cached = self._entries.get(rel_path)
            if cached is None or cached.get("content_hash") != content_hash:
                stale.add(rel_path)

        # Find deleted files
        for cached_path in list(self._entries.keys()):
            if cached_path not in candidate_files:
                deleted.add(cached_path)

        return stale, deleted

    def get_entry(self, rel_path: str) -> dict | None:
        """Get cached data for a file (symbols, call_sites, summaries)."""
        return self._entries.get(rel_path)

    def set_entry(self, rel_path: str, entry: dict) -> None:
        """Store/update cache entry for a file."""
        self._entries[rel_path] = entry

    def remove_entry(self, rel_path: str) -> None:
        """Remove a file from cache (deleted from project)."""
        self._entries.pop(rel_path, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._entries = {}


def compute_file_hash(content: str) -> str:
    """Compute MD5 hash of file content for change detection."""
    return hashlib.md5(content.encode("utf-8")).hexdigest()
