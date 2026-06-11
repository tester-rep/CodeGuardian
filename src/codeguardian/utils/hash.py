"""Hash utilities for caching and deduplication."""

import hashlib
from pathlib import Path


def sha256_text(text: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str | None:
    """Compute SHA-256 hash of a file's contents."""
    try:
        return sha256_bytes(path.read_bytes())
    except OSError:
        return None
