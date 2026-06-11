"""Logging configuration utility."""

import logging
import sys


def setup_logging(level: int = logging.INFO, verbose: bool = False) -> None:
    """Configure root logger with consistent format.

    Args:
        level: Logging level (default INFO).
        verbose: If True, also log to stdout with DEBUG level.
    """
    fmt = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt=datefmt,
        stream=sys.stderr,  # Log to stderr so it doesn't interfere with stdout output
    )

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("charset_normalizer").setLevel(logging.ERROR)
