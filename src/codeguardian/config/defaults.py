"""Default configuration values."""

from codeguardian.config.schema import AppConfig


def default_config() -> AppConfig:
    return AppConfig()
