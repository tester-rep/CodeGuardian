"""AI provider factory — creates the appropriate provider from configuration.

Supports any OpenAI-compatible endpoint. Provider name "openai", "venus",
"azure", or "compatible" all use the same OpenAI-compatible client.
Any unknown provider falls back to DummyAIProvider.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from codeguardian.ai.providers.dummy import DummyAIProvider

if TYPE_CHECKING:
    from codeguardian.ai.base import AIProvider
    from codeguardian.config.schema import AIConfig

logger = logging.getLogger(__name__)


def create_provider(config: AIConfig) -> AIProvider:
    """Create an AI provider instance based on configuration.

    Falls back to :class:`DummyAIProvider` when:
    - ``config.enabled`` is False
    - the requested provider is ``"dummy"`` or unknown
    - the API key is not configured

    This ensures the scan pipeline never fails due to AI misconfiguration —
    it simply degrades gracefully to the dummy placeholder.
    """
    if not config.enabled:
        logger.debug("AI disabled in config; using DummyAIProvider")
        return DummyAIProvider()

    provider_name = config.provider.lower().strip()

    if provider_name == "dummy":
        return DummyAIProvider()

    if provider_name in ("openai", "venus", "azure", "compatible"):
        return _create_openai_compatible(config)

    logger.warning(
        "Unsupported AI provider '%s'; falling back to DummyAIProvider. "
        "Supported: 'openai', 'venus', 'azure', 'compatible', 'dummy'.",
        provider_name,
    )
    return DummyAIProvider()


def create_provider_for_model(config: AIConfig, model_override: str) -> AIProvider:
    """Create a provider using *model_override* instead of ``config.model``.

    If *model_override* is empty or identical to ``config.model``, delegates
    directly to :func:`create_provider` without copying the config.
    """
    if not model_override or model_override == config.model:
        return create_provider(config)
    overridden = config.model_copy(update={"model": model_override})
    return create_provider(overridden)


def _create_openai_compatible(config: AIConfig) -> AIProvider:
    """Instantiate the OpenAI-compatible provider, falling back to dummy on error."""
    from codeguardian.ai.providers.venus_provider import VenusProvider

    try:
        return VenusProvider(
            model=config.model,
            api_key_env=config.api_key_env,
            base_url=config.base_url,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            timeout=config.timeout,
            requests_per_second=config.requests_per_second,
        )
    except ValueError as exc:
        logger.warning(
            "AI provider configuration error: %s. Falling back to DummyAIProvider.", exc
        )
        return DummyAIProvider()
