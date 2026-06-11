"""Base AI provider interface."""

from typing import Protocol

from codeguardian.ai.models import GenerateResult


class AIProvider(Protocol):
    """Interface for AI providers (OpenAI, Anthropic, Ollama, etc.)."""

    async def generate(self, prompt: str, **kwargs: object) -> str:
        """Generate a response from the AI model."""
        ...

    async def generate_with_usage(self, prompt: str, **kwargs: object) -> GenerateResult:
        """Generate a response and return token usage info.

        Default implementation wraps generate() with zero usage.
        Providers should override this to extract real usage from API.
        """
        text = await self.generate(prompt, **kwargs)
        return GenerateResult(text=text)

