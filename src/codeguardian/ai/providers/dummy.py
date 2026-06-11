"""DummyAIProvider — placeholder provider for testing and offline use."""


class DummyAIProvider:
    """Returns canned responses for testing without real AI calls."""

    async def generate(self, prompt: str, **kwargs: object) -> str:
        return (

            "[dummy] AI response not available.\n"
            "To enable AI features:\n"
            "  1. Set ai.enabled = true in codeguardian.toml\n"
            "  2. Set the CODEGUARDIAN_API_KEY environment variable\n"
            "\n"
            f"Prompt was: {prompt[:200]}..."
        )

    async def generate_with_usage(self, prompt: str, **kwargs: object) -> "GenerateResult":
        """Dummy provider returns zero usage."""
        from codeguardian.ai.models import GenerateResult

        text = await self.generate(prompt, **kwargs)
        return GenerateResult(text=text)
