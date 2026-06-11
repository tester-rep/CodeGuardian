"""Tests for the AI provider system — factory, router, providers, and orchestrator integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from codeguardian.ai.factory import create_provider
from codeguardian.ai.providers.dummy import DummyAIProvider
from codeguardian.ai.router import AIRouter
from codeguardian.config.schema import AIConfig


# ---------------------------------------------------------------------------
# Helper: build an AIConfig with sensible defaults
# ---------------------------------------------------------------------------

def _ai_config(**overrides: object) -> AIConfig:
    defaults = {
        "enabled": True,
        "provider": "openai",
        "model": "gpt-4o",
        "api_key_env": "CODEGUARDIAN_API_KEY",
        "base_url": None,
        "max_tokens": 2000,
        "temperature": 0.3,
    }
    defaults.update(overrides)
    return AIConfig(**defaults)  # type: ignore[arg-type]


# ===== Factory tests =====


class TestCreateProvider:
    """Tests for ``create_provider`` factory function."""

    def test_disabled_returns_dummy(self) -> None:
        """When ai.enabled=false, always returns DummyAIProvider."""
        config = _ai_config(enabled=False)
        provider = create_provider(config)
        assert isinstance(provider, DummyAIProvider)

    def test_dummy_provider_explicit(self) -> None:
        """Explicitly requesting 'dummy' returns DummyAIProvider."""
        config = _ai_config(provider="dummy")
        provider = create_provider(config)
        assert isinstance(provider, DummyAIProvider)

    def test_unknown_provider_falls_back_to_dummy(self) -> None:
        """Unknown provider name falls back to DummyAIProvider with a warning."""
        config = _ai_config(provider="nonexistent-model")
        provider = create_provider(config)
        assert isinstance(provider, DummyAIProvider)

    def test_legacy_openai_provider_falls_back(self) -> None:
        """Legacy 'openai' configs gracefully degrade to DummyAIProvider."""
        config = _ai_config(provider="openai")
        provider = create_provider(config)
        assert isinstance(provider, DummyAIProvider)

    def test_legacy_anthropic_provider_falls_back(self) -> None:
        """Legacy 'anthropic' configs gracefully degrade to DummyAIProvider."""
        config = _ai_config(provider="anthropic")
        provider = create_provider(config)
        assert isinstance(provider, DummyAIProvider)

    @patch.dict("os.environ", {"CODEGUARDIAN_API_KEY": "test-token-123"})
    def test_openai_provider_created(self) -> None:
        """When CODEGUARDIAN_API_KEY is set, factory creates a VenusProvider."""
        from codeguardian.ai.providers.venus_provider import VenusProvider

        config = _ai_config(provider="openai")
        provider = create_provider(config)
        assert isinstance(provider, VenusProvider)

    def test_openai_no_api_key_falls_back(self) -> None:
        """When CODEGUARDIAN_API_KEY is not set, falls back to DummyAIProvider."""
        config = _ai_config(provider="openai", api_key_env="NONEXISTENT_ENV_VAR_FOR_TEST")
        provider = create_provider(config)
        assert isinstance(provider, DummyAIProvider)


# ===== Router tests =====


class TestAIRouter:
    """Tests for ``AIRouter`` routing logic."""

    def test_default_router_uses_dummy(self) -> None:
        """Default router (no provider) uses DummyAIProvider."""
        router = AIRouter()
        assert isinstance(router.provider, DummyAIProvider)

    def test_from_config_disabled(self) -> None:
        """from_config with disabled AI returns DummyAIProvider."""
        config = _ai_config(enabled=False)
        router = AIRouter.from_config(config)
        assert isinstance(router.provider, DummyAIProvider)

    def test_from_config_with_custom_provider(self) -> None:
        """from_config passes through to factory."""
        mock_provider = MagicMock()
        with patch("codeguardian.ai.factory.create_provider", return_value=mock_provider):
            config = _ai_config(provider="openai")
            router = AIRouter.from_config(config)
            assert router.provider is mock_provider

    async def test_explain_finding_calls_provider(self) -> None:
        """explain_finding routes to provider.generate_with_usage."""
        from codeguardian.ai.models import GenerateResult
        mock_provider = AsyncMock()
        mock_provider.generate_with_usage.return_value = GenerateResult(text="Explanation text")
        router = AIRouter(provider=mock_provider)
        result = await router.explain_finding("SEC-001")
        assert result == "Explanation text"
        mock_provider.generate_with_usage.assert_called_once()

    async def test_summarize_findings_calls_provider(self) -> None:
        """summarize_findings routes to provider.generate_with_usage."""
        from codeguardian.ai.models import GenerateResult
        mock_provider = AsyncMock()
        mock_provider.generate_with_usage.return_value = GenerateResult(text="Summary text")
        router = AIRouter(provider=mock_provider)
        result = await router.summarize_findings({"total": 5})
        assert result == "Summary text"
        mock_provider.generate_with_usage.assert_called_once()

    async def test_suggest_fix_calls_provider(self) -> None:
        """suggest_fix routes to provider.generate_with_usage."""
        from codeguardian.ai.models import GenerateResult
        mock_provider = AsyncMock()
        mock_provider.generate_with_usage.return_value = GenerateResult(text="Fix suggestion")
        router = AIRouter(provider=mock_provider)
        result = await router.suggest_fix({"rule_id": "SQL-INJECTION"})
        assert result == "Fix suggestion"
        mock_provider.generate_with_usage.assert_called_once()

    async def test_review_release_calls_provider(self) -> None:
        """review_release routes to provider.generate_with_usage."""
        from codeguardian.ai.models import GenerateResult
        mock_provider = AsyncMock()
        mock_provider.generate_with_usage.return_value = GenerateResult(text="Release review")
        router = AIRouter(provider=mock_provider)
        result = await router.review_release({"score": 85})
        assert result == "Release review"
        mock_provider.generate_with_usage.assert_called_once()


# ===== DummyProvider tests =====


class TestDummyAIProvider:
    """Tests for DummyAIProvider."""

    async def test_returns_placeholder_message(self) -> None:
        """Dummy provider returns an instructional placeholder."""
        provider = DummyAIProvider()
        result = await provider.generate("test prompt")
        assert "[dummy]" in result
        assert "AI response not available" in result

    async def test_includes_prompt_preview(self) -> None:
        """Dummy response includes a truncated preview of the prompt."""
        provider = DummyAIProvider()
        result = await provider.generate("Hello world test")
        assert "Hello world test" in result


# ===== Provider prompt quality tests =====


class TestRouterPrompts:
    """Verify that prompts built by the router contain expected structure."""

    def test_explain_prompt_structure(self) -> None:
        """Explain prompt includes the finding ID."""
        prompt = AIRouter._build_explain_prompt("SEC-001")
        assert "SEC-001" in prompt
        assert "What is the problem" in prompt

    def test_summary_prompt_structure(self) -> None:
        """Summary prompt includes payload reference."""
        prompt = AIRouter._build_summary_prompt({"total": 5, "critical": 1})
        assert "executive summary" in prompt.lower() or "Issue Summarizer" in prompt

    def test_release_prompt_structure(self) -> None:
        """Release prompt includes recommendation guidance."""
        prompt = AIRouter._build_release_prompt({"score": 85, "verdict": "recommended"})
        assert "release" in prompt.lower()
        assert "blocked" in prompt.lower() or "conditional" in prompt.lower()


# ===== Orchestrator integration tests =====


class TestOrchestratorAIIntegration:
    """Test that Orchestrator correctly integrates with the AI provider system."""

    async def test_ai_disabled_skips_enhancement(self) -> None:
        """When AI is disabled, _apply_ai_enhancement returns inputs unchanged."""
        from codeguardian.config.schema import AppConfig
        from codeguardian.core.orchestrator import Orchestrator
        from codeguardian.models.profile import ProjectProfile, ReleaseConclusion

        config = AppConfig()
        assert config.ai.enabled is False  # default

        orchestrator = Orchestrator(config)
        profile = ProjectProfile(
            project_name="test",
            overall_score=85.0,
            health_status="good",
            languages=["python"],
            frameworks=[],
            total_files=10,
            total_loc=500,
            total_sloc=400,
            total_functions=20,
            total_classes=5,
            dimension_scores=[],
            modules=[],
        )
        release = ReleaseConclusion(
            verdict="recommended",
            review_summary="All good",
            review_source="local",
            blocking_items=[],
            residual_risks=[],
            suggested_verifications=[],
            post_release_monitoring=[],
        )

        result_summary, result_release, _ = await orchestrator._apply_ai_enhancement(
            profile, [], [], MagicMock(), "original summary", release
        )
        assert result_summary == "original summary"
        assert result_release.review_source == "local"

    async def test_ai_enabled_dummy_fallback_skips(self) -> None:
        """When AI is enabled but factory returns DummyAIProvider (no key),
        enhancement is skipped."""
        from codeguardian.config.schema import AIConfig, AppConfig
        from codeguardian.core.orchestrator import Orchestrator
        from codeguardian.models.profile import ProjectProfile, ReleaseConclusion

        ai_config = AIConfig(enabled=True, provider="openai", api_key_env="NONEXISTENT_KEY_FOR_TEST")
        config = AppConfig(ai=ai_config)

        orchestrator = Orchestrator(config)
        profile = ProjectProfile(
            project_name="test",
            overall_score=85.0,
            health_status="good",
            languages=["python"],
            frameworks=[],
            total_files=10,
            total_loc=500,
            total_sloc=400,
            total_functions=20,
            total_classes=5,
            dimension_scores=[],
            modules=[],
        )
        release = ReleaseConclusion(
            verdict="recommended",
            review_summary="Local review",
            review_source="local",
            blocking_items=[],
            residual_risks=[],
            suggested_verifications=[],
            post_release_monitoring=[],
        )

        result_summary, result_release, _ = await orchestrator._apply_ai_enhancement(
            profile, [], [], MagicMock(), "original summary", release
        )
        assert result_summary == "original summary"
        assert result_release.review_source == "local"

    async def test_ai_enabled_real_provider_enhances(self) -> None:
        """When AI is enabled with a real provider, enhancement is applied."""
        from codeguardian.config.schema import AIConfig, AppConfig
        from codeguardian.core.orchestrator import Orchestrator
        from codeguardian.models.profile import ProjectProfile, ReleaseConclusion

        ai_config = AIConfig(enabled=True, provider="openai")
        config = AppConfig(ai=ai_config)

        orchestrator = Orchestrator(config)
        profile = ProjectProfile(
            project_name="test",
            overall_score=65.0,
            health_status="warning",
            languages=["python"],
            frameworks=[],
            total_files=10,
            total_loc=500,
            total_sloc=400,
            total_functions=20,
            total_classes=5,
            dimension_scores=[],
            modules=[],
        )
        release = ReleaseConclusion(
            verdict="conditional",
            review_summary="Local review",
            review_source="local",
            blocking_items=[],
            residual_risks=[],
            suggested_verifications=[],
            post_release_monitoring=[],
        )

        mock_provider = AsyncMock()
        from codeguardian.ai.models import GenerateResult
        mock_provider.generate_with_usage.side_effect = [
            GenerateResult(text="AI-generated executive summary"),
            GenerateResult(text="AI-generated release review"),
        ]

        # Patch factory to return our mock provider
        with patch("codeguardian.ai.factory.create_provider", return_value=mock_provider):
            result_summary, result_release, _ = await orchestrator._apply_ai_enhancement(
                profile, [], [], MagicMock(incremental=False, changed_files=[]),
                "original summary", release
            )

        assert result_summary == "AI-generated executive summary"
        assert result_release.review_summary == "AI-generated release review"
        assert result_release.review_source == "ai"

    async def test_ai_error_preserves_local_fallback(self) -> None:
        """When AI provider raises an exception, the local summary is preserved."""
        from codeguardian.config.schema import AIConfig, AppConfig
        from codeguardian.core.orchestrator import Orchestrator
        from codeguardian.models.profile import ProjectProfile, ReleaseConclusion

        ai_config = AIConfig(enabled=True, provider="openai")
        config = AppConfig(ai=ai_config)

        orchestrator = Orchestrator(config)
        profile = ProjectProfile(
            project_name="test",
            overall_score=85.0,
            health_status="good",
            languages=["python"],
            frameworks=[],
            total_files=10,
            total_loc=500,
            total_sloc=400,
            total_functions=20,
            total_classes=5,
            dimension_scores=[],
            modules=[],
        )
        release = ReleaseConclusion(
            verdict="recommended",
            review_summary="Local review",
            review_source="local",
            blocking_items=[],
            residual_risks=[],
            suggested_verifications=[],
            post_release_monitoring=[],
        )

        mock_provider = AsyncMock()
        mock_provider.generate_with_usage.side_effect = RuntimeError("API timeout")

        with patch("codeguardian.ai.factory.create_provider", return_value=mock_provider):
            # The exception from summarize_findings should be caught by asyncio.gather(return_exceptions=True)
            result_summary, result_release, _ = await orchestrator._apply_ai_enhancement(
                profile, [], [], MagicMock(incremental=False, changed_files=[]),
                "original summary", release
            )

        # On exception, the original values are preserved
        assert result_summary == "original summary"
        assert result_release.review_source == "local"
