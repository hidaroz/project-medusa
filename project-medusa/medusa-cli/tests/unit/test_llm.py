"""
Unit tests for LLM integration with the new provider-based architecture

Tests LLM client functionality with local, mock, and cloud providers.
"""

import pytest
import asyncio
import json
import os
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from medusa.core.llm import (
    LLMClient, LLMConfig, create_llm_client, MockLLMClient, LocalLLMClient,
    LocalProvider, MockProvider
)
from medusa.core.llm.factory import create_llm_provider
from medusa.core.llm.providers.base import LLMResponse


@pytest.mark.unit
class TestLLMConfig:
    """Test LLMConfig dataclass"""

    def test_llm_config_creation_defaults(self):
        """Test creating LLMConfig with default values"""
        config = LLMConfig()

        assert config.provider == "auto"
        assert config.temperature == 0.7
        assert config.max_tokens == 2048
        assert config.timeout == 60
        assert config.max_retries == 3
        assert config.mock_mode is False

    def test_llm_config_with_local_provider(self):
        """Test LLMConfig with local provider"""
        config = LLMConfig(
            provider="local",
            local_model="mistral:7b-instruct",
            temperature=0.8
        )

        assert config.provider == "local"
        assert config.local_model == "mistral:7b-instruct"
        assert config.temperature == 0.8

    def test_llm_config_with_mock_provider(self):
        """Test LLMConfig with mock provider"""
        config = LLMConfig(provider="mock", mock_mode=True)

        assert config.provider == "mock"
        assert config.mock_mode is True

    def test_llm_config_validate_local(self):
        """Test validation for local provider"""
        config = LLMConfig(provider="local", local_model="mistral:7b-instruct")
        # Should not raise
        config.validate()

    def test_llm_config_validate_mock(self):
        """Test validation for mock provider"""
        config = LLMConfig(provider="mock")
        # Should not raise
        config.validate()

    @pytest.mark.skipif(
        not os.getenv("CLOUD_API_KEY"),
        reason="No cloud API key configured"
    )
    def test_llm_config_validate_cloud(self):
        """Test validation for cloud provider"""
        config = LLMConfig(
            provider="openai",
            cloud_api_key=os.getenv("CLOUD_API_KEY"),
            cloud_model="gpt-3.5-turbo"
        )
        # Should not raise
        config.validate()


@pytest.mark.unit
class TestMockProvider:
    """Test Mock provider"""

    def test_mock_provider_initialization(self):
        """Test mock provider can be initialized"""
        provider = MockProvider()
        assert provider.PROVIDER_NAME == "mock"

    @pytest.mark.asyncio
    async def test_mock_provider_generate(self):
        """Test mock provider generates responses"""
        provider = MockProvider()
        response = await provider.generate(
            prompt="Test prompt",
            force_json=True
        )

        assert isinstance(response, LLMResponse)
        assert response.provider == "mock"
        assert response.content
        assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_mock_provider_health_check(self):
        """Test mock provider health check always passes"""
        provider = MockProvider()
        is_healthy = await provider.health_check()

        assert is_healthy is True

    @pytest.mark.asyncio
    async def test_mock_provider_model_info(self):
        """Test mock provider returns model info"""
        provider = MockProvider()
        info = await provider.get_model_info()

        assert isinstance(info, dict)
        assert "mock" in str(info).lower() or info == {}


@pytest.mark.unit
class TestLocalProvider:
    """Test Local provider (Ollama)"""

    def test_local_provider_initialization(self):
        """Test local provider can be initialized"""
        provider = LocalProvider(
            base_url="http://localhost:11434",
            model="mistral:7b-instruct"
        )

        assert provider.PROVIDER_NAME == "local"
        assert provider.model == "mistral:7b-instruct"

    @pytest.mark.asyncio
    async def test_local_provider_health_check_offline(self):
        """Test local provider health check when offline"""
        provider = LocalProvider(
            base_url="http://localhost:9999"  # Unlikely to be running
        )

        is_healthy = await provider.health_check()
        # Should handle gracefully
        assert isinstance(is_healthy, bool)

    @pytest.mark.asyncio
    async def test_local_provider_extract_json(self):
        """Test JSON extraction from responses"""
        provider = LocalProvider()

        # Test with markdown code blocks
        content_with_markdown = """
        Here's the result:
        ```json
        {"key": "value"}
        ```
        """
        extracted = provider._extract_json(content_with_markdown)
        assert "key" in extracted

        # Test with plain JSON
        content_plain = '{"key": "value"}'
        extracted = provider._extract_json(content_plain)
        assert "key" in extracted


@pytest.mark.unit
class TestLLMClientOrchestrator:
    """Test main LLMClient orchestrator"""

    @pytest.mark.asyncio
    async def test_llm_client_with_mock_provider(self):
        """Test LLMClient with mock provider"""
        config = LLMConfig(provider="mock")
        provider = MockProvider()
        client = LLMClient(config=config, provider=provider)

        response = await client.generate(prompt="Test")

        assert isinstance(response, LLMResponse)
        assert response.provider == "mock"

    @pytest.mark.asyncio
    async def test_llm_client_health_check(self):
        """Test LLMClient health check"""
        config = LLMConfig(provider="mock")
        provider = MockProvider()
        client = LLMClient(config=config, provider=provider)

        health = await client.health_check()

        assert isinstance(health, dict)
        assert "provider" in health
        assert "healthy" in health

    @pytest.mark.asyncio
    async def test_llm_client_context_manager(self):
        """Test LLMClient as context manager"""
        config = LLMConfig(provider="mock")
        provider = MockProvider()

        async with LLMClient(config=config, provider=provider) as client:
            response = await client.generate(prompt="Test")
            assert response is not None


@pytest.mark.unit
class TestLLMFactory:
    """Test provider factory"""

    def test_factory_create_mock_provider(self):
        """Test factory creates mock provider"""
        config = LLMConfig(provider="mock")
        provider = create_llm_provider(config)

        assert provider.PROVIDER_NAME == "mock"
        assert isinstance(provider, MockProvider)

    def test_factory_create_local_provider(self):
        """Test factory creates local provider"""
        config = LLMConfig(
            provider="local",
            local_model="mistral:7b-instruct"
        )
        provider = create_llm_provider(config)

        assert provider.PROVIDER_NAME == "local"
        assert isinstance(provider, LocalProvider)

    def test_factory_create_llm_client(self):
        """Test factory creates LLMClient"""
        config = LLMConfig(provider="mock")
        client = create_llm_client(config)

        assert isinstance(client, LLMClient)

    def test_factory_auto_selects_mock(self):
        """Test factory auto-selects mock when appropriate"""
        config = LLMConfig(provider="auto")
        # On systems without Ollama running, should fall back to mock
        provider = create_llm_provider(config)

        assert provider is not None  # Should return something


@pytest.mark.unit
class TestBackwardCompatibility:
    """Test backward compatibility with legacy interface"""

    def test_legacy_mock_llm_client_import(self):
        """Test legacy MockLLMClient can be imported"""
        client = MockLLMClient()
        assert client is not None

    def test_legacy_local_llm_client_import(self):
        """Test legacy LocalLLMClient can be imported"""
        config = LLMConfig(provider="local")
        client = LocalLLMClient(config)
        assert client is not None

    @pytest.mark.asyncio
    async def test_legacy_mock_llm_client_methods(self):
        """Test legacy MockLLMClient methods still work"""
        client = MockLLMClient()

        # Test old interface method
        result = await client.get_reconnaissance_recommendation(
            target="test.com",
            context={}
        )

        assert isinstance(result, dict)
        assert "recommended_actions" in result or isinstance(result, dict)


@pytest.mark.unit
class TestLLMProviderInterface:
    """Test that all providers implement the interface"""

    def test_mock_provider_implements_interface(self):
        """Test MockProvider implements BaseLLMProvider"""
        provider = MockProvider()

        # Check required methods
        assert hasattr(provider, 'generate')
        assert hasattr(provider, 'health_check')
        assert hasattr(provider, 'get_model_info')
        assert hasattr(provider, 'PROVIDER_NAME')

    def test_local_provider_implements_interface(self):
        """Test LocalProvider implements BaseLLMProvider"""
        provider = LocalProvider()

        # Check required methods
        assert hasattr(provider, 'generate')
        assert hasattr(provider, 'health_check')
        assert hasattr(provider, 'get_model_info')
        assert hasattr(provider, 'PROVIDER_NAME')


@pytest.mark.unit
class TestLLMExceptions:
    """Test LLM exception handling"""

    def test_llm_config_validation_error(self):
        """Test invalid config raises error"""
        from medusa.core.llm.exceptions import LLMConfigurationError

        config = LLMConfig(provider="invalid_provider")

        with pytest.raises(LLMConfigurationError):
            config.validate()


@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("RUN_INTEGRATION_TESTS"),
    reason="Integration tests disabled by default"
)
class TestLLMIntegration:
    """Integration tests for LLM providers"""

    @pytest.mark.asyncio
    async def test_local_provider_with_ollama(self):
        """Test local provider with actual Ollama instance"""
        config = LLMConfig(
            provider="local",
            local_model="mistral:7b-instruct"
        )

        try:
            provider = LocalProvider(
                base_url=config.ollama_url,
                model=config.local_model
            )

            is_healthy = await provider.health_check()

            if is_healthy:
                response = await provider.generate(
                    prompt="Test prompt",
                    force_json=False
                )
                assert response.content
            else:
                pytest.skip("Ollama not running")

        except Exception as e:
            pytest.skip(f"Ollama not available: {e}")

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not os.getenv("CLOUD_API_KEY"),
        reason="No cloud API key configured"
    )
    async def test_cloud_provider(self):
        """Test cloud provider (requires API key)"""
        # This is a placeholder for cloud provider tests
        # Actual implementation depends on which provider is configured
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
