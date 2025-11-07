"""
Factory function for creating LLM clients based on configuration.
"""

import logging
import asyncio
from typing import Union

from .config import LLMConfig
from .providers import LocalProvider, MockProvider
from .providers.base import BaseLLMProvider
from .exceptions import LLMConfigurationError


logger = logging.getLogger(__name__)


def create_llm_provider(config: LLMConfig) -> BaseLLMProvider:
    """
    Factory function to create appropriate LLM provider.

    Priority order:
    1. Mock mode (for testing)
    2. User-specified provider
    3. Auto-detect: Local (Ollama) -> Mock

    Args:
        config: LLM configuration

    Returns:
        BaseLLMProvider instance (LocalProvider, OpenAIProvider, etc.)
    """
    config.validate()

    # Mock mode for testing
    if config.mock_mode or config.provider == "mock":
        logger.info("Using MockProvider (testing mode)")
        return MockProvider()

    # User explicitly specified provider
    if config.provider == "local":
        logger.info(f"Using LocalProvider with model: {config.local_model}")
        return LocalProvider(
            base_url=config.ollama_url,
            model=config.local_model,
            timeout=config.timeout,
            max_retries=config.max_retries,
            retry_delay=config.retry_delay
        )

    elif config.provider == "openai":
        # Lazy import for optional cloud dependencies
        try:
            from .providers.openai import OpenAIProvider

            if not config.cloud_api_key:
                raise LLMConfigurationError(
                    "OpenAI provider requires API key. "
                    "Set CLOUD_API_KEY environment variable."
                )

            logger.info(f"Using OpenAIProvider with model: {config.cloud_model}")
            return OpenAIProvider(
                api_key=config.cloud_api_key,
                model=config.cloud_model or "gpt-4-turbo-preview",
                base_url=config.cloud_base_url,
                timeout=config.timeout
            )
        except ImportError:
            logger.error("OpenAI provider requires: pip install openai")
            logger.warning("Falling back to MockProvider")
            return MockProvider()

    elif config.provider == "anthropic":
        try:
            from .providers.anthropic import AnthropicProvider

            if not config.cloud_api_key:
                raise LLMConfigurationError(
                    "Anthropic provider requires API key. "
                    "Set CLOUD_API_KEY environment variable."
                )

            logger.info(f"Using AnthropicProvider with model: {config.cloud_model}")
            return AnthropicProvider(
                api_key=config.cloud_api_key,
                model=config.cloud_model or "claude-3-sonnet-20240229",
                timeout=config.timeout
            )
        except ImportError:
            logger.error("Anthropic provider requires: pip install anthropic")
            logger.warning("Falling back to MockProvider")
            return MockProvider()

    # Auto-detect best available option
    elif config.provider == "auto":
        # Try local first (if Ollama is available)
        try:
            local_provider = LocalProvider(
                base_url=config.ollama_url,
                model=config.local_model,
                timeout=config.timeout
            )

            # Quick health check
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            try:
                is_healthy = loop.run_until_complete(local_provider.health_check())
                if is_healthy:
                    logger.info(f"Auto-detected: Using LocalProvider (Ollama running)")
                    return local_provider
                else:
                    logger.info(f"Ollama not ready, falling back to MockProvider")
            except:
                logger.debug("Ollama health check failed")

        except Exception as e:
            logger.debug(f"Local provider unavailable: {e}")

        # Fall back to cloud if configured
        if config.cloud_api_key and config.cloud_model:
            if "gpt" in config.cloud_model.lower():
                try:
                    from .providers.openai import OpenAIProvider
                    logger.info("Auto-detected: Using OpenAIProvider")
                    return OpenAIProvider(
                        api_key=config.cloud_api_key,
                        model=config.cloud_model,
                        base_url=config.cloud_base_url,
                        timeout=config.timeout
                    )
                except ImportError:
                    pass
            elif "claude" in config.cloud_model.lower():
                try:
                    from .providers.anthropic import AnthropicProvider
                    logger.info("Auto-detected: Using AnthropicProvider")
                    return AnthropicProvider(
                        api_key=config.cloud_api_key,
                        model=config.cloud_model,
                        timeout=config.timeout
                    )
                except ImportError:
                    pass

        # Last resort: Mock mode
        logger.warning(
            "No LLM available. Using MockProvider.\n"
            "To use real AI:\n"
            "  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh\n"
            "  2. Pull model: ollama pull mistral:7b-instruct\n"
            "  3. Or set CLOUD_API_KEY for cloud providers"
        )
        return MockProvider()

    else:
        logger.error(f"Unknown provider: {config.provider}")
        raise LLMConfigurationError(
            f"Unknown provider: {config.provider}. "
            f"Valid providers: 'local', 'openai', 'anthropic', 'mock', 'auto'"
        )


def create_llm_client(config: LLMConfig):
    """
    Legacy compatibility function.

    Creates an LLM client (wrapper around provider).
    This maintains backward compatibility with existing code.
    """
    from .client import LLMClient

    provider = create_llm_provider(config)
    return LLMClient(config=config, provider=provider)
