"""
LLM Integration for MEDUSA AI Pentesting

Provides AI-powered decision making through a clean provider-based architecture.
Supports local (Ollama), cloud (OpenAI, Anthropic), and mock providers.

Default: Local Mistral-7B-Instruct via Ollama
"""

from .config import LLMConfig
from .client import LLMClient
from .factory import create_llm_client
from .providers import BaseLLMProvider, LLMResponse, LocalProvider, MockProvider
from .exceptions import (
    LLMError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMConfigurationError,
    LLMModelNotFoundError
)

# For backward compatibility
from .legacy_adapter import MockLLMClient, LocalLLMClient

__all__ = [
    # Core classes
    "LLMConfig",
    "LLMClient",
    "create_llm_client",

    # Provider classes
    "BaseLLMProvider",
    "LLMResponse",
    "LocalProvider",
    "MockProvider",

    # Exceptions
    "LLMError",
    "LLMConnectionError",
    "LLMTimeoutError",
    "LLMConfigurationError",
    "LLMModelNotFoundError",

    # Legacy compatibility
    "MockLLMClient",
    "LocalLLMClient",
]
