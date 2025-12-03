"""
LLM Provider interfaces for MEDUSA

This package provides a clean provider-based architecture for LLM integration.
All providers implement the BaseLLMProvider interface for consistency.
"""

from .base import BaseLLMProvider, LLMResponse
from .local import LocalProvider
from .mock import MockProvider

# Cloud providers are optional and imported lazily
# from .openai import OpenAIProvider
# from .anthropic import AnthropicProvider

# Google Gemini provider (optional)
try:
    from .google import GoogleProvider
    GOOGLE_AVAILABLE = True
except ImportError:
    GoogleProvider = None
    GOOGLE_AVAILABLE = False

__all__ = [
    "BaseLLMProvider",
    "LLMResponse",
    "LocalProvider",
    "MockProvider",
    # "OpenAIProvider",  # Optional
    # "AnthropicProvider",  # Optional
]

if GOOGLE_AVAILABLE:
    __all__.append("GoogleProvider")
