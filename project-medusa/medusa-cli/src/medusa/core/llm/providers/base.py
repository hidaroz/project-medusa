"""
Base provider interface for all LLM providers in MEDUSA.

This ensures consistency across local and cloud providers and makes
adding new providers trivial.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LLMResponse:
    """
    Standardized response format from any LLM provider.

    This ensures all providers return data in a consistent format,
    making provider switching seamless.
    """
    content: str
    provider: str
    model: str
    tokens_used: int
    latency_ms: float
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary"""
        return {
            "content": self.content,
            "provider": self.provider,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


class BaseLLMProvider(ABC):
    """
    Base class for all LLM providers.

    All LLM providers (local, cloud, mock) must implement this interface.
    This ensures consistency and makes the system extensible for future providers.
    """

    PROVIDER_NAME: str = "base"

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        force_json: bool = False
    ) -> LLMResponse:
        """
        Generate completion from the model.

        Args:
            prompt: User prompt/question
            system_prompt: System instructions (optional)
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
            force_json: Whether to enforce JSON output format

        Returns:
            LLMResponse with generated content and metadata

        Raises:
            LLMError: On generation failure
            LLMConnectionError: On connection issues
            LLMTimeoutError: On timeout
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if provider is available and healthy.

        Returns:
            True if provider is ready, False otherwise
        """
        pass

    @abstractmethod
    async def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the model.

        Returns:
            Dict with model information (name, parameters, capabilities, etc.)
        """
        pass

    async def close(self):
        """
        Cleanup resources (optional).

        Override this if your provider needs cleanup (e.g., closing HTTP clients).
        """
        pass
