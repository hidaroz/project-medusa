"""
Main LLM client that orchestrates provider selection and usage.

This is the primary interface for using LLM functionality in MEDUSA.
It handles provider selection, error handling, and metrics tracking.
"""

import logging
from typing import Optional, Dict, Any

from .config import LLMConfig
from .providers.base import BaseLLMProvider, LLMResponse
from .exceptions import LLMError


logger = logging.getLogger(__name__)


class LLMClient:
    """
    Main LLM client for MEDUSA.

    Handles:
    - Provider orchestration
    - Request/response management
    - Error handling and retries
    - Metrics tracking

    Usage:
        from medusa.core.llm import LLMClient, LLMConfig, create_llm_client
        
        # Option 1: Auto-detection
        client = create_llm_client()
        
        # Option 2: Explicit configuration
        config = LLMConfig(provider="local", local_model="mistral:7b-instruct")
        provider = create_llm_provider(config)
        client = LLMClient(config=config, provider=provider)
        
        # Use the client
        response = await client.generate(
            prompt="Analyze this target for vulnerabilities",
            force_json=True
        )
        
        # Or use high-level methods (delegated by providers)
        recon = await client.get_reconnaissance_recommendation(
            target="example.com",
            context={"phase": "reconnaissance"}
        )
    """

    def __init__(self, config: LLMConfig, provider: BaseLLMProvider):
        """
        Initialize LLM client.

        Args:
            config: LLM configuration
            provider: LLM provider instance
        """
        self.config = config
        self.provider = provider
        self.logger = logger
        
        self.logger.info(
            f"LLMClient initialized with provider={provider.PROVIDER_NAME}, "
            f"model={getattr(provider, 'model', 'unknown')}"
        )

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        force_json: bool = False
    ) -> LLMResponse:
        """
        Generate completion using configured provider.

        Args:
            prompt: User prompt
            system_prompt: System instructions
            temperature: Override default temperature
            max_tokens: Override default max tokens
            force_json: Enforce JSON output format

        Returns:
            LLMResponse with generated content

        Raises:
            LLMError: On generation failure
        """
        # Use defaults from config if not specified
        temperature = temperature if temperature is not None else self.config.temperature
        max_tokens = max_tokens if max_tokens is not None else self.config.max_tokens

        try:
            self.logger.debug(
                f"LLM generation request: prompt_len={len(prompt)}, "
                f"temperature={temperature}, max_tokens={max_tokens}, "
                f"force_json={force_json}"
            )

            response = await self.provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                force_json=force_json
            )

            self.logger.debug(
                f"LLM response received: "
                f"provider={response.provider}, "
                f"tokens={response.tokens_used}, "
                f"latency={response.latency_ms:.2f}ms"
            )

            return response

        except Exception as e:
            self.logger.error(f"LLM generation failed: {e}")
            raise

    async def health_check(self) -> Dict[str, Any]:
        """
        Check provider health and readiness.

        Returns:
            Dict with health status and model info
        """
        try:
            is_healthy = await self.provider.health_check()
            model_info = await self.provider.get_model_info() if is_healthy else {}

            health_status = {
                "provider": self.provider.PROVIDER_NAME,
                "healthy": is_healthy,
                "model": getattr(self.provider, 'model', 'unknown'),
                "model_info": model_info
            }

            if is_healthy:
                self.logger.info(f"Health check passed: {self.provider.PROVIDER_NAME}")
            else:
                self.logger.warning(
                    f"Health check failed: {self.provider.PROVIDER_NAME}"
                )

            return health_status

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return {
                "provider": self.provider.PROVIDER_NAME,
                "healthy": False,
                "error": str(e)
            }

    async def close(self):
        """Cleanup resources"""
        try:
            if hasattr(self.provider, 'close'):
                await self.provider.close()
                self.logger.debug("LLM provider closed")
        except Exception as e:
            self.logger.warning(f"Error closing LLM provider: {e}")

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

