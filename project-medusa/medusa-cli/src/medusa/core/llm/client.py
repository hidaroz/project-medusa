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
from .router import ModelRouter


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

        # Initialize Model Router for smart model selection
        self.router = ModelRouter(config)

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

    async def generate_with_routing(
        self,
        prompt: str,
        task_type: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        force_json: bool = False,
        **kwargs
    ) -> LLMResponse:
        """
        Generate with automatic model routing based on task complexity.

        This method uses the ModelRouter to intelligently select between
        fast (Haiku) and smart (Sonnet) models based on task complexity,
        significantly reducing costs while maintaining quality.

        Args:
            prompt: User prompt
            task_type: Task identifier for routing (e.g., "parse_nmap", "plan_attack")
            system_prompt: System instructions
            temperature: Override default temperature
            max_tokens: Override default max tokens
            force_json: Enforce JSON output format
            **kwargs: Additional routing context

        Returns:
            LLMResponse with generated content

        Example:
            # Simple task - uses Haiku (fast, cheap)
            response = await client.generate_with_routing(
                prompt="Parse this Nmap output",
                task_type="parse_nmap_output"
            )

            # Complex task - uses Sonnet (smart, expensive)
            response = await client.generate_with_routing(
                prompt="Generate comprehensive attack strategy",
                task_type="plan_attack_strategy"
            )
        """
        # Select appropriate model using router
        selected_model = self.router.select_model(task_type, kwargs.get('context'))

        # Update provider model if it supports dynamic model switching
        original_model = None
        if hasattr(self.provider, 'model') and selected_model != self.provider.model:
            original_model = self.provider.model
            self.provider.model = selected_model
            self.logger.info(f"Routing to {selected_model} for task={task_type}")

        try:
            response = await self.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                force_json=force_json
            )

            # Add routing metadata
            if 'routing' not in response.metadata:
                response.metadata['routing'] = {}
            response.metadata['routing']['task_type'] = task_type
            response.metadata['routing']['selected_model'] = selected_model

            return response

        finally:
            # Restore original model
            if original_model and hasattr(self.provider, 'model'):
                self.provider.model = original_model

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

