"""
OpenAI/Azure OpenAI cloud provider.

Template for future cloud integration. Not required for default MEDUSA operation.
Install openai package if needed: pip install openai
"""

import time
import logging
from typing import Dict, Optional, Any

from .base import BaseLLMProvider, LLMResponse
from ..exceptions import LLMError, LLMConnectionError


logger = logging.getLogger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """
    OpenAI cloud provider (GPT-4, GPT-3.5-turbo, etc.)

    Future implementation for cloud-hosted models.
    Requires: pip install openai

    This is a template for future cloud deployment needs.
    """

    PROVIDER_NAME = "openai"

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4-turbo-preview",
        base_url: Optional[str] = None,  # For Azure OpenAI
        timeout: int = 60
    ):
        """
        Initialize OpenAI Provider.

        Args:
            api_key: OpenAI API key
            model: Model name (e.g., "gpt-4-turbo-preview")
            base_url: Optional base URL (for Azure OpenAI)
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

        # Lazy import - only when actually used
        try:
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout
            )
            logger.info(f"OpenAIProvider initialized: {model}")
        except ImportError:
            raise LLMError(
                "OpenAI provider requires: pip install openai\n"
                "This is an optional dependency for cloud deployments."
            )

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        force_json: bool = False
    ) -> LLMResponse:
        """Generate completion using OpenAI API"""
        start_time = time.time()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        if force_json:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            response = await self.client.chat.completions.create(**kwargs)

            content = response.choices[0].message.content
            tokens_used = response.usage.total_tokens
            latency_ms = (time.time() - start_time) * 1000

            return LLMResponse(
                content=content,
                provider=self.PROVIDER_NAME,
                model=self.model,
                tokens_used=tokens_used,
                latency_ms=latency_ms,
                metadata={
                    "finish_reason": response.choices[0].finish_reason,
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens
                }
            )
        except Exception as e:
            logger.error(f"OpenAI provider error: {e}")
            raise LLMError(f"OpenAI provider error: {str(e)}") from e

    async def health_check(self) -> bool:
        """Check if OpenAI API is accessible"""
        try:
            await self.client.models.list()
            return True
        except Exception as e:
            logger.debug(f"Health check failed: {e}")
            return False

    async def get_model_info(self) -> Dict[str, Any]:
        """Get model information from OpenAI"""
        try:
            model = await self.client.models.retrieve(self.model)
            return model.model_dump()
        except Exception as e:
            logger.debug(f"Failed to get model info: {e}")
            return {}

    async def close(self):
        """Cleanup resources"""
        await self.client.close()
        logger.debug("OpenAIProvider closed")
