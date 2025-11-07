"""
Local LLM provider using Ollama.

This is the primary/default provider for MEDUSA, providing:
- Unlimited local inference
- No API costs
- Privacy (no data sent to cloud)
- GPU acceleration support
"""

import httpx
import json
import time
import asyncio
import logging
from typing import Dict, Optional

from .base import BaseLLMProvider, LLMResponse
from ..exceptions import LLMError, LLMConnectionError, LLMTimeoutError, LLMModelNotFoundError


logger = logging.getLogger(__name__)


class LocalProvider(BaseLLMProvider):
    """
    Local LLM provider using Ollama for inference.

    Supports:
    - Mistral-7B-Instruct (default)
    - Any other Ollama-compatible model
    - GPU acceleration (automatic)
    - Streaming responses (optional)
    """

    PROVIDER_NAME = "local"
    DEFAULT_MODEL = "mistral:7b-instruct"
    DEFAULT_URL = "http://localhost:11434"

    def __init__(
        self,
        base_url: str = DEFAULT_URL,
        model: str = DEFAULT_MODEL,
        timeout: int = 60,
        max_retries: int = 3,
        retry_delay: int = 2
    ):
        """
        Initialize Local Provider.

        Args:
            base_url: Ollama server URL
            model: Model name (e.g., "mistral:7b-instruct")
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            retry_delay: Base delay between retries (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(
                max_keepalive_connections=5,
                max_connections=10
            )
        )

        logger.info(f"LocalProvider initialized: {self.model} @ {self.base_url}")

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        force_json: bool = False
    ) -> LLMResponse:
        """
        Generate completion using local Ollama API.

        Args:
            prompt: User prompt
            system_prompt: System instructions
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
            force_json: Whether to enforce JSON output

        Returns:
            LLMResponse with generated content
        """
        start_time = time.time()

        # Build full prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        else:
            full_prompt = prompt

        # Add JSON enforcement if requested
        if force_json:
            full_prompt += "\n\nRespond with valid JSON only. No markdown, no explanations."

        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "top_p": 0.9,
                "top_k": 40,
            }
        }

        # Enable JSON mode if requested
        if force_json:
            payload["format"] = "json"

        last_error = None
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Local LLM request attempt {attempt + 1}/{self.max_retries}")

                response = await self.client.post(
                    "/api/generate",
                    json=payload
                )
                response.raise_for_status()
                result = response.json()

                content = result.get("response", "").strip()

                # Clean JSON if forced
                if force_json and content:
                    content = self._extract_json(content)

                latency_ms = (time.time() - start_time) * 1000

                return LLMResponse(
                    content=content,
                    provider=self.PROVIDER_NAME,
                    model=self.model,
                    tokens_used=result.get("eval_count", 0),
                    latency_ms=latency_ms,
                    metadata={
                        "context_length": result.get("prompt_eval_count", 0),
                        "load_duration": result.get("load_duration"),
                        "total_duration": result.get("total_duration")
                    }
                )

            except httpx.TimeoutException as e:
                last_error = f"Request timed out after {self.timeout}s"
                logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))

            except httpx.ConnectError as e:
                last_error = (
                    f"Cannot connect to Ollama at {self.base_url}. "
                    f"Is Ollama running? Install: https://ollama.com"
                )
                logger.error(last_error)
                raise LLMConnectionError(last_error) from e

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    last_error = (
                        f"Model '{self.model}' not found. "
                        f"Pull it first: ollama pull {self.model}"
                    )
                    logger.error(last_error)
                    raise LLMModelNotFoundError(last_error) from e

                last_error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
                logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))

            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                logger.warning(f"Attempt {attempt + 1} failed: {last_error}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))

        raise LLMTimeoutError(
            f"Local LLM request failed after {self.max_retries} attempts: {last_error}"
        )

    async def health_check(self) -> bool:
        """Check if Ollama is running and model is available"""
        try:
            # Check if Ollama is running
            response = await self.client.get("/api/version", timeout=5.0)
            if response.status_code != 200:
                return False

            # Check if model is available
            response = await self.client.get("/api/tags", timeout=5.0)
            result = response.json()
            models = [m.get("name", "") for m in result.get("models", [])]

            return self.model in models

        except Exception as e:
            logger.debug(f"Health check failed: {e}")
            return False

    async def get_model_info(self) -> Dict[str, any]:
        """Get information about the local model"""
        try:
            response = await self.client.post(
                "/api/show",
                json={"name": self.model},
                timeout=10.0
            )
            return response.json()
        except Exception as e:
            logger.debug(f"Failed to get model info: {e}")
            return {}

    def _extract_json(self, content: str) -> str:
        """Extract JSON from content that might have markdown formatting"""
        # Remove markdown code blocks
        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        return content.strip()

    async def close(self):
        """Cleanup resources"""
        await self.client.aclose()
        logger.debug("LocalProvider closed")
