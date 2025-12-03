"""
Google Gemini cloud provider.

Supports Google's Gemini API for AI-powered decision making.
Requires: pip install google-generativeai
"""

import time
import logging
from typing import Dict, Optional, Any

from .base import BaseLLMProvider, LLMResponse
from ..exceptions import LLMError, LLMConnectionError, LLMTimeoutError

logger = logging.getLogger(__name__)


class GoogleProvider(BaseLLMProvider):
    """
    Google Gemini cloud provider (gemini-pro, gemini-1.5-pro, etc.)

    Provides access to Google's Gemini models via API.
    Requires: pip install google-generativeai
    """

    PROVIDER_NAME = "google"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-pro",
        timeout: int = 60
    ):
        """
        Initialize Google Gemini Provider.

        Args:
            api_key: Google AI API key
            model: Model name (e.g., "gemini-pro", "gemini-1.5-pro")
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

        # Lazy import - only when actually used
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.genai = genai
            logger.info(f"GoogleProvider initialized: {model}")
        except ImportError:
            raise LLMError(
                "Google provider requires: pip install google-generativeai\n"
                "Install with: pip install google-generativeai"
            )
        except Exception as e:
            raise LLMError(f"Failed to initialize Google provider: {e}")

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        force_json: bool = False
    ) -> LLMResponse:
        """Generate completion using Google Gemini API"""
        start_time = time.time()

        try:
            # Combine system prompt and user prompt
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"

            # Get the model
            model = self.genai.GenerativeModel(self.model)

            # Configure generation parameters
            generation_config = {
                "temperature": temperature,
                "max_output_tokens": max_tokens,
            }

            # If JSON is required, add instruction to prompt
            if force_json:
                full_prompt = f"{full_prompt}\n\nRespond with valid JSON only, no markdown formatting."

            # Generate response
            response = await self._generate_with_timeout(
                model, full_prompt, generation_config
            )

            # Extract text from response
            content = response.text if hasattr(response, 'text') else str(response)

            # Clean up JSON if force_json was used
            if force_json:
                content = self._extract_json(content)

            # Estimate tokens (Gemini doesn't always provide usage stats)
            tokens_used = len(content.split()) * 1.3  # Rough estimate
            latency_ms = (time.time() - start_time) * 1000

            return LLMResponse(
                content=content,
                provider=self.PROVIDER_NAME,
                model=self.model,
                tokens_used=int(tokens_used),
                latency_ms=latency_ms,
                metadata={
                    "finish_reason": getattr(response, 'finish_reason', None),
                    "prompt_token_count": getattr(response, 'usage_metadata', {}).get('prompt_token_count', None) if hasattr(response, 'usage_metadata') else None,
                    "candidates_token_count": getattr(response, 'usage_metadata', {}).get('candidates_token_count', None) if hasattr(response, 'usage_metadata') else None,
                }
            )

        except Exception as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                raise LLMTimeoutError(f"Google Gemini request timed out: {error_msg}")
            elif "connection" in error_msg.lower() or "network" in error_msg.lower():
                raise LLMConnectionError(f"Failed to connect to Google Gemini: {error_msg}")
            else:
                raise LLMError(f"Google Gemini generation failed: {error_msg}")

    async def _generate_with_timeout(self, model, prompt: str, config: Dict):
        """Generate with timeout handling"""
        import asyncio

        try:
            # Run in executor to handle timeout
            loop = asyncio.get_event_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: model.generate_content(prompt, generation_config=config)
                ),
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            raise LLMTimeoutError(f"Request timed out after {self.timeout}s")

    def _extract_json(self, content: str) -> str:
        """Extract JSON from response, removing markdown formatting if present"""
        import json
        import re

        # Try to parse as-is first
        try:
            json.loads(content)
            return content
        except json.JSONDecodeError:
            pass

        # Try to extract from markdown code blocks
        json_match = re.search(
            r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL
        )
        if json_match:
            try:
                json.loads(json_match.group(1))
                return json_match.group(1)
            except json.JSONDecodeError:
                pass

        # Try to find JSON object in text
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            try:
                json.loads(json_match.group(0))
                return json_match.group(0)
            except json.JSONDecodeError:
                pass

        # Return original if we can't extract valid JSON
        logger.warning("Could not extract valid JSON from response")
        return content

    async def health_check(self) -> bool:
        """Check if Google Gemini API is available"""
        try:
            model = self.genai.GenerativeModel(self.model)
            # Simple test prompt
            response = model.generate_content("test", max_output_tokens=1)
            return True
        except Exception as e:
            logger.debug(f"Google Gemini health check failed: {e}")
            return False

    async def get_model_info(self) -> Dict[str, Any]:
        """Get information about the Gemini model"""
        return {
            "provider": self.PROVIDER_NAME,
            "model": self.model,
            "name": f"Google {self.model}",
            "type": "cloud",
            "supports_streaming": True,
            "supports_json_mode": True,
            "max_tokens": 8192,  # Gemini supports up to 8k tokens
            "context_window": 32768  # Approximate context window
        }

