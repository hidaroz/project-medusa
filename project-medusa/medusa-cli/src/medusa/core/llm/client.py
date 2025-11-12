"""
Main LLM client that orchestrates provider selection and usage.

This is the primary interface for using LLM functionality in MEDUSA.
It handles provider selection, error handling, and metrics tracking.
"""

import logging
import json
import re
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

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """
        Extract JSON from LLM response.
        
        Handles various formats:
        - Pure JSON
        - JSON wrapped in markdown code blocks
        - JSON with surrounding text
        """
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            json_match = re.search(
                r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL
            )
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON object in the response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            raise ValueError("Invalid JSON response from LLM")

    async def get_reconnaissance_recommendation(
        self,
        target: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get AI recommendation for reconnaissance phase.
        
        Args:
            target: Target URL or IP address
            context: Additional context for the reconnaissance
            
        Returns:
            Dict with reconnaissance recommendations including:
            - recommended_actions: List of actions to perform
            - focus_areas: Areas to focus on
            - risk_assessment: Risk level assessment
        """
        try:
            from medusa.core.prompts import PromptTemplates
            
            prompt = PromptTemplates.reconnaissance_strategy(target, context)
            self.logger.debug(f"Requesting reconnaissance recommendation for {target}")
            
            response = await self.generate(
                prompt=prompt,
                force_json=True
            )
            
            result = self._extract_json_from_response(response.content)
            self.logger.info(f"Reconnaissance recommendation generated for {target}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get reconnaissance recommendation: {e}")
            # Return fallback response
            return {
                "recommended_actions": [
                    {
                        "action": "port_scan",
                        "ports": "1-1000",
                        "technique_id": "T1046",
                        "technique_name": "Network Service Discovery",
                        "priority": "high",
                        "reasoning": "Standard port scanning to discover open services"
                    },
                    {
                        "action": "web_fingerprint",
                        "technique_id": "T1595.002",
                        "technique_name": "Active Scanning",
                        "priority": "high",
                        "reasoning": "Identify web technologies and versions"
                    }
                ],
                "focus_areas": ["web_services", "network_services"],
                "risk_assessment": "LOW"
            }

    async def get_next_action_recommendation(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get recommendation for the next action to take.
        
        Args:
            context: Current operation context including phase, findings, history
            
        Returns:
            Dict with recommendations including:
            - recommendations: List of recommended actions
            - context_analysis: Analysis of current context
            - suggested_next_phase: Suggested next phase
        """
        try:
            from medusa.core.prompts import PromptTemplates
            
            prompt = PromptTemplates.next_action_recommendation(context)
            self.logger.debug("Requesting next action recommendation")
            
            response = await self.generate(
                prompt=prompt,
                force_json=True
            )
            
            result = self._extract_json_from_response(response.content)
            self.logger.info("Next action recommendation generated")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get next action recommendation: {e}")
            # Return fallback response
            return {
                "recommendations": [
                    {
                        "action": "continue_enumeration",
                        "confidence": 0.7,
                        "reasoning": "Continue systematic enumeration",
                        "technique": "T1590",
                        "risk_level": "LOW",
                    }
                ],
                "context_analysis": "Continuing with safe reconnaissance activities",
                "suggested_next_phase": context.get("phase", "enumeration"),
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

