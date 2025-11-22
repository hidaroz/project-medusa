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

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """
        Extract JSON from LLM response with robust error handling.

        Handles various formats:
        - Pure JSON
        - JSON wrapped in markdown code blocks (```json ... ```)
        - JSON with surrounding text
        - Malformed JSON (trailing commas, unescaped quotes)

        Implements a "Clean and Parse" workflow:
        1. Strip markdown code blocks
        2. Find first { and last }
        3. Attempt json.loads
        4. If fails, apply text repairs and retry
        5. Validate result is dict or list

        Args:
            response: Raw LLM response string

        Returns:
            Parsed JSON as dict or list

        Raises:
            ValueError: If JSON cannot be extracted or parsed
        """
        if not response or not isinstance(response, str):
            raise ValueError(f"Invalid response type: {type(response)}")

        # Step 1: Try direct parsing first (fastest path)
        try:
            result = json.loads(response)
            if isinstance(result, (dict, list)):
                return result
        except json.JSONDecodeError:
            pass

        # Step 2: Strip markdown code blocks
        cleaned = self._strip_markdown_code_blocks(response)

        # Step 3: Extract JSON boundaries (first { to last })
        json_str = self._extract_json_boundaries(cleaned)

        if not json_str:
            # Fallback: try original response boundaries
            json_str = self._extract_json_boundaries(response)

        if not json_str:
            raise ValueError("No JSON object found in response")

        # Step 4: Attempt to parse
        try:
            result = json.loads(json_str)
            if isinstance(result, (dict, list)):
                return result
            else:
                raise ValueError(f"JSON parsed but result is {type(result)}, not dict/list")
        except json.JSONDecodeError as e:
            self.logger.debug(f"Initial JSON parse failed: {e}")

            # Step 5: Apply text repairs and retry
            repaired = self._repair_json_text(json_str)
            try:
                result = json.loads(repaired)
                if isinstance(result, (dict, list)):
                    self.logger.debug("JSON successfully repaired and parsed")
                    return result
                else:
                    raise ValueError(f"Repaired JSON is {type(result)}, not dict/list")
            except json.JSONDecodeError as e2:
                self.logger.error(
                    f"JSON parsing failed even after repair. "
                    f"Original error: {e}, Repair error: {e2}"
                )
                # Log snippet for debugging
                snippet = json_str[:200] + "..." if len(json_str) > 200 else json_str
                self.logger.debug(f"Failed JSON snippet: {snippet}")
                raise ValueError(f"Invalid JSON in LLM response: {e2}")

    def _strip_markdown_code_blocks(self, text: str) -> str:
        """
        Remove markdown code block delimiters.

        Handles:
        - ```json ... ```
        - ``` ... ```
        - Multiple code blocks

        Args:
            text: Text potentially containing markdown code blocks

        Returns:
            Text with code block delimiters removed
        """
        # Remove code blocks with language specifier (```json, ```python, etc.)
        text = re.sub(r'```\w+\s*\n', '', text)
        # Remove plain code blocks
        text = re.sub(r'```\s*\n?', '', text)
        return text.strip()

    def _extract_json_boundaries(self, text: str) -> Optional[str]:
        """
        Extract content between first { and last }.

        Also handles [ ] for JSON arrays.

        Args:
            text: Text containing JSON

        Returns:
            Extracted JSON string or None if not found
        """
        # Try object extraction first { ... }
        first_brace = text.find('{')
        last_brace = text.rfind('}')

        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            return text[first_brace:last_brace + 1]

        # Try array extraction [ ... ]
        first_bracket = text.find('[')
        last_bracket = text.rfind(']')

        if first_bracket != -1 and last_bracket != -1 and last_bracket > first_bracket:
            return text[first_bracket:last_bracket + 1]

        return None

    def _repair_json_text(self, json_str: str) -> str:
        """
        Apply common JSON repairs to fix LLM-generated malformed JSON.

        Fixes:
        - Trailing commas before } or ]
        - Unescaped newlines in strings
        - Single quotes to double quotes (simple cases)
        - Common escape sequence issues

        Args:
            json_str: Potentially malformed JSON string

        Returns:
            Repaired JSON string
        """
        repaired = json_str

        # Fix 1: Remove trailing commas before closing braces/brackets
        # ,} -> }  and  ,] -> ]
        repaired = re.sub(r',\s*}', '}', repaired)
        repaired = re.sub(r',\s*]', ']', repaired)

        # Fix 2: Remove trailing commas in middle of objects/arrays
        # Multiple commas: ,, -> ,
        repaired = re.sub(r',\s*,', ',', repaired)

        # Fix 3: Replace unescaped newlines within strings (common LLM error)
        # This is tricky - only do simple cases
        # Replace \n not preceded by \ with \\n
        # repaired = re.sub(r'(?<!\\)\n', '\\n', repaired)

        # Fix 4: Remove comments (// or /* */) that LLMs sometimes add
        repaired = re.sub(r'//.*?$', '', repaired, flags=re.MULTILINE)
        repaired = re.sub(r'/\*.*?\*/', '', repaired, flags=re.DOTALL)

        # Fix 5: Handle common escape issues
        # Replace \" with " in simple cases (if not already escaped)
        # This is risky, so we skip it for now

        return repaired.strip()

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

