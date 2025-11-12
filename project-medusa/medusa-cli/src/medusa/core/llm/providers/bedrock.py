"""
AWS Bedrock LLM Provider
Supports Claude 3.5 (Sonnet, Haiku), Titan, and other Bedrock models
"""

import boto3
import json
import logging
import time
from typing import Optional, Dict, Any
from botocore.exceptions import ClientError

from .base import BaseLLMProvider, LLMResponse
from ..config import LLMConfig
from ..exceptions import LLMError, LLMAuthenticationError, LLMRateLimitError


class BedrockProvider(BaseLLMProvider):
    """AWS Bedrock provider with cost tracking"""

    PROVIDER_NAME = "bedrock"

    # Model pricing (per 1M tokens) - as of 2025
    PRICING = {
        "anthropic.claude-3-5-sonnet-20241022-v2:0": {
            "input": 3.00,  # $3 per 1M input tokens
            "output": 15.00  # $15 per 1M output tokens
        },
        "anthropic.claude-3-5-haiku-20241022-v1:0": {
            "input": 0.80,  # $0.80 per 1M input tokens
            "output": 4.00  # $4 per 1M output tokens
        },
        "amazon.titan-text-premier-v1:0": {
            "input": 0.50,
            "output": 1.50
        }
    }

    def __init__(self, config: LLMConfig):
        """
        Initialize Bedrock provider

        Args:
            config: LLM configuration with AWS credentials
        """
        super().__init__()
        self.config = config

        # Model selection: smart vs fast
        self.model = config.cloud_model or "anthropic.claude-3-5-haiku-20241022-v1:0"

        # Initialize boto3 client
        aws_config = {}
        if hasattr(config, 'aws_region') and config.aws_region:
            aws_config['region_name'] = config.aws_region
        else:
            aws_config['region_name'] = 'us-west-2'

        if hasattr(config, 'aws_access_key_id') and config.aws_access_key_id:
            aws_config['aws_access_key_id'] = config.aws_access_key_id
        if hasattr(config, 'aws_secret_access_key') and config.aws_secret_access_key:
            aws_config['aws_secret_access_key'] = config.aws_secret_access_key

        self.bedrock_runtime = boto3.client(
            service_name='bedrock-runtime',
            **aws_config
        )

        # Cost tracking
        self.total_cost = 0.0
        self.total_input_tokens = 0
        self.total_output_tokens = 0

        self.logger = logging.getLogger(__name__)
        self.logger.info(f"BedrockProvider initialized with model={self.model}")

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        force_json: bool = False
    ) -> LLMResponse:
        """
        Generate completion using AWS Bedrock

        Returns:
            LLMResponse with content, metadata, and cost tracking
        """
        start_time = time.time()

        # Build request body based on model family
        if self.model.startswith("anthropic.claude"):
            body = self._build_claude_request(
                prompt, system_prompt, temperature, max_tokens, force_json
            )
        elif self.model.startswith("amazon.titan"):
            body = self._build_titan_request(
                prompt, system_prompt, temperature, max_tokens
            )
        else:
            raise LLMError(f"Unsupported model: {self.model}")

        try:
            response = self.bedrock_runtime.invoke_model(
                modelId=self.model,
                body=json.dumps(body)
            )

            response_body = json.loads(response['body'].read())

            # Parse response based on model
            content, input_tokens, output_tokens = self._parse_response(response_body)

            # Calculate cost
            cost = self._calculate_cost(input_tokens, output_tokens)

            # Update running totals
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost += cost

            latency_ms = (time.time() - start_time) * 1000

            self.logger.info(
                f"Bedrock response: tokens={input_tokens}+{output_tokens}, "
                f"cost=${cost:.4f}, latency={latency_ms:.0f}ms"
            )

            return LLMResponse(
                content=content,
                provider=self.PROVIDER_NAME,
                model=self.model,
                tokens_used=input_tokens + output_tokens,
                latency_ms=latency_ms,
                metadata={
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cost_usd": cost,
                    "cumulative_cost_usd": self.total_cost,
                    "model_id": self.model
                }
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ThrottlingException':
                raise LLMRateLimitError(f"Bedrock rate limit: {e}")
            elif error_code in ['AccessDeniedException', 'UnauthorizedException']:
                raise LLMAuthenticationError(f"Bedrock auth failed: {e}")
            else:
                raise LLMError(f"Bedrock error: {e}")

    def _build_claude_request(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: Optional[float],
        max_tokens: Optional[int],
        force_json: bool
    ) -> Dict[str, Any]:
        """Build request body for Claude models"""
        messages = [{"role": "user", "content": prompt}]

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens
        }

        if system_prompt:
            body["system"] = system_prompt

        if force_json:
            body["system"] = (body.get("system", "") +
                             "\n\nYou must respond with valid JSON only.")

        return body

    def _build_titan_request(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: Optional[float],
        max_tokens: Optional[int]
    ) -> Dict[str, Any]:
        """Build request body for Titan models"""
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        return {
            "inputText": full_prompt,
            "textGenerationConfig": {
                "temperature": temperature if temperature is not None else self.config.temperature,
                "maxTokenCount": max_tokens or self.config.max_tokens,
                "topP": 0.9
            }
        }

    def _parse_response(self, response_body: Dict[str, Any]) -> tuple:
        """Parse response and extract content + token counts"""
        if "content" in response_body:  # Claude format
            content = response_body["content"][0]["text"]
            input_tokens = response_body["usage"]["input_tokens"]
            output_tokens = response_body["usage"]["output_tokens"]
        elif "results" in response_body:  # Titan format
            content = response_body["results"][0]["outputText"]
            input_tokens = response_body.get("inputTextTokenCount", 0)
            output_tokens = response_body.get("results", [{}])[0].get("tokenCount", 0)
        else:
            raise LLMError("Unexpected response format from Bedrock")

        return content, input_tokens, output_tokens

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost in USD for this request"""
        pricing = self.PRICING.get(self.model, {"input": 0, "output": 0})

        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]

        return input_cost + output_cost

    async def health_check(self) -> bool:
        """Check if Bedrock is accessible"""
        try:
            # Try listing models as a connectivity test
            bedrock_client = boto3.client('bedrock', region_name='us-west-2')
            bedrock_client.list_foundation_models(
                byProvider='anthropic',
                byOutputModality='TEXT'
            )
            return True
        except Exception as e:
            self.logger.error(f"Bedrock health check failed: {e}")
            return False

    async def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        pricing = self.PRICING.get(self.model, {})

        return {
            "model_id": self.model,
            "provider": "AWS Bedrock",
            "pricing": {
                "input_per_1m": pricing.get("input", 0),
                "output_per_1m": pricing.get("output", 0),
                "currency": "USD"
            },
            "session_stats": {
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_cost_usd": self.total_cost
            }
        }

    def get_cost_summary(self) -> Dict[str, Any]:
        """Get detailed cost breakdown for current session"""
        return {
            "provider": self.PROVIDER_NAME,
            "model": self.model,
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "total_cost_usd": self.total_cost,
            "pricing": self.PRICING.get(self.model, {})
        }
