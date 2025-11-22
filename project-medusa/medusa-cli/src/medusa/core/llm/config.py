"""
LLM configuration for MEDUSA.
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from .exceptions import LLMConfigurationError


@dataclass
class LLMConfig:
    """
    Configuration for LLM providers.

    Provider Options:
    - local: Local Ollama instance (default, recommended)
    - openai: OpenAI/Azure OpenAI cloud
    - anthropic: Anthropic Claude cloud
    - mock: Mock provider for testing only
    - auto: Auto-detect best available provider

    Default Configuration:
    - Uses local Ollama with Mistral-7B-Instruct
    - No API keys required
    - Zero cost, unlimited usage
    """

    # Provider selection
    provider: str = field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "auto")
    )

    # Local provider settings (Ollama)
    ollama_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434")
    )
    local_model: str = field(
        default_factory=lambda: os.getenv("LOCAL_MODEL", "mistral:7b-instruct")
    )

    # Cloud provider settings (optional)
    cloud_api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOUD_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    )
    cloud_model: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOUD_MODEL")
    )
    cloud_base_url: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOUD_BASE_URL")
    )

    # AWS Bedrock configuration
    aws_region: Optional[str] = field(
        default_factory=lambda: os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION"))
    )
    aws_access_key_id: Optional[str] = field(
        default_factory=lambda: os.getenv("AWS_ACCESS_KEY_ID")
    )
    aws_secret_access_key: Optional[str] = field(
        default_factory=lambda: os.getenv("AWS_SECRET_ACCESS_KEY")
    )

    # Model selection strategy
    smart_model: str = field(
        default_factory=lambda: os.getenv("SMART_MODEL", "anthropic.claude-3-5-sonnet-20241022-v2:0")
    )
    fast_model: str = field(
        default_factory=lambda: os.getenv("FAST_MODEL", "anthropic.claude-3-5-haiku-20241022-v1:0")
    )

    # Generation parameters
    temperature: float = field(
        default_factory=lambda: float(os.getenv("LLM_TEMPERATURE", "0.7"))
    )
    max_tokens: int = field(
        default_factory=lambda: int(os.getenv("LLM_MAX_TOKENS", "2048"))
    )
    timeout: int = field(
        default_factory=lambda: int(os.getenv("LLM_TIMEOUT", "60"))
    )

    # Retry settings
    max_retries: int = 3
    retry_delay: int = 2

    # Testing mode
    mock_mode: bool = False

    # Legacy compatibility fields
    api_key: Optional[str] = None  # For backward compatibility
    model: Optional[str] = None  # For backward compatibility

    def __post_init__(self):
        """Post-initialization processing for backward compatibility"""
        # Map legacy 'model' field to appropriate provider model
        if self.model and not self.local_model:
            if "mistral" in self.model.lower() or "llama" in self.model.lower():
                self.local_model = self.model
            elif "gpt" in self.model.lower():
                self.cloud_model = self.model
                if not self.provider or self.provider == "auto":
                    self.provider = "openai"
            elif "claude" in self.model.lower():
                self.cloud_model = self.model
                if not self.provider or self.provider == "auto":
                    self.provider = "anthropic"

        # Map legacy 'api_key' to cloud_api_key if set
        if self.api_key and not self.cloud_api_key:
            self.cloud_api_key = self.api_key

        # Fallback: If cloud_api_key is still None (e.g. passed as None from config dict), try env vars
        if not self.cloud_api_key:
            self.cloud_api_key = os.getenv("CLOUD_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Create config from environment variables"""
        return cls()

    def validate(self):
        """Validate configuration"""
        if self.provider == "local":
            if not self.local_model:
                raise LLMConfigurationError("local_model is required for local provider")

        elif self.provider == "openai":
            if not self.cloud_api_key:
                raise LLMConfigurationError("cloud_api_key is required for OpenAI provider")
            if not self.cloud_model:
                self.cloud_model = "gpt-4-turbo-preview"

        elif self.provider == "anthropic":
            if not self.cloud_api_key:
                raise LLMConfigurationError("cloud_api_key is required for Anthropic provider")
            if not self.cloud_model:
                self.cloud_model = "claude-3-sonnet-20240229"

        elif self.provider == "bedrock":
            # AWS credentials can come from env vars, ~/.aws/credentials, or IAM roles
            # We don't enforce them here as boto3 handles credential chain
            if not self.cloud_model:
                self.cloud_model = "anthropic.claude-3-5-haiku-20241022-v1:0"
            if not self.aws_region:
                self.aws_region = "us-west-2"

        elif self.provider not in ["auto", "mock"]:
            raise LLMConfigurationError(
                f"Unknown provider: {self.provider}. "
                f"Valid: local, openai, anthropic, bedrock, mock, auto"
            )
